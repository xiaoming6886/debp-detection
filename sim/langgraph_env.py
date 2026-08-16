"""LangGraph 编排框架模拟层（依据 langchain-ai/langgraph 真实源码建模）。

源码基准：langgraph==1.2.11 @ commit 644815f9e5bc52ad8f7a5227a456227e9c3e639b (2026-08-11)

源码事实（与模拟实现逐条对应）：
1. 工具执行检查点：ToolNode(wrap_tool_call=...)（libs/prebuilt/langgraph/prebuilt/tool_node.py
   L750）。handler 签名 (request: ToolCallRequest, execute) -> ToolMessage | Command：
   返回 ToolMessage 即短路（工具不执行）；调用 execute 才执行。
2. 节点触发（pregel/_algo.py _triggers L1255）：仅当节点 triggers 通道版本高于其
   versions_seen 时调度（版本化触发）。
3. 状态更新（pregel/_algo.py apply_writes L250）：同 superstep 所有 writes 聚合后
   channels[chan].update(vals)，reducer（如 messages 的 operator.add）一次调用。
4. 图中断（langgraph/types.py interrupt L809）：interrupt() 首次调用抛 GraphInterrupt，
   持久化为 (INTERRUPT, (Interrupt,)) writes（pregel/_runner.py commit L576）；
   NodeInterrupt 已废弃（errors.py L109）。
5. 短路结束（pregel/_loop.py tick L598）：无 writes 指向任何 channel → 无节点触发 →
   not self.tasks → status="done"（不是显式 END 对象）。

本模拟层以检测内核等价 wrap_tool_call handler：deny → 返回错误 ToolMessage（工具不
执行、无状态写入）→ 图中断（interrupted）→ 后续节点不再执行（无触发即 done）。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from detection_core import DetectionEngine, TaskMeta, ToolCall, ToolResult
from sim.opencode_env import StepRecord, TrajectoryResult
from sim.tools import ToolSandbox


@dataclass
class GraphState:
    """模拟的 LangGraph 图状态（messages channel，聚合语义见 apply_writes）。"""

    messages: list[str] = field(default_factory=list)
    interrupted: bool = False
    interrupt_reason: str = ""
    interrupt_code: str | None = None
    interrupt_step: int = -1

    def append(self, msg: str) -> None:
        """messages channel 更新：源码为 Annotated[list, operator.add] reducer，
        每次节点写入追加到已有列表（BinaryOperatorAggregate.update）。"""
        self.messages.append(msg)


class LangGraphEnv:
    """LangGraph 状态图节点执行模拟器（ToolNode wrap_tool_call 检查点语义）。

    每个节点（工具调用）执行语义：
    1. wrap_tool_call handler = 检测内核判定（源码 tool_node.py L750 的拦截点）
    2. deny → handler 返回错误 ToolMessage（不调用 execute）→ 图状态 interrupted
       → 后续节点短路（无 writes → 无触发 → done，_loop.py tick L598）
    3. allow → execute（沙箱执行）→ 结果写入 messages channel + 回传检测内核
    """

    def __init__(self, engine: DetectionEngine, sandbox: ToolSandbox):
        self.engine = engine
        self.sandbox = sandbox
        self.state = GraphState()

    def start(self, task_meta: TaskMeta) -> None:
        """注册任务并推导期望行为轮廓。"""
        self.engine.on_task_start(task_meta)
        self.state = GraphState()

    def run(self, task_id: str, nodes: list[dict], max_steps: int = 100) -> TrajectoryResult:
        """按预设节点序列执行状态图。

        nodes: [{"tool": "read", "args": {...}}, ...]
        任一节点触发拦截 → 图中断（interrupted），outcome=intercepted。
        """
        result = TrajectoryResult(task_id=task_id)
        for i, node in enumerate(nodes[:max_steps]):
            tool = node["tool"]
            args = node.get("args", {})
            call = ToolCall(call_id=f"{task_id}:{tool}", tool=tool, args=args, caller=task_id)

            # 1. wrap_tool_call handler：检测内核判定
            decision = self.engine.on_tool_call(call)

            if not decision.allow:
                # 2. deny：返回错误 ToolMessage，工具不执行（短路）
                code = decision.reason_code.value if decision.reason_code else "?"
                step = StepRecord(
                    tool=tool,
                    args=args,
                    allow=False,
                    reason_code=code,
                    detail=decision.detail,
                )
                result.steps.append(step)
                result.outcome = "intercepted"
                result.trigger_code = code
                result.trigger_step = i
                # 图中断（GraphInterrupt 语义）：无状态写入 → 无节点触发 → done
                self.state.interrupted = True
                self.state.interrupt_reason = decision.detail
                self.state.interrupt_code = code
                self.state.interrupt_step = i
                break

            # 3. allow：execute（沙箱执行）
            ok, output = self.sandbox.call(tool, args)
            result.steps.append(StepRecord(tool=tool, args=args, allow=True, ok=ok, output=output))
            # 4. 状态更新（apply_writes）：messages channel 聚合 + 结果回传检测内核
            self.state.append(f"[{tool}] {output[:200]}")
            self.engine.on_tool_result(
                ToolResult(call_id=call.call_id, tool=tool, ok=ok, output=output)
            )
        return result
