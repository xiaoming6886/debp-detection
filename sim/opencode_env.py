"""OpenCode 编排框架模拟层（依据 anomalyco/opencode 真实源码建模）。

源码基准：anomalyco/opencode @ 4643e65ad6334de3e4e68dedc201d5fbb828c9fe (dev 分支) / release v1.18.18

源码事实（与模拟实现逐条对应）：
1. 检查点位置：packages/opencode/src/session/tools.ts 的 SessionTools.resolve() 中，
   execute 包装器顺序为 tool.execute.before → item.execute → tool.execute.after。
2. hook 语义（packages/plugin/src/index.ts）：before 的 output 仅 {args}，after 的
   output 为 {title, output, metadata}；plugin.trigger 按引用修改 output 对象，
   不返回值替换（packages/opencode/src/plugin/index.ts L277）。
3. 阻断语义（packages/opencode/src/permission/index.ts）：before hook 不能返回 deny；
   真正的阻断是权限检查（等价 ctx.ask）抛 DeniedError/RejectedError → 工具不执行 →
   processor.failToolCall 将 part 状态置 error → ctx.blocked=true → process() 返回
   "stop" → 主循环 break（除非 experimental.continue_loop_on_deny）。
4. 结果回传（session/message-v2.ts）：completed 状态 → {title, metadata, output,
   attachments?}；error 状态 → errorText。

本模拟层以检测内核（DetectionEngine）等价 permission.ask 检查点：deny → 工具不执行
+ 记录 error + 默认终止循环（stop 语义），与源码阻断链路一致。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from detection_core import DetectionEngine, TaskMeta, ToolCall, ToolResult
from sim.tools import ToolSandbox


@dataclass
class StepRecord:
    """单次工具调用记录（after hook 输出结构 {title, output, metadata}）。"""

    tool: str
    args: dict
    allow: bool
    reason_code: str | None = None
    detail: str = ""
    ok: bool | None = None
    output: str = ""
    title: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class TrajectoryResult:
    """一次任务轨迹的执行结果。"""

    task_id: str
    steps: list[StepRecord] = field(default_factory=list)
    outcome: str = "completed"  # completed | intercepted
    trigger_code: str | None = None
    trigger_step: int = -1

    @property
    def intercepted(self) -> bool:
        return self.outcome == "intercepted"

    @property
    def tool_count(self) -> int:
        return len(self.steps)


class OpenCodeEnv:
    """OpenCode 文本管道循环模拟执行器。

    每次工具调用模拟源码链路：
    1. tool.execute.before（output {args}，按引用，模拟层透传）
    2. 权限检查（检测内核三通道判定，等价 ctx.ask）
    3. deny → 工具不执行，part error，process 返回 stop → 循环 break
    4. allow → item.execute（沙箱执行）
    5. tool.execute.after（output {title, output, metadata}）
    6. 结果回传检测内核（数据流传播、状态机推进）
    """

    def __init__(
        self,
        engine: DetectionEngine,
        sandbox: ToolSandbox,
        continue_loop_on_deny: bool = False,
    ):
        self.engine = engine
        self.sandbox = sandbox
        # 对应 experimental.continue_loop_on_deny：deny 后是否继续让 LLM 看到错误
        self.continue_loop_on_deny = continue_loop_on_deny

    def start(self, task_meta: TaskMeta) -> None:
        """注册任务并推导期望行为轮廓。"""
        self.engine.on_task_start(task_meta)

    def run(
        self,
        task_id: str,
        calls: list[dict],
        max_steps: int = 100,
    ) -> TrajectoryResult:
        """按预设工具调用序列执行轨迹（模拟主循环 step）。

        calls: [{"tool": "read", "args": {...}}, ...]
        任一调用触发检测拦截 → 工具不执行（error part）→ 默认终止循环（stop 语义）。
        """
        result = TrajectoryResult(task_id=task_id)
        for i, spec in enumerate(calls[:max_steps]):
            tool = spec["tool"]
            args = spec.get("args", {})

            # 1. tool.execute.before：output {args} 按引用（模拟层无插件，透传）
            before_output = {"args": args}

            # 2. 权限检查：检测内核判定（等价 Permission.ask）
            call = ToolCall(
                call_id=f"{task_id}:{tool}",
                tool=tool,
                args=before_output["args"],
                caller=task_id,
            )
            decision = self.engine.on_tool_call(call)

            if not decision.allow:
                # 3. deny：工具不执行（DeniedError 语义），part 状态 error
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
                if not self.continue_loop_on_deny:
                    # process() 返回 "stop" → 主循环 break（prompt.ts L1315）
                    break
                # continue_loop_on_deny：LLM 收到 errorText 后继续下一轮
                continue

            # 4. item.execute：沙箱执行
            ok, output = self.sandbox.call(tool, args)

            # 5. tool.execute.after：output {title, output, metadata}（按引用）
            after_output = {"title": tool, "output": output, "metadata": {}}

            # 6. 结果回传（completeToolCall 语义）：数据流传播、状态机推进
            self.engine.on_tool_result(
                ToolResult(call_id=call.call_id, tool=tool, ok=ok, output=output)
            )
            result.steps.append(
                StepRecord(
                    tool=tool,
                    args=args,
                    allow=True,
                    ok=ok,
                    output=output,
                    title=after_output["title"],
                    metadata=after_output["metadata"],
                )
            )
        return result
