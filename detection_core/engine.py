"""检测内核主类（对应论文第4.3、4.5节）。

标准接口：on_task_start / on_tool_call / on_tool_result
三通道独立判定，融合时优先级 A1 > C > B > D（A1 工具不可用最高）。
"""

from __future__ import annotations

from detection_core.audit import AuditLogger
from detection_core.channels import (
    DataFlowTracker,
    channel_parameter_boundary,
    channel_state_machine,
)
from detection_core.machine import TaskStateMachine
from detection_core.models import Decision, Profile, ReasonCode, TaskMeta, ToolCall
from detection_core.profile import derive_profile


class DetectionEngine:
    """框架无关的检测内核（纯函数库，无 I/O）。"""

    def __init__(self, channels_enabled: set[str] | None = None):
        """channels_enabled: 消融开关，默认全开 {"machine","parameter","dataflow"}。"""
        self.channels_enabled = channels_enabled or {"machine", "parameter", "dataflow"}
        self.tasks: dict[str, TaskStateMachine] = {}
        self.trackers: dict[str, DataFlowTracker] = {}
        self.audit = AuditLogger()

    # ------------------------------------------------------------------
    # 标准接口
    # ------------------------------------------------------------------

    def on_task_start(self, task_meta: TaskMeta) -> Profile:
        profile = derive_profile(task_meta)
        # 将环境敏感值挂到 profile 上供数据流通道使用（不进入序列化输出）
        profile._env_values = task_meta.environment.get("sensitive_env", {})
        # 将可用工具 schema 挂到 profile 上供参数边界通道使用（B1 校验依据，
        # 对应审查 P1-1：schema 来自工具定义，而非调用参数）
        profile._tool_schemas = {t.id: t.schema for t in task_meta.available_tools}
        machine = TaskStateMachine(task_meta.task_id, profile)
        machine.on_task_start()
        self.tasks[task_meta.task_id] = machine
        self.trackers[task_meta.task_id] = DataFlowTracker(profile)
        return profile

    def on_tool_call(self, call: ToolCall) -> Decision:
        machine = self.tasks.get(call.caller)
        if machine is None:
            return Decision(allow=False, detail="unknown task")

        c1 = c2 = c3 = (False, None, "")
        if "machine" in self.channels_enabled:
            c1 = channel_state_machine(machine.seen_categories, machine.profile, call.tool)
        if "parameter" in self.channels_enabled:
            c2 = channel_parameter_boundary(call, machine.profile)
        if "dataflow" in self.channels_enabled:
            tracker = self.trackers[call.caller]
            c3 = tracker.on_tool_call(call)

        triggered = [x for x in (c1, c2, c3) if x[0]]
        if triggered:
            # 融合：取最高危害（A1 > C > B > D）
            winner = max(triggered, key=lambda x: _severity(x[1]))
            machine.on_detection_triggered()
            decision = Decision(allow=False, reason_code=winner[1], detail=winner[2])
        else:
            legal, msg = machine.is_legal(call)
            if not legal:
                machine.on_detection_triggered()
                decision = Decision(allow=False, reason_code=ReasonCode.A1, detail=msg)
            else:
                decision = Decision(allow=True)
        self.audit.log(call, decision)
        return decision

    def on_tool_result(self, result) -> None:
        tracker = self.trackers.get(result.call_id.split(":")[0])
        if tracker is not None:
            tracker.on_tool_result(result)
        machine = self.tasks.get(result.call_id.split(":")[0])
        if machine is not None:
            machine.on_result(result)


def _severity(code: ReasonCode | None) -> int:
    """融合优先级：A1（工具不可用）最高，其次 C（数据外泄），其次 B（越权），其次 D（顺序）。

    语义：先拦截"工具根本不该用"（A1），再拦"数据不可逆外泄"（C），
    再拦"越权使用"（B），最后拦"顺序错乱"（D）。
    """
    if code == ReasonCode.A1:
        return 4
    if code in (ReasonCode.C1, ReasonCode.C2):
        return 3
    if code in (ReasonCode.B1, ReasonCode.B2):
        return 2
    return 1
