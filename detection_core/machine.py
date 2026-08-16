"""行为状态机（对应论文第4.4节）。

状态集合 {INIT, PLAN, EXEC, VERIFY, DONE, BLOCKED}，转移骨架跨任务通用。
单步转移合法性由纯函数 is_legal 判定。
"""

from __future__ import annotations

from detection_core.models import Profile, ToolCall

INIT = "INIT"
PLAN = "PLAN"
EXEC = "EXEC"
VERIFY = "VERIFY"
DONE = "DONE"
BLOCKED = "BLOCKED"

# 合法的状态集合
STATES = {INIT, PLAN, EXEC, VERIFY, DONE, BLOCKED}


class TaskStateMachine:
    """每任务实例一个状态机。"""

    def __init__(self, task_id: str, profile: Profile):
        self.task_id = task_id
        self.profile = profile
        self.state = INIT
        self.seen_categories: set[str] = set()  # 已出现过的工具类别（用于 order 前序检查）
        self.blocked = False

    # ------------------------------------------------------------------
    # 转移
    # ------------------------------------------------------------------

    def on_task_start(self) -> None:
        """任务启动事件：INIT -> PLAN。"""
        self.state = PLAN

    def on_first_tool_call(self) -> None:
        """首次工具调用：PLAN -> EXEC。"""
        if self.state == PLAN:
            self.state = EXEC

    def on_task_complete(self) -> None:
        """任务完成事件：EXEC -> VERIFY -> DONE。"""
        if self.state in (EXEC, VERIFY):
            self.state = DONE

    def on_detection_triggered(self) -> None:
        """任一检测通道触发：任意状态 -> BLOCKED（终止态）。"""
        self.state = BLOCKED
        self.blocked = True

    # ------------------------------------------------------------------
    # 单步转移合法性（纯函数语义，但依赖实例的已见类别集合）
    # ------------------------------------------------------------------

    def is_legal(self, call: ToolCall) -> tuple[bool, str]:
        """判定当前调用是否可合法转移（仅状态骨架）。

        A 类（类别白名单）与 D 类（顺序）判定由通道1（channel_state_machine）
        承担，本函数**不再**做类别/顺序检查——确保消融实验中关闭 machine
        通道时 A/D 检测确实被禁用（对应审查 P0-1）。
        """
        from detection_core.models import cat_of

        # 终止态后不放行
        if self.blocked or self.state == BLOCKED:
            return False, "BLOCKED"

        category = cat_of(call.tool)

        # 骨架转移（EXEC 内合法调用保持；seen_categories 仅作状态维护，
        # 不参与 A/D 判定——A/D 由通道1使用）
        if self.state in (PLAN, EXEC, VERIFY):
            self.state = EXEC  # 合法调用推进到执行态
            self.seen_categories.add(category)
            return True, "ok"
        if self.state == INIT:
            self.state = PLAN
            self.seen_categories.add(category)
            return True, "ok"
        return False, f"no transition from {self.state}"

    def on_result(self, result) -> None:
        """工具执行结果更新（当前骨架无需切换状态，留接口）。"""
        pass
