"""检测内核数据模型。

对应论文第3节定义1、定义2及第4.3节接口数据要素。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# 工具类别（跨任务通用，对应内核设计规格 §2.1）
# ---------------------------------------------------------------------------

CATEGORY: dict[str, set[str]] = {
    "read": {"read", "list", "grep", "view"},
    "edit": {"edit", "write", "patch"},
    "exec": {"bash", "execute", "run"},
    "web": {"websearch", "fetch", "http"},
    "data": {"db", "query", "sql"},
    "delegate": {"task", "spawn", "delegate"},
    "sys": {"env", "config", "package"},
}


def cat_of(tool_id: str) -> str:
    """工具标识到类别的映射（cat(tool)，论文定义2辅助记号）。"""
    for category, members in CATEGORY.items():
        if tool_id in members:
            return category
    # 未注册工具按自身 id 归入同名类别
    return tool_id


@dataclass
class ToolSpec:
    """工具定义（任务元数据中的可用工具清单元素）。"""

    id: str
    description: str = ""
    schema: dict = field(default_factory=dict)  # 参数模式：必填字段/类型/枚举


@dataclass
class TaskMeta:
    """任务元数据（on_task_start 输入，对应定义1的任务T）。"""

    task_id: str
    task_desc: str
    available_tools: list[ToolSpec] = field(default_factory=list)
    environment: dict = field(default_factory=dict)  # 环境提示，如工作区路径、域名白名单


@dataclass
class Profile:
    """期望行为轮廓 Profile(T)=(T_task,D_task,S_task,order)，对应定义1。"""

    task_id: str
    T_task: set[str] = field(default_factory=set)  # 可调用工具类别集
    D_task: set[str] = field(default_factory=set)  # 数据访问域白名单
    S_task: set[str] = field(default_factory=set)  # 敏感数据源集合
    order: list[tuple[str, str]] = field(default_factory=list)  # 类别前序关系 (先, 后)
    derivation_trace: list[str] = field(default_factory=list)  # 推导过程记录

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "T_task": sorted(self.T_task),
            "D_task": sorted(self.D_task),
            "S_task": sorted(self.S_task),
            "order": [[a, b] for a, b in self.order],
            "derivation_trace": self.derivation_trace,
        }


@dataclass
class ToolCall:
    """工具调用事件 call=(tool,args,caller,ts)，对应定义2。"""

    call_id: str
    tool: str
    args: dict = field(default_factory=dict)
    caller: str = "main"
    ts: float = 0.0


@dataclass
class ToolResult:
    """工具执行结果（on_tool_result 输入）。"""

    call_id: str
    tool: str
    output: Any = None
    ok: bool = True
    ts: float = 0.0


class ReasonCode(Enum):
    """异常原因码（对应论文表3）。"""

    A1 = "A1"  # 越界工具
    B1 = "B1"  # 参数越权
    B2 = "B2"  # 数据域越权
    C1 = "C1"  # 出网
    C2 = "C2"  # 写入外部域
    D1 = "D1"  # 顺序异常
    D2 = "D2"  # 前序缺失


@dataclass
class Decision:
    """判定输出（对应第4.3节决策结构）。"""

    allow: bool
    reason_code: ReasonCode | None = None
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "allow": self.allow,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "detail": self.detail,
        }
