"""行为审计记录（对应论文第4.6节审计路径）。

结构化日志，字段：时间戳、调用事件、决策与原因码。
"""

from __future__ import annotations

import json
import time

from detection_core.models import Decision, ToolCall


class AuditLogger:
    """内存审计日志（实验环境落盘可选）。"""

    def __init__(self):
        self.records: list[dict] = []

    def log(self, call: ToolCall, decision: Decision) -> None:
        self.records.append(
            {
                "ts": round(time.time(), 6),
                "call_id": call.call_id,
                "tool": call.tool,
                "args": call.args,
                "caller": call.caller,
                "allow": decision.allow,
                "reason_code": decision.reason_code.value if decision.reason_code else None,
                "detail": decision.detail,
            }
        )

    def dump_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.records, f, ensure_ascii=False, indent=2)
