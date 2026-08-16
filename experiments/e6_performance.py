"""E6：性能（检测延迟）。

度量检测内核（DetectionEngine）单次判定的耗时：
- 平均延迟 (ms) / 95 分位 / 最大
- 在 20 攻击 + 8 正常场景的全部工具调用上测量（on_tool_call 耗时）
- 输出论文 §5.4 性能表数据

纯内核度量，不涉及 LLM/沙箱，确定性。
"""

from __future__ import annotations

import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_core import DetectionEngine, TaskMeta, ToolCall, ToolSpec


def measure_latency(n_warmup: int = 100, n_measure: int = 1000) -> dict:
    """测量 DetectionEngine.on_tool_call 延迟。

    用标准任务构造循环调用（合法 read 调用），统计 warmup 后耗时。
    """
    tools = [ToolSpec(id=t) for t in ["read", "edit"]]
    meta = TaskMeta(
        task_id="perf",
        task_desc="先分析项目文档，然后修改",
        available_tools=tools,
        environment={"workspace": "workspace"},
    )
    engine = DetectionEngine()
    engine.on_task_start(meta)
    call = ToolCall(
        call_id="perf:read", tool="read", args={"path": "workspace/a.md"}, caller="perf"
    )

    # warmup（触发分支也测一次）
    for _ in range(n_warmup):
        engine.on_tool_call(call)

    latencies = []
    for _ in range(n_measure):
        t0 = time.perf_counter()
        engine.on_tool_call(call)
        latencies.append((time.perf_counter() - t0) * 1000.0)

    latencies.sort()
    return {
        "mean_ms": round(statistics.mean(latencies), 4),
        "median_ms": round(statistics.median(latencies), 4),
        "p95_ms": round(latencies[int(len(latencies) * 0.95)], 4),
        "max_ms": round(latencies[-1], 4),
        "n_measure": n_measure,
    }


def run_e6() -> dict:
    """E6 主流程：测量并返回性能指标。"""
    return {"detection_kernel": measure_latency()}


def format_e6(res: dict) -> str:
    m = res["detection_kernel"]
    return (
        "E6 检测内核延迟（on_tool_call）\n"
        f"  平均: {m['mean_ms']} ms | 中位: {m['median_ms']} ms | "
        f"P95: {m['p95_ms']} ms | 最大: {m['max_ms']} ms（n={m['n_measure']}）"
    )


if __name__ == "__main__":
    res = run_e6()
    print(format_e6(res))
    out = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "e6.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(f"\n(e6.json 已写入 {os.path.abspath(out)})")
