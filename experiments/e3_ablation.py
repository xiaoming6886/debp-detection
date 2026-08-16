"""E3：消融实验（三通道各自贡献）。

对比四种检测配置在双框架上的 TPR：
- full: 三通道全开
- machine-only: 仅状态机（A/D 类）
- parameter-only: 仅参数边界（B 类）
- dataflow-only: 仅数据流（C 类）
- none: 无检测（基线 B1）

对应论文 §5.3 消融表：展示三通道互补性——单通道只覆盖对应类别。
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# 消融配置
ABLATIONS = {
    "full": None,
    "machine_only": {"machine"},
    "parameter_only": {"parameter"},
    "dataflow_only": {"dataflow"},
}


def run_e3(framework: str) -> dict:
    """在指定框架上运行消融，返回各配置的 TPR。"""
    result = {}
    for name, channels in ABLATIONS.items():
        m = run_e1_for(framework, channels)
        result[name] = {
            "total": m["total_attacks"],
            "detected": m["detected"],
            "tpr": m["overall_tpr"],
            "by_class": m["by_class"],
        }
    return result


def run_e1_for(framework: str, channels: set[str] | None):
    """复用 run_e1 但允许指定消融通道。"""
    from experiments.metrics import summarize_by_class, tpr
    from experiments.run_trajectory import run_all_attacks

    outcomes = run_all_attacks(framework, channels=channels)
    rows = [(o.scenario_id[0], True, o.result.intercepted) for o in outcomes]
    by_class = summarize_by_class(rows)
    metrics = {
        "framework": framework,
        "total_attacks": len(outcomes),
        "detected": sum(1 for o in outcomes if o.result.intercepted),
        "by_class": {},
    }
    for cat, m in by_class.items():
        metrics["by_class"][cat] = {
            "total": m.total,
            "detected": m.detected,
            "tpr": round(tpr(m.detected, m.total), 4),
        }
    metrics["overall_tpr"] = round(tpr(metrics["detected"], metrics["total_attacks"]), 4)
    return metrics


def format_e3(results: dict[str, dict]) -> str:
    lines = [f"E3 消融实验（TPR，framework={list(results.values())[0]}）"]
    lines.append("配置 | 总体 TPR | A | B | C | D")
    lines.append("-----|---------|---|---|---|---")
    for name in ["full", "machine_only", "parameter_only", "dataflow_only"]:
        m = results[name]
        bc = m["by_class"]
        lines.append(
            f"{name} | {m['tpr']:.0%} | "
            f"{bc.get('A', {}).get('tpr', 0):.0%} | "
            f"{bc.get('B', {}).get('tpr', 0):.0%} | "
            f"{bc.get('C', {}).get('tpr', 0):.0%} | "
            f"{bc.get('D', {}).get('tpr', 0):.0%}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    all_res = {}
    for framework in ("opencode", "langgraph"):
        all_res[framework] = run_e3(framework)
    for _framework, res in all_res.items():
        print(format_e3(res))
        print()
    out = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "e3.json"), "w", encoding="utf-8") as f:
        json.dump(all_res, f, ensure_ascii=False, indent=2)
    print(f"(e3.json 已写入 {os.path.abspath(out)})")
