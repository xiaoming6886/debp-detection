"""E1：检测有效性（TPR 按类 × 框架）。

运行全部攻击场景（A/B/C/D 各 5），在双框架上统计：
- 全通道检测的 TPR（按类 + 总体）
- 与无检测基线 B1 对比（B1 下所有攻击"成功"，TPR=0）
- 结果输出为表格式文本 + JSON（供论文 §5.3 填表）
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.metrics import summarize_by_class, tpr
from experiments.run_trajectory import run_all_attacks


def run_e1(framework: str) -> dict:
    """在指定框架上运行 E1，返回指标字典。"""
    outcomes = run_all_attacks(framework, channels=None)
    # 按类别统计: (category, is_attack, intercepted)
    rows = [(_cat_of(s), True, s.result.intercepted) for s in outcomes]
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


def _cat_of(outcome) -> str:
    """从场景 sid 取类别（A1→A, B3→B...）。"""
    return outcome.scenario_id[0]


def format_e1(results: list[dict]) -> str:
    """格式化 E1 结果表。"""
    lines = ["E1 检测有效性（TPR）"]
    lines.append("类别 | 场景数 | OpenCode | LangGraph")
    lines.append("-----|--------|----------|----------")
    cats = ["A", "B", "C", "D"]
    for cat in cats:
        vals = [r["by_class"].get(cat, {}).get("tpr", 0.0) for r in results]
        total = results[0]["by_class"][cat]["total"] if cat in results[0]["by_class"] else 0
        lines.append(f"{cat} | {total} | {vals[0]:.0%} | {vals[1]:.0%}")
    lines.append(
        f"总体 | {results[0]['total_attacks']} | "
        f"{results[0]['overall_tpr']:.0%} | {results[1]['overall_tpr']:.0%}"
    )
    return "\n".join(lines)


if __name__ == "__main__":
    res = [run_e1("opencode"), run_e1("langgraph")]
    print(format_e1(res))
    out = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "e1.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(f"\n(e1.json 已写入 {os.path.abspath(out)})")
