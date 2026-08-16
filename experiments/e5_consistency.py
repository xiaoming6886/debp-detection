"""E5：一致性实验（2×2 矩阵：框架 × 模型后端）。

验证目标（论文 §5.9 跨框架一致性）：检测内核的判定决策不随运行环境
（框架 / LLM 后端）变化。

方法学（对应审查 P0-2 修正）：
- 对每个攻击场景，使用**固定轨迹**（scenario.trajectory，确定性注入攻击），
  在 4 组合（OpenCode/DeepSeek、OpenCode/Qwen、LangGraph/DeepSeek、
  LangGraph/Qwen）上各重复运行 N 次；
- 指标1 组合内一致率：同一组合 N 次运行的决策完全一致（检测确定性）；
- 指标2 跨组合一致率：同一场景在 4 组合上的拦截决策完全一致
  （框架/模型无关性）；
- 指标3 跨组合 TPR：4 组合的 TPR 应一致且等于 E1 的 TPR。

说明：不采用"LLM 自由生成轨迹"验证一致性，因为攻击场景的注入内容
（文档/工具描述投毒）不在任务描述中，LLM 从良性 task_desc 无法复现
攻击，会得到 trivially 全放行（=0 TPR），无法证明一致性（Momus 审查
P0-2 指出的结构性缺陷）。LLM 生成轨迹仅用于 E4 基线，不参与 E5。
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.metrics import decision_consistency
from experiments.run_trajectory import run_scenario
from experiments.scenarios import ATTACK_SCENARIOS

# 2×2 组合（framework, backend）。backend 字段保留用于扩展（当前固定轨迹
# 不调用 LLM，backend 无实际作用，但保留组合结构供论文表述）
COMBINATIONS = [
    ("opencode", "deepseek"),
    ("opencode", "qwen"),
    ("langgraph", "deepseek"),
    ("langgraph", "qwen"),
]


def run_e5(n_runs: int = 3) -> dict:
    """E5 主流程：固定攻击轨迹 × 4 组合 × n_runs。"""
    # 每组合收集每个场景的决策序列：per_combo[combo][scenario_idx] = [bool × n_runs]
    per_combo: dict[tuple, list[list[bool]]] = {c: [] for c in COMBINATIONS}

    for scenario in ATTACK_SCENARIOS:
        for combo in COMBINATIONS:
            framework, _backend = combo
            decisions = []
            for _ in range(n_runs):
                outcome = run_scenario(scenario, framework=framework, channels=None)
                decisions.append(outcome.result.intercepted)
            per_combo[combo].append(decisions)

    result: dict = {"n_runs": n_runs, "combinations": {}, "cross_combo": {}}
    # 指标1：组合内一致率（每场景决策向量跨 n_runs 比对）
    for combo, runs in per_combo.items():
        # runs: list[场景][run] → 转置为 list[run][场景] 供 decision_consistency
        n_scen = len(runs)
        transposed = [[runs[i][j] for i in range(n_scen)] for j in range(n_runs)]
        result["combinations"][f"{combo[0]}/{combo[1]}"] = {
            "consistency": decision_consistency(transposed),
            "tpr": sum(1 for d in runs if any(d)) / n_scen,
        }

    # 指标2/3：跨组合一致率（每场景在 4 组合的首次运行决策完全一致）
    n_scen = len(ATTACK_SCENARIOS)
    cross_consistent = 0
    per_combo_tpr: dict[str, float] = {}
    for i in range(n_scen):
        first_run = [per_combo[c][i][0] for c in COMBINATIONS]
        if len(set(first_run)) == 1:
            cross_consistent += 1
    for combo in COMBINATIONS:
        per_combo_tpr[f"{combo[0]}/{combo[1]}"] = (
            sum(1 for i in range(n_scen) if per_combo[combo][i][0]) / n_scen
        )

    result["cross_combo"] = {
        "consistency": cross_consistent / n_scen,
        "scenarios": n_scen,
        "per_combo_tpr": per_combo_tpr,
    }
    return result


def format_e5(res: dict) -> str:
    lines = [f"E5 一致性（2×2 矩阵，n_runs={res['n_runs']}，固定攻击轨迹）"]
    lines.append("组合 | 组合内一致率 | TPR")
    lines.append("-----|-------------|-----")
    for combo, m in res["combinations"].items():
        lines.append(f"{combo} | {m['consistency']:.0%} | {m['tpr']:.0%}")
    lines.append(
        f"跨组合一致率: {res['cross_combo']['consistency']:.0%} "
        f"（{res['cross_combo']['scenarios']} 场景）"
    )
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--n-runs", type=int, default=3)
    args = parser.parse_args()
    res = run_e5(n_runs=args.n_runs)
    print(format_e5(res))
    out = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "e5.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(f"\n(e5.json 已写入 {os.path.abspath(out)})")
