"""卡方独立性检验：验证检测决策与模型/框架的无关性。

用于论文 §5 的统计论证：
1. B2 基线（LLM 自检测）的决策 × 模型（DeepSeek/Qwen）：若独立，
   说明 LLM 审查器的高误报是跨模型的普遍现象；
2. DEBP 的决策 × 框架（OpenCode/LangGraph）：若独立，支撑框架无关性。
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scipy import stats


def _collect_b2_decisions(backend: str) -> list[bool]:
    """重新跑 B2 基线，收集每个场景的决策（True=拦截）。

    为节省 LLM 调用，直接读取实验结果 JSON 中的聚合值不可行（不存逐场景
    决策），因此本函数实际重跑 B2。调用方注意 token 消耗。
    """
    from experiments.e4_complementarity import llm_baseline_run
    from experiments.scenarios import ATTACK_SCENARIOS, NORMAL_TASKS
    from sim.llm_client import LLMClient

    client = LLMClient(backend=backend, temperature=0.0)
    decisions = []
    for s in ATTACK_SCENARIOS:
        decisions.append(llm_baseline_run(s, client))
    for s in NORMAL_TASKS:
        decisions.append(llm_baseline_run(s, client))
    return decisions


def chi2_independence(model_decisions: dict[str, list[bool]], label: str) -> dict:
    """2×K 卡方检验：模型 × 决策（拦截/放行）独立性。

    model_decisions: {模型名: [28 个布尔决策]}（20 攻击 + 8 正常）
    """
    models = list(model_decisions.keys())
    n = len(model_decisions[models[0]])
    table = [[0, 0] for _ in models]  # [拦截, 放行]
    for i, m in enumerate(models):
        table[i][0] = sum(1 for d in model_decisions[m] if d)
        table[i][1] = n - table[i][0]

    chi2, p, dof, expected = stats.chi2_contingency(table)
    return {
        "test": label,
        "models": models,
        "n_scenarios": n,
        "table": table,
        "chi2": round(float(chi2), 4),
        "p_value": round(float(p), 4),
        "dof": int(dof),
        "independent": bool(p > 0.05),
    }


def _debp_framework_table() -> dict:
    """DEBP 决策 × 框架：E5 已证明 4 组合 100% 一致，直接构造列联表。"""
    from experiments.run_trajectory import run_scenario
    from experiments.scenarios import ATTACK_SCENARIOS, NORMAL_TASKS

    oc = [run_scenario(s, "opencode").result.intercepted for s in ATTACK_SCENARIOS + NORMAL_TASKS]
    lg = [run_scenario(s, "langgraph").result.intercepted for s in ATTACK_SCENARIOS + NORMAL_TASKS]
    n = len(oc)
    table = [
        [sum(1 for d in oc if d), n - sum(1 for d in oc if d)],
        [sum(1 for d in lg if d), n - sum(1 for d in lg if d)],
    ]
    chi2, p, dof, expected = stats.chi2_contingency(table)
    return {
        "test": "DEBP 决策 × 框架独立性",
        "models": ["opencode", "langgraph"],
        "n_scenarios": n,
        "table": table,
        "chi2": round(float(chi2), 4),
        "p_value": round(float(p), 4),
        "dof": int(dof),
        "independent": bool(p > 0.05),
    }


if __name__ == "__main__":
    # 1) B2 基线：模型无关性（重跑 B2 收集逐场景决策，DeepSeek + Qwen）
    #    结果缓存到 results/e7_b2_decisions.json，避免重复 LLM 调用
    cache_path = os.path.join(os.path.dirname(__file__), "..", "results", "e7_b2_decisions.json")
    if os.path.exists(cache_path):
        print("从缓存读取 B2 决策...")
        cache = json.load(open(cache_path, encoding="utf-8"))
        b2_ds = cache["deepseek"]
        b2_qw = cache["qwen"]
    else:
        print("正在重跑 B2 基线收集逐场景决策（DeepSeek + Qwen，各 28 场景）...")
        b2_ds = _collect_b2_decisions("deepseek")
        b2_qw = _collect_b2_decisions("qwen")
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump({"deepseek": b2_ds, "qwen": b2_qw}, f)
    res_b2 = chi2_independence({"deepseek": b2_ds, "qwen": b2_qw}, "B2 基线决策 × 模型独立性")
    print(f"B2 基线：DeepSeek 拦截 {sum(b2_ds)}/28，Qwen 拦截 {sum(b2_qw)}/28")
    print(f"  chi2={res_b2['chi2']}, p={res_b2['p_value']}, dof={res_b2['dof']}")
    print(f"  独立性判定: {'独立（模型无关）' if res_b2['independent'] else '非独立'}")

    # 2) DEBP：框架无关性（确定性，无需 LLM）
    print("正在运行 DEBP 双框架（确定性，无 LLM 调用）...")
    res_debp = _debp_framework_table()
    print(
        f"DEBP：OpenCode 拦截 {res_debp['table'][0][0]}/{res_debp['n_scenarios']}，"
        f"LangGraph 拦截 {res_debp['table'][1][0]}/{res_debp['n_scenarios']}"
    )
    print(f"  chi2={res_debp['chi2']}, p={res_debp['p_value']}, dof={res_debp['dof']}")
    print(f"  独立性判定: {'独立（框架无关）' if res_debp['independent'] else '非独立'}")

    # 3) 落盘
    out = os.path.join(os.path.dirname(__file__), "..", "results", "e7_independence.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"B2_model": res_b2, "DEBP_framework": res_debp}, f, ensure_ascii=False, indent=2)
    print(f"\n(e7_independence.json 已写入 {os.path.abspath(out)})")
