"""E8：行为层同类方案对比（对应论文 P0-2 补强）

三个检测方案在同一 20 攻击 + 8 正常场景集上对比：
- DEBP             ：三通道（状态机+参数边界+数据流）
- ClawGuard 风格   ：任务→规则集→单调用校验（确定性，零 LLM）
- PlanGuard 风格   ：Planner(LLM 参考动作集)+Stage I 硬约束+Stage II LLM 验证

输出 TPR/FPR、逐类检出与漏检场景明细。
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.baselines import clawguard_run, planguard_run
from experiments.run_trajectory import run_scenario
from experiments.scenarios import ATTACK_SCENARIOS, NORMAL_TASKS
from sim.llm_client import LLMClient

RESULT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def by_class_summary(scenarios, intercepted_map: dict[str, bool]) -> dict:
    """按类别汇总：每个类别 total/detected/missed 场景 id 列表。"""
    summary: dict[str, dict] = {}
    for s in scenarios:
        cat = s.category
        if cat not in summary:
            summary[cat] = {"total": 0, "detected": 0, "missed": []}
        summary[cat]["total"] += 1
        if intercepted_map.get(s.sid, False):
            summary[cat]["detected"] += 1
        else:
            summary[cat]["missed"].append(s.sid)
    return summary


def run_e8(backend: str = "deepseek", n_runs: int = 3) -> dict:
    result: dict = {
        "backend": backend,
        "n_runs": n_runs,
        "methods": {},
        "llm_note": "",
    }

    # ---- DEBP（确定性内核，零 LLM） ----
    debp_attack = {
        s.sid: run_scenario(s, framework="opencode", channels=None).result.intercepted
        for s in ATTACK_SCENARIOS
    }
    debp_normal = {
        s.sid: run_scenario(s, framework="opencode", channels=None).result.intercepted
        for s in NORMAL_TASKS
    }
    result["methods"]["DEBP"] = {
        "tpr": sum(debp_attack.values()) / len(ATTACK_SCENARIOS),
        "fpr": sum(debp_normal.values()) / len(NORMAL_TASKS),
        "attack_by_class": by_class_summary(ATTACK_SCENARIOS, debp_attack),
        "normal_misblocked": [sid for sid, v in debp_normal.items() if v],
    }

    # ---- ClawGuard 风格（确定性，零 LLM） ----
    cg_attack = {s.sid: clawguard_run(s) for s in ATTACK_SCENARIOS}
    cg_normal = {s.sid: clawguard_run(s) for s in NORMAL_TASKS}
    result["methods"]["clawguard_style"] = {
        "tpr": sum(cg_attack.values()) / len(ATTACK_SCENARIOS),
        "fpr": sum(cg_normal.values()) / len(NORMAL_TASKS),
        "attack_by_class": by_class_summary(ATTACK_SCENARIOS, cg_attack),
        "normal_misblocked": [sid for sid, v in cg_normal.items() if v],
    }

    # ---- PlanGuard 风格（需 LLM，n_runs 次报均值±标准差） ----
    try:
        client = LLMClient(backend=backend, temperature=0.0)
        pg_tprs: list[float] = []
        pg_fprs: list[float] = []
        pg_per_run: list[dict] = []
        for _run_i in range(n_runs):
            pg_attack: dict[str, bool] = {}
            pg_stage: dict[str, str] = {}
            pg_normal: dict[str, bool] = {}
            for s in ATTACK_SCENARIOS:
                blocked, stage = planguard_run(client, s)
                pg_attack[s.sid] = blocked
                pg_stage[s.sid] = stage or "pass"
            for s in NORMAL_TASKS:
                blocked, _ = planguard_run(client, s)
                pg_normal[s.sid] = blocked
            tpr_v = sum(pg_attack.values()) / len(ATTACK_SCENARIOS)
            fpr_v = sum(pg_normal.values()) / len(NORMAL_TASKS)
            pg_tprs.append(tpr_v)
            pg_fprs.append(fpr_v)
            pg_per_run.append(
                {
                    "tpr": tpr_v,
                    "fpr": fpr_v,
                    "attack_by_class": by_class_summary(ATTACK_SCENARIOS, pg_attack),
                    "normal_misblocked": [sid for sid, v in pg_normal.items() if v],
                    "stage_by_scenario": pg_stage,
                }
            )
        import statistics

        result["methods"]["planguard_style"] = {
            "tpr_mean": sum(pg_tprs) / len(pg_tprs),
            "tpr_std": statistics.stdev(pg_tprs) if n_runs > 1 else 0.0,
            "fpr_mean": sum(pg_fprs) / len(pg_fprs),
            "fpr_std": statistics.stdev(pg_fprs) if n_runs > 1 else 0.0,
            "n_runs": n_runs,
            "per_run": pg_per_run,
        }
    except RuntimeError as e:
        result["methods"]["planguard_style"] = {"error": str(e)[:200]}
        result["llm_note"] = "PlanGuard 风格基线因 LLM 不可用未完成（已记录，不静默）"

    return result


def format_e8(res: dict) -> str:
    lines = ["E8 行为层同类对比（20 攻击 + 8 正常）"]
    lines.append("方案 | TPR | FPR | 说明")
    lines.append("-----|-----|-----|------")
    for name, m in res["methods"].items():
        if "error" in m:
            lines.append(f"{name} | ERR | ERR | {m['error'][:40]}")
            continue
        if name == "planguard_style":
            tpr_s = f"{m['tpr_mean'] * 100:.0f}%±{m['tpr_std'] * 100:.0f}%"
            fpr_s = f"{m['fpr_mean'] * 100:.0f}%±{m['fpr_std'] * 100:.0f}%"
            last = m["per_run"][-1]
            missed = []
            for cat, cm in last["attack_by_class"].items():
                if cm["missed"]:
                    missed.append(f"{cat}:{','.join(cm['missed'])}")
            note = f"漏检 {'; '.join(missed)}" if missed else "无漏检"
        else:
            tpr_s = f"{m['tpr'] * 100:.0f}%"
            fpr_s = f"{m['fpr'] * 100:.0f}%"
            missed = []
            for cat, cm in m["attack_by_class"].items():
                if cm["missed"]:
                    missed.append(f"{cat}:{','.join(cm['missed'])}")
            note = f"漏检 {'; '.join(missed)}" if missed else "无漏检"
        lines.append(f"{name} | {tpr_s} | {fpr_s} | {note}")
    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", default="deepseek", choices=["deepseek", "qwen"])
    parser.add_argument("--n-runs", type=int, default=3)
    args = parser.parse_args()
    res = run_e8(backend=args.backend, n_runs=args.n_runs)
    print(format_e8(res))
    os.makedirs(RESULT_DIR, exist_ok=True)
    path = os.path.join(RESULT_DIR, "e8_behavioral_baselines.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(f"\n(e8_behavioral_baselines.json 已写入 {os.path.abspath(path)})")
