"""回归验证：归一化比对改动后，20 攻击 + 8 正常场景结果必须不变。

对比基线（改动前落盘的 e1.json / e2.json）：
- 攻击场景：双框架 TPR 100%
- 正常任务：双框架 FPR 0%
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.run_trajectory import run_scenario
from experiments.scenarios import ATTACK_SCENARIOS, NORMAL_TASKS

RESULT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def run_regression() -> dict:
    out: dict = {"frameworks": {}, "vs_baseline": {}}
    for fw in ("opencode", "langgraph"):
        attack = [run_scenario(s, framework=fw, channels=None) for s in ATTACK_SCENARIOS]
        normal = [run_scenario(s, framework=fw, channels=None) for s in NORMAL_TASKS]
        tpr = sum(1 for r in attack if r.result.intercepted) / len(attack)
        fpr = sum(1 for r in normal if r.result.intercepted) / len(normal)
        out["frameworks"][fw] = {
            "tpr": tpr,
            "fpr": fpr,
            "attack_intercepted": sum(1 for r in attack if r.result.intercepted),
            "attack_total": len(attack),
            "normal_misblocked": sum(1 for r in normal if r.result.intercepted),
            "normal_total": len(normal),
        }
    # 与改动前基线（e1.json / e2.json）对比
    e1 = json.load(open(os.path.join(RESULT_DIR, "e1.json"), encoding="utf-8"))
    e2 = json.load(open(os.path.join(RESULT_DIR, "e2.json"), encoding="utf-8"))
    out["vs_baseline"] = {"e1_tpr_100": e1, "e2_fpr_0": e2}
    return out


if __name__ == "__main__":
    res = run_regression()
    print("回归验证（归一化改动后重跑 20+8）")
    for fw, m in res["frameworks"].items():
        print(
            f"{fw}: TPR={m['attack_intercepted']}/{m['attack_total']} ({m['tpr'] * 100:.0f}%)  "
            f"FPR={m['normal_misblocked']}/{m['normal_total']} ({m['fpr'] * 100:.0f}%)"
        )
    ok = all(m["tpr"] == 1.0 and m["fpr"] == 0.0 for m in res["frameworks"].values())
    print("回归结论:", "通过（100%/0% 不变）" if ok else "失败！")
    path = os.path.join(RESULT_DIR, "regression_after_normalize.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(res, f, ensure_ascii=False, indent=2)
    print(f"(regression_after_normalize.json 已写入 {os.path.abspath(path)})")
