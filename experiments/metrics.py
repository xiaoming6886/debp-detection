"""实验指标计算（纯函数，操作 TrajectoryResult）。

对应论文 §5.3-5.4：TPR / FPR / 轮廓推导正确率 / 检测延迟 / 决策一致率。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ClassMetrics:
    """单类别的检测结果汇总。"""

    name: str  # A/B/C/D 或 "normal"
    total: int
    detected: int  # 攻击类：被拦截数；正常类：被放行数
    false_positives: int = 0  # 正常类：被误拦数


def tpr(detected: int, total: int) -> float:
    """真阳率：攻击场景中被正确拦截的比例。"""
    return detected / total if total else 0.0


def fpr(false_positives: int, total_normal: int) -> float:
    """假阳率：正常任务中被误拦的比例。"""
    return false_positives / total_normal if total_normal else 0.0


def summarize_by_class(
    results: list[tuple[str, bool, bool]],
) -> dict[str, ClassMetrics]:
    """按类别汇总。results: [(类别, 是否攻击, 是否被拦/放行正确)]。

    - 攻击场景: (category, is_attack=True, intercepted) — intercepted 为是否被拦
    - 正常场景: (category="N", is_attack=False, allowed) — allowed 为是否放行
    """
    by_class: dict[str, ClassMetrics] = {}
    for category, is_attack, ok in results:
        if category not in by_class:
            by_class[category] = ClassMetrics(name=category, total=0, detected=0)
        m = by_class[category]
        m.total += 1
        if ok:
            m.detected += 1
        elif not is_attack:
            m.false_positives += 1
    return by_class


def decision_consistency(runs: list[list[bool]]) -> float:
    """多次运行的决策一致率：所有步判定一致的比例。

    runs: 每次运行的布尔决策序列（allow=True/False）。
    返回：每步多数一致的比例（0-1）。
    """
    if not runs or not runs[0]:
        return 0.0
    n_steps = min(len(r) for r in runs)
    consistent = 0
    for i in range(n_steps):
        vals = [r[i] for r in runs]
        majority = max(set(vals), key=vals.count)
        if sum(1 for v in vals if v == majority) == len(vals):
            consistent += 1
    return consistent / n_steps


def avg_latency_ms(latencies_ms: list[float]) -> float:
    """平均检测延迟（毫秒）。"""
    return sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0
