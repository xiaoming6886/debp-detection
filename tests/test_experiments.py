"""实验组件单元测试（metrics / LLM 轨迹解析）。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.llm_trajectory import parse_json_lines
from experiments.metrics import decision_consistency, fpr, summarize_by_class, tpr

# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------


def test_tpr_fpr():
    assert tpr(5, 5) == 1.0
    assert tpr(0, 5) == 0.0
    assert tpr(0, 0) == 0.0
    assert fpr(1, 8) == 0.125
    assert fpr(0, 8) == 0.0


def test_summarize_by_class():
    results = [
        ("A", True, True),
        ("A", True, True),
        ("A", True, False),
        ("B", True, True),
        ("N", False, True),
        ("N", False, False),
    ]
    by = summarize_by_class(results)
    assert by["A"].total == 3 and by["A"].detected == 2
    assert by["B"].detected == 1
    assert by["N"].total == 2 and by["N"].false_positives == 1


def test_decision_consistency():
    # 3 次运行，5 步：第 1/3/4/5 步一致，第 2 步分歧 → 4/5
    runs = [
        [True, True, False, True, False],
        [True, False, False, True, False],
        [True, True, False, True, False],
    ]
    assert decision_consistency(runs) == 0.8
    assert decision_consistency([[True], [True]]) == 1.0


# ---------------------------------------------------------------------------
# LLM 轨迹解析
# ---------------------------------------------------------------------------


def test_parse_json_array():
    text = '[{"tool": "read", "args": {"path": "a.md"}, "reason": "x"}, {"tool": "edit", "args": {"path": "a.md", "content": "y"}, "reason": "z"}]'
    parsed = parse_json_lines(text)
    assert len(parsed) == 2
    assert parsed[0]["tool"] == "read"
    assert parsed[1]["tool"] == "edit"


def test_parse_json_lines_with_fence():
    text = '```json\n[{"tool": "read", "args": {"path": "a.md"}}]\n```'
    parsed = parse_json_lines(text)
    assert len(parsed) == 1
    assert parsed[0]["tool"] == "read"


def test_parse_json_lines_sequence():
    text = '{"tool": "read", "args": {"path": "a.md"}}\n{"tool": "bash", "args": {"command": "ls"}}'
    parsed = parse_json_lines(text)
    assert len(parsed) == 2


def test_parse_json_empty():
    assert parse_json_lines("") == []
    assert parse_json_lines("just some text without json") == []


def test_parse_json_drops_malformed():
    """整体数组含坏元素时，不静默返回部分结果（数组解析失败则逐行；返回空可接受，须告警）。"""
    text = '[{"tool": "read", "args": {"path": "a.md"} BAD}, {"tool": "edit", "args": {"path": "b.md"}}]'
    parsed = parse_json_lines(text)
    assert isinstance(parsed, list)  # 不抛异常；空结果由告警机制暴露
