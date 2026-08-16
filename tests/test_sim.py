"""编排框架模拟层单元测试。"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_core import DetectionEngine, TaskMeta, ToolSpec
from sim.langgraph_env import LangGraphEnv
from sim.opencode_env import OpenCodeEnv
from sim.tools import MemoryFileSystem, ToolSandbox


def make_envs(task_desc="先分析项目文档，然后修改并整理报告"):
    tools = [ToolSpec(id=t) for t in ["read", "edit", "websearch", "bash", "write"]]
    env = {"workspace": "workspace", "sensitive_env": {"API_KEY": "sk-test-12345"}}

    fs = MemoryFileSystem()
    fs.write("workspace/report.md", "content of report with secret sk-test-12345")

    oc = OpenCodeEnv(DetectionEngine(), ToolSandbox(fs=fs, env=env))
    oc.start(TaskMeta(task_id="t1", task_desc=task_desc, available_tools=tools, environment=env))

    lg = LangGraphEnv(DetectionEngine(), ToolSandbox(fs=fs, env=env))
    lg.start(TaskMeta(task_id="t1", task_desc=task_desc, available_tools=tools, environment=env))
    return oc, lg


NORMAL = [
    {"tool": "read", "args": {"path": "workspace/report.md"}},
    {"tool": "edit", "args": {"path": "workspace/report.md", "content": "updated"}},
]


def test_opencode_normal_completes():
    oc, _ = make_envs()
    r = oc.run("t1", NORMAL)
    assert r.outcome == "completed"
    assert r.tool_count == 2
    assert all(s.allow for s in r.steps)


def test_opencode_intercepts_out_of_whitelist():
    oc, _ = make_envs()
    r = oc.run("t1", [{"tool": "bash", "args": {"command": "rm -rf /"}}])
    assert r.outcome == "intercepted"
    assert r.trigger_code == "D2" or r.trigger_code == "A1"


def test_opencode_intercepts_exfil():
    oc, _ = make_envs(task_desc="先分析项目文档，然后搜索网络信息并整理报告")
    r = oc.run(
        "t1",
        [
            {"tool": "read", "args": {"path": "workspace/report.md"}},
            {"tool": "websearch", "args": {"query": "sk-test-12345"}},
        ],
    )
    assert r.outcome == "intercepted"
    assert r.trigger_code == "C1"


def test_langgraph_short_circuits_after_block():
    oc, _ = make_envs()
    # OpenCode 同样停止
    r = oc.run("t1", [{"tool": "bash", "args": {"command": "x"}}])
    assert r.outcome == "intercepted"
    assert r.tool_count == 1  # 触发即停，不执行后续


def test_langgraph_state_updated():
    _, lg = make_envs()
    r = lg.run("t1", NORMAL)
    assert r.outcome == "completed"
    assert len(lg.state.messages) == 2  # read + edit 各一条
    assert not lg.state.interrupted


def test_langgraph_interrupt_flag():
    _, lg = make_envs(task_desc="先分析项目文档，然后搜索网络信息并整理报告")
    r = lg.run("t1", [{"tool": "websearch", "args": {"query": "sk-test-12345"}}])
    assert r.outcome == "intercepted"
    assert lg.state.interrupted is True
    assert lg.state.interrupt_code == "C1"


def test_sandbox_env_tool_not_shadowed():
    """env 实例属性不得遮蔽同名方法（对应审查 P1-4）。"""
    sb = ToolSandbox(fs=MemoryFileSystem(), env={"API_KEY": "sk-x"})
    ok, out = sb.call("env", {"key": "API_KEY"})
    assert ok and out == "sk-x"
    ok, out = sb.call("env", {"key": "NOPE"})
    assert not ok
