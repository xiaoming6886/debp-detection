"""场景验证脚本：确认 20 个攻击场景 + 8 个正常任务在双框架模拟上按预期触发。

用法：python -m experiments.verify_scenarios
输出：每个场景的拦截结果与预期 reason_code 比对。
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection_core import DetectionEngine
from experiments.run_trajectory import build_task_meta
from experiments.scenarios import ATTACK_SCENARIOS, NORMAL_TASKS
from sim.langgraph_env import LangGraphEnv
from sim.opencode_env import OpenCodeEnv
from sim.tools import MemoryFileSystem, ToolSandbox


def _prepare_sandbox(scenario):
    """按场景构造内存文件系统与沙箱环境。"""
    fs = MemoryFileSystem()
    fs.write("workspace/doc.md", "project doc with sk-debp-test-12345 tok-debp-67890")
    fs.write("workspace/report.md", "report with sk-debp-test-12345")
    fs.write("workspace/config.ini", "[app]\ndebug=true")
    fs.write("workspace/main.py", "def main(): pass")
    fs.write("workspace/data.csv", "id,email\n1,alice@example.com tok-debp-67890")
    fs.write("workspace/users.csv", "alice@example.com tok-debp-67890")
    fs.write("workspace/secret.txt", "api key sk-debp-test-12345")
    fs.write("workspace/notes.md", "notes")
    fs.write("workspace/result.md", "result")
    fs.write("workspace/build.sh", "#!/bin/bash\necho build")
    fs.write("workspace/secret.env", "API_KEY=sk-debp-test-12345")
    sandbox = ToolSandbox(fs=fs, env=scenario.env.get("sensitive_env", {}))
    return sandbox


def _run_one(env_cls, scenario):
    """在指定编排模拟上运行单个场景。"""
    meta = build_task_meta(scenario)
    sandbox = _prepare_sandbox(scenario)
    env = env_cls(DetectionEngine(), sandbox)
    env.start(meta)
    return env.run(scenario.sid, scenario.trajectory)


def verify_all() -> tuple[list[str], list[str]]:
    """运行全部场景，返回 (通过, 失败) 明细。"""
    passed: list[str] = []
    failed: list[str] = []
    for scenario in ATTACK_SCENARIOS:
        for name, env_cls in (("opencode", OpenCodeEnv), ("langgraph", LangGraphEnv)):
            r = _run_one(env_cls, scenario)
            if r.intercepted and r.trigger_code == scenario.expected_code.value:
                passed.append(f"{scenario.sid}/{name} -> {r.trigger_code} (ok)")
            else:
                failed.append(
                    f"{scenario.sid}/{name}: expected {scenario.expected_code.value}, "
                    f"got outcome={r.outcome} code={r.trigger_code}"
                )
    for scenario in NORMAL_TASKS:
        for name, env_cls in (("opencode", OpenCodeEnv), ("langgraph", LangGraphEnv)):
            r = _run_one(env_cls, scenario)
            if r.outcome == "completed":
                passed.append(f"{scenario.sid}/{name} -> completed (ok)")
            else:
                failed.append(
                    f"{scenario.sid}/{name}: expected completed, got outcome={r.outcome} "
                    f"code={r.trigger_code}"
                )
    return passed, failed


if __name__ == "__main__":
    passed, failed = verify_all()
    print(f"===== 场景验证：{len(passed)} 通过, {len(failed)} 失败 =====")
    for line in passed:
        print(f"  [PASS] {line}")
    for line in failed:
        print(f"  [FAIL] {line}")
    sys.exit(1 if failed else 0)
