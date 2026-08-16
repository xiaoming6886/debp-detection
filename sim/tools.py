"""工具沙箱（内存文件系统 + 受控工具实现）。

安全设计：所有工具在内存中执行，不触碰真实文件系统、命令执行或网络。
read/edit 操作内存文件；bash 返回预设输出；websearch 返回预置结果；
env 读取模拟环境变量。
"""

from __future__ import annotations

import re


class MemoryFileSystem:
    """内存文件系统（模拟工作区）。"""

    def __init__(self):
        self.files: dict[str, str] = {}

    def write(self, path: str, content: str) -> None:
        self.files[path] = content

    def read(self, path: str) -> str:
        if path in self.files:
            return self.files[path]
        raise FileNotFoundError(path)

    def exists(self, path: str) -> bool:
        return path in self.files


class ToolSandbox:
    """受控工具实现。所有工具返回 (ok, output)。"""

    def __init__(
        self,
        fs: MemoryFileSystem | None = None,
        env: dict | None = None,
        web_results: dict | None = None,
    ):
        self.fs = fs or MemoryFileSystem()
        # 注意：命名为 _env 而非 env，避免遮蔽同名 env() 方法（对应审查 P1-4）
        self._env = env or {}
        self.web_results = web_results or {}

    # ------------------------------------------------------------------
    # 工具实现
    # ------------------------------------------------------------------

    def read(self, args: dict) -> tuple[bool, str]:
        path = args.get("path", "")
        try:
            return True, self.fs.read(path)
        except FileNotFoundError:
            return False, f"error: file not found: {path}"

    def list(self, args: dict) -> tuple[bool, str]:
        prefix = args.get("path", "")
        names = [p for p in self.fs.files if p.startswith(prefix)]
        return True, "\n".join(sorted(names)) or "(empty)"

    def edit(self, args: dict) -> tuple[bool, str]:
        path = args.get("path", "")
        content = args.get("content", "")
        self.fs.write(path, content)
        return True, f"written {len(content)} chars to {path}"

    def write(self, args: dict) -> tuple[bool, str]:
        return self.edit(args)

    def bash(self, args: dict) -> tuple[bool, str]:
        cmd = args.get("command", "")
        # 受控：只返回预设输出，不执行真实命令
        if "echo" in cmd:
            m = re.search(r"echo\s+(.+)", cmd)
            return True, m.group(1) if m else "ok"
        return True, f"(sandbox) command accepted: {cmd[:40]}"

    def websearch(self, args: dict) -> tuple[bool, str]:
        query = args.get("query", "")
        if query in self.web_results:
            return True, self.web_results[query]
        return True, f"(websearch sandbox) no result for: {query}"

    def fetch(self, args: dict) -> tuple[bool, str]:
        url = args.get("url", "")
        return True, f"(fetch sandbox) content of {url}"

    def env(self, args: dict) -> tuple[bool, str]:
        key = args.get("key", "")
        val = self._env.get(key)
        return (True, val) if val is not None else (False, f"env {key} not set")

    def task(self, args: dict) -> tuple[bool, str]:
        # 委派：返回子任务说明（沙箱内不实际创建子代理，由编排层处理）
        return True, f"(delegate sandbox) subtask: {args.get('description', '')}"

    def db(self, args: dict) -> tuple[bool, str]:
        query = args.get("query", "")
        if re.search(r"\b(DELETE|DROP)\b", query, re.IGNORECASE):
            return True, f"(db sandbox) executed: {query}"
        return True, f"(db sandbox) result for: {query}"

    # ------------------------------------------------------------------
    # 统一调度
    # ------------------------------------------------------------------

    def call(self, tool: str, args: dict) -> tuple[bool, str]:
        fn = getattr(self, tool, None)
        if fn is None:
            return False, f"unknown tool: {tool}"
        return fn(args)


# 工具 schema 定义（供参数边界通道 B1 校验）
TOOL_SCHEMAS: dict[str, dict] = {
    "read": {"required": ["path"], "types": {"path": str}},
    "list": {"required": ["path"], "types": {"path": str}},
    "edit": {"required": ["path"], "types": {"path": str, "content": str}},
    "write": {"required": ["path"], "types": {"path": str, "content": str}},
    "bash": {"required": ["command"], "types": {"command": str}},
    "websearch": {"required": ["query"], "types": {"query": str}},
    "fetch": {"required": ["url"], "types": {"url": str}},
    "env": {"required": ["key"], "types": {"key": str}},
    "task": {"required": ["description"], "types": {"description": str}},
    "db": {"required": ["query"], "types": {"query": str}},
}
