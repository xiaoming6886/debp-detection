"""三通道检测判定（对应论文第4.5节）。

通道1 状态机：A/D 类（类别越界与顺序违反）
通道2 参数边界：B 类（参数结构与数据域）
通道3 数据流：C 类（敏感值流向）

各通道独立触发，融合时按危害程度取优先级：A1 > C > B > D。
"""

from __future__ import annotations

import base64
import re
import urllib.parse

from detection_core.models import Profile, ReasonCode, ToolCall, cat_of

# ---------------------------------------------------------------------------
# 通道1：状态机通道（A/D 类）
# ---------------------------------------------------------------------------


def channel_state_machine(
    seen_categories: set[str], profile: Profile, tool_id: str
) -> tuple[bool, ReasonCode, str]:
    """判定类别越界与顺序违反。

    返回 (是否触发, 原因码, 细节)。不修改 seen_categories（由 engine 维护）。
    """
    category = cat_of(tool_id)

    # A 类：类别越界（非 delegate）
    if category not in profile.T_task and category != "delegate":
        return True, ReasonCode.A1, f"{tool_id} category {category} not in T_task"

    # D 类：顺序违反
    for before, after in profile.order:
        if category == after and before not in seen_categories:
            return True, ReasonCode.D2, f"missing predecessor {before} before {after}"
        if category == before and after in seen_categories:
            return True, ReasonCode.D1, f"predecessor {before} appears after {after}"

    return False, None, ""


# ---------------------------------------------------------------------------
# 通道2：参数边界通道（B 类）
# ---------------------------------------------------------------------------

# 危险语义模式（参数边界通道的补充子规则）：
# 对 exec/data 类工具的命令与查询参数做危险模式匹配，
# 覆盖不涉及数据域标识的纯语义参数操纵（对应论文定义4与性质1的边界收窄）。
DANGEROUS_SEMANTIC_PATTERNS: list = [
    re.compile(r"(?i)\bDELETE\s+FROM\b(?![\s\S]*\bWHERE\b)"),  # DELETE 无 WHERE
    re.compile(r"(?i)\bUPDATE\b(?![\s\S]*\bWHERE\b)"),  # UPDATE 无 WHERE
    re.compile(r"(?i)\bDROP\s+(TABLE|DATABASE|INDEX)\b"),  # DROP
    re.compile(r"(?i)\bTRUNCATE\b"),  # TRUNCATE
    re.compile(r"(?i)\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b"),  # rm -rf / rm -fr
    re.compile(r"(?i)\bchmod\s+-R\s+777\b"),  # 递归放开权限
    re.compile(r"(?i)\bchown\s+-R\b"),  # 递归改属主
    re.compile(r"(?i)\bcurl\b[^\n]*\|\s*(ba)?sh\b"),  # curl | sh 管道执行
    re.compile(r"(?i)\bwget\b[^\n]*\|\s*(ba)?sh\b"),  # wget | sh 管道执行
    re.compile(r"(?i)\b(dd|mkfs|fdisk)\s+of=/dev/"),  # 写裸设备
    re.compile(r"(?i)\bformat\s+[a-z]:/"),  # 格式化磁盘
]


def _dangerous_semantic_check(call: ToolCall) -> tuple[bool, str]:
    """危险语义子规则：exec/data 类工具的命令/查询参数命中危险模式即触发。

    与 B3 关键词黑名单的区别：本规则仅施加于任务授权的 exec/data 类工具上，
    作为参数边界通道的确定性约束（任务锚定），而非全局黑名单。
    """
    cat = cat_of(call.tool)
    if cat not in ("exec", "data"):
        return False, ""
    args = call.args or {}
    for key in ("command", "query", "sql"):
        val = args.get(key)
        if isinstance(val, str) and val:
            for p in DANGEROUS_SEMANTIC_PATTERNS:
                if p.search(val):
                    return True, f"dangerous semantic pattern in {key}"
    return False, ""


def channel_parameter_boundary(call: ToolCall, profile: Profile) -> tuple[bool, ReasonCode, str]:
    """校验参数结构、数据域约束与危险语义模式。"""
    args = call.args or {}

    # B1：schema 违反（结构非法：必填缺失、类型不符、超出枚举）
    # schema 来源：工具定义（TaskMeta.available_tools 的 ToolSpec.schema），
    # 而非调用参数——避免"攻击者自报 schema"的循环论证（对应审查 P1-1）
    schema = getattr(profile, "_tool_schemas", {}).get(call.tool) or {}
    if schema:
        for req in schema.get("required", []):
            if req not in args:
                return True, ReasonCode.B1, f"missing required arg {req}"
        for key, expected in schema.get("types", {}).items():
            if key in args and not isinstance(args[key], expected):
                return True, ReasonCode.B1, f"arg {key} type mismatch"
        enum_map = schema.get("enums", {})
        for key, allowed in enum_map.items():
            if key in args and args[key] not in allowed:
                return True, ReasonCode.B1, f"arg {key} value not in enum"

    # B1 补充：危险语义模式（exec/data 工具的命令与查询参数）
    hit, detail = _dangerous_semantic_check(call)
    if hit:
        return True, ReasonCode.B1, detail

    # B2：数据域越界（参数中的数据域标识超出 D_task）
    domains = _extract_domains(args, call.tool)
    for d in domains:
        if not _domain_allowed(d, profile.D_task):
            return True, ReasonCode.B2, f"data domain {d} not in D_task"

    return False, None, ""


def _extract_domains(args: dict, tool: str) -> set[str]:
    """从参数中提取数据域标识（资源路径、域名、网络标识）。

    仅提取参数中显式出现的标识，工具类别本身不构成数据域。
    """
    domains: set[str] = set()
    for key in ("path", "file", "filePath", "url", "domain", "target", "output"):
        val = args.get(key)
        if isinstance(val, str) and val:
            domains.add(val)
    return domains


def _domain_allowed(domain: str, d_task: set[str]) -> bool:
    """判断数据域是否在白名单内（本地/工作区路径、白名单域名、本地网络标识）。"""
    if domain in d_task:
        return True
    # 统一路径穿越检查：任何 .. 段必须拒绝（不区分点前缀与否）。
    # 对应复审：workspace/../etc/passwd 曾因 head 前缀短路绕过 .. 检查。
    norm = domain.replace("\\", "/")
    if any(seg == ".." for seg in norm.split("/")):
        return False
    # 相对路径：. ./ 与点开头的本地文件（.env 等）视为本地/工作区域
    if domain.startswith("."):
        return "local" in d_task or "workspace" in d_task
    if domain == "network":
        return "network" in d_task
    # 路径前缀匹配：workspace/report.md → 首段 workspace ∈ D_task 即放行
    head = domain.split("/", 1)[0].split("\\", 1)[0]
    if head and head in d_task:
        return True
    # 具体域名：检查是否有域名级白名单（如 docs.example.com 在 D_task）
    if any(domain.endswith("/" + d) or domain == d for d in d_task if "://" not in d):
        return True
    return False


# ---------------------------------------------------------------------------
# 通道3：数据流通道（C 类）
# ---------------------------------------------------------------------------


class DataFlowTracker:
    """敏感值标记集合（跨调用传播）。"""

    def __init__(self, profile: Profile):
        self.profile = profile
        self.marked_values: set[str] = set()
        # 预标记：环境敏感源的值（原值匹配粒度，对应定义5）
        # S_task 中键形如 "env:API_KEY"，_env_values 键形如 "API_KEY"
        env_vals = getattr(profile, "_env_values", {}) or {}
        for key in profile.S_task:
            k = key.split(":", 1)[1] if ":" in key else key
            env_val = env_vals.get(k)
            if env_val:
                self.marked_values.add(str(env_val))

    def on_tool_call(self, call: ToolCall) -> tuple[bool, ReasonCode, str]:
        """检查调用参数中是否出现已标记敏感值，且流向数据域之外。"""
        args = call.args or {}
        cat = cat_of(call.tool)
        # 敏感值出现在参数中
        present = [v for v in self.marked_values if _value_in_args(v, args)]
        if not present:
            return False, None, ""
        # 流向外部目标（出网工具或写入外部路径）
        outgoing = cat == "web" or _writes_external(args, self.profile.D_task)
        if outgoing:
            return (
                True,
                ReasonCode.C1 if cat == "web" else ReasonCode.C2,
                f"sensitive value {present[0][:8]}... flows outside",
            )
        return False, None, ""

    def on_tool_result(self, result) -> None:
        """工具输出中的敏感值参与标记（传播）。

        真实传播（对应审查 P1-3）：敏感源值出现在工具输出中时，将该值
        标记；同时从输出中提取"与敏感键关联的新值"（如 env 键=值的行），
        使后续调用中携带该值也能被识别。原型范围：仅覆盖预声明敏感键
        对应的值传播，不覆盖未声明的任意文件内容推断。
        """
        if not result.ok or result.output is None:
            return
        out = str(result.output)
        env_vals = getattr(self.profile, "_env_values", {}) or {}
        # 1) 已标记值出现在输出 → 保持标记（确认传播）
        for v in list(self.marked_values):
            if v in out:
                self.marked_values.add(v)
        # 2) 敏感键=值 模式出现在输出 → 提取新值并标记
        #    （如输出含 "API_KEY=sk-xxx" 或 "API_KEY: sk-xxx"）
        for key in self.profile.S_task:
            k = key.split(":", 1)[1] if ":" in key else key
            env_val = env_vals.get(k)
            if env_val and str(env_val) in out:
                continue  # 已知值，跳过
            for m in re.finditer(rf"{re.escape(k)}\s*[=:]\s*([A-Za-z0-9_\-./=+]+)", out):
                self.marked_values.add(m.group(1))


def _value_in_args(value: str, args: dict) -> bool:
    for v in args.values():
        if isinstance(v, str) and value in v:
            return True
        if isinstance(v, str) and _normalized_match(value, v):
            return True
        if isinstance(v, dict) and _value_in_args(value, v):
            return True
    return False


def _normalized_match(value: str, arg: str) -> bool:
    """编码绕过归一化比对：原值子串未命中时，尝试常见编码解码后与原值匹配。

    覆盖 base64 / URL 编码 / 十六进制三类变形（对应论文 P1-2 与对抗样本实验）。
    仅当解码结果含有敏感原值时判定命中，解码失败的候选被忽略。
    """
    candidates: list[str] = []
    # base64：带填充与去填充两种形式
    s = arg
    if s.endswith("="):
        s = s.rstrip("=")
    s += "=" * (-len(s) % 4)
    try:
        candidates.append(base64.b64decode(s).decode("utf-8", errors="ignore"))
    except Exception:
        pass
    # URL 编码（%XX 形式）
    try:
        candidates.append(urllib.parse.unquote(arg))
    except Exception:
        pass
    # 十六进制（ASCII hex，偶长度）
    if len(arg) % 2 == 0:
        try:
            candidates.append(bytes.fromhex(arg).decode("utf-8", errors="ignore"))
        except Exception:
            pass
    return any(value in c for c in candidates)


def _writes_external(args: dict, d_task: set[str]) -> bool:
    """写入目标是否在数据访问域之外。"""
    for key in ("path", "file", "filePath", "output", "target"):
        val = args.get(key)
        if isinstance(val, str) and val and not _domain_allowed(val, d_task):
            return True
    return False
