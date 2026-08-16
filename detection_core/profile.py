"""期望行为轮廓推导（R1-R4 规则，对应论文第4.2节）。

规则驱动、确定性推导：同一任务描述在任何时刻推导结果一致，
每条轮廓分量均可回溯至对应的任务特征（derivation_trace）。
"""

from __future__ import annotations

from detection_core.models import Profile, TaskMeta

# ---------------------------------------------------------------------------
# 规则库（R1-R4）
# ---------------------------------------------------------------------------

# R1: 动作-资源特征 → 工具类别（关键词到类别的映射）
R1_RULES: list[tuple[set[str], set[str]]] = [
    ({"编写", "修改", "生成", "编辑", "创建", "文件"}, {"edit", "read"}),
    ({"分析", "阅读", "检查", "查看", "总结", "审阅"}, {"read"}),
    # "查询" 单独映射 read：网络查询由"搜索/网络/网页/信息/调研"触发，
    # 避免"查询数据库"被同义词污染授予 web 权限（对应审查：E2 标注独立性）
    ({"查询"}, {"read"}),
    ({"搜索", "网络", "网页", "信息", "调研"}, {"web", "read"}),
    ({"上传", "发布", "外发"}, {"web"}),
    ({"执行", "运行", "测试", "命令", "部署"}, {"exec", "read"}),
    ({"数据库", "sql", "表"}, {"data"}),
    ({"委派", "并行", "子任务", "agent"}, {"delegate"}),
]

# R2: 资源位置特征 → 数据访问域
R2_LOCAL_KEYWORDS = {"本地", "项目", "工作区", "workspace", "文件"}

# R3: 环境敏感字段名启发式
R3_SENSITIVE_SUBSTR = ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "PRIVATE")

# R4: 阶段词 → 顺序约束（仅当任务描述显式表达"先X后Y"阶段次序时生成）
# after 关键词使用具体动作词而非通用连接词"然后/再/之后"，避免跨规则交叉
# 命中导致过度生成（对应审查 P2-2）
R4_PHASE_RULES: list[tuple[set[str], str, set[str], str]] = [
    (
        {"先分析", "首先分析", "先阅读", "先读"},
        "read",
        {"修改", "整理", "编辑", "写入", "生成"},
        "edit",
    ),
    (
        {"先分析", "首先分析", "先阅读", "先读"},
        "read",
        {"执行", "运行", "部署", "测试"},
        "exec",
    ),
    ({"先搜索", "首先搜索", "先查"}, "web", {"总结", "整理", "分析"}, "read"),
]


def _match_r4(task_desc: str) -> list[tuple[str, str]]:
    order: list[tuple[str, str]] = []
    for before_kw, before_cat, after_kw, after_cat in R4_PHASE_RULES:
        before_pos = -1
        for kw in before_kw:
            p = task_desc.find(kw)
            if p >= 0:
                before_pos = p if before_pos < 0 else min(before_pos, p)
        after_pos = -1
        for kw in after_kw:
            p = task_desc.find(kw)
            if p >= 0:
                after_pos = p if after_pos < 0 else min(after_pos, p)
        if before_pos >= 0 and after_pos > before_pos:
            order.append((before_cat, after_cat))
    return order


def _match_r1(task_desc: str) -> set[str]:
    matched: set[str] = set()
    for keywords, categories in R1_RULES:
        if any(k in task_desc for k in keywords):
            matched |= categories
    return matched


def _match_r2(task_desc: str, environment: dict) -> set[str]:
    domains: set[str] = set()
    # 环境提示优先：工作区/域名白名单（工作区属于本地域，语义上同步授予 local）
    if environment.get("workspace"):
        domains.add("workspace")
        domains.add("local")
    if environment.get("domains"):
        domains.update(environment["domains"])
    # 任务描述中的本地资源关键词
    if any(k in task_desc for k in R2_LOCAL_KEYWORDS):
        domains.add("local")
        domains.add("workspace")
    return domains


def _match_r3(environment: dict) -> set[str]:
    sensitive: set[str] = set()
    for key in environment.get("sensitive_env", {}):
        if any(s in key.upper() for s in R3_SENSITIVE_SUBSTR):
            sensitive.add(f"env:{key}")
    return sensitive


# ---------------------------------------------------------------------------
# 主推导函数
# ---------------------------------------------------------------------------


def derive_profile(task_meta: TaskMeta) -> Profile:
    """从任务元数据在线推导 Profile(T)。纯函数，无历史数据依赖。"""
    desc = task_meta.task_desc
    trace: list[str] = []

    # R1: 工具许可（保守：未命中类别不加入）
    t_task = _match_r1(desc)
    trace.append(f"R1: {sorted(t_task)} <- 动作资源关键词")
    if not t_task:
        t_task = {"read"}  # 保守默认：仅只读
        trace.append("R1: 未命中 -> 保守默认 {read}")

    # R2: 数据访问域（保守：默认仅本地）
    d_task = _match_r2(desc, task_meta.environment)
    trace.append(f"R2: {sorted(d_task)} <- 资源位置")
    if not d_task:
        d_task = {"local"}
        trace.append("R2: 未命中 -> 保守默认 {local}")

    # R3: 敏感源识别（从环境）
    s_task = _match_r3(task_meta.environment)
    trace.append(f"R3: {sorted(s_task)} <- 环境敏感字段")

    # R4: 顺序约束
    order = _match_r4(desc)
    trace.append(f"R4: {order} <- 阶段词")

    return Profile(
        task_id=task_meta.task_id,
        T_task=t_task,
        D_task=d_task,
        S_task=s_task,
        order=order,
        derivation_trace=trace,
    )
