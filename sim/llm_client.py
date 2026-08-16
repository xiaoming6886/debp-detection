"""LLM API 客户端（DeepSeek V4 Pro / Qwen3.7-Max，OpenAI 兼容接口）。

仅供实验轨迹生成使用，不参与检测判定。
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

# 后端配置
BACKENDS = {
    "deepseek": {
        "base": "https://api.deepseek.com/v1",
        "key_env": "DEEPSEEK_API_KEY",
        "model": "deepseek-v4-pro",
    },
    "qwen": {
        "base": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "key_env": "DASHSCOPE_API_KEY",
        "model": "qwen3.7-max",
    },
}


class LLMClient:
    """OpenAI 兼容 chat completion 客户端。

    thinking: DeepSeek 推理开关。True=启用推理（reasoning_content），
    False=关闭推理直接输出。实验默认关闭：确定性更高、token 消耗低、
    content 不会被推理内容挤占。
    """

    def __init__(
        self,
        backend: str = "deepseek",
        model: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        thinking: bool = False,
    ):
        if backend not in BACKENDS:
            raise ValueError(f"unknown backend: {backend}")
        cfg = BACKENDS[backend]
        self.base = cfg["base"]
        self.key = os.environ.get(cfg["key_env"], "")
        if not self.key:
            raise RuntimeError(f"missing env {cfg['key_env']}")
        self.model = model or cfg["model"]
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.thinking = thinking

    def chat(
        self, messages: list[dict], temperature: float | None = None, max_tokens: int | None = None
    ) -> str:
        """发送对话，返回助手文本。"""
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
            "max_tokens": self.max_tokens if max_tokens is None else max_tokens,
        }
        if not self.thinking:
            # DeepSeek：显式关闭推理，避免推理内容挤占 content（max_tokens 共享预算）
            payload["thinking"] = {"type": "disabled"}
        req = urllib.request.Request(
            self.base + "/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": "Bearer " + self.key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"].get("content")
            if content is None:
                content = ""  # 推理模型的 content 可能为空（对应审查 P2-5）
            return content
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM HTTP {e.code}: {body[:300]}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise RuntimeError(f"LLM network error: {e}") from e
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            raise RuntimeError(f"LLM response parse error: {e}") from e

    def complete(
        self, prompt: str, temperature: float | None = None, max_tokens: int | None = None
    ) -> str:
        """单轮补全。"""
        return self.chat(
            [{"role": "user", "content": prompt}], temperature=temperature, max_tokens=max_tokens
        )
