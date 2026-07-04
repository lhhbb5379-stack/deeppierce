"""配置管理 — YAML 配置文件 + 环境变量。"""

from __future__ import annotations

import os
from pathlib import Path

import yaml


class Config:
    """DeepPierce 全局配置。

    加载优先级: YAML 配置文件 > 环境变量
    """

    DEFAULT_CONFIG_PATH = Path.home() / ".deeppierce" / "config.yml"

    def __init__(
        self,
        api_key: str = "",
        api_base_url: str = "",
        model: str = "claude-sonnet-4-6",
        burp_proxy: str = "http://127.0.0.1:8080",
        burp_mcp_url: str = "http://127.0.0.1:9876/sse",
        proxy_enabled: bool = True,
        burp_mcp_enabled: bool = True,
        max_rounds: int = 9999,
        request_timeout: int = 30,
        agent_custom_prompt: str = "",
        custom_api_patterns: str = "",
        custom_secret_rules: str = "",
        **kwargs,
    ):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        self.api_base_url = api_base_url or os.getenv("ANTHROPIC_BASE_URL", "")
        self.model = model or os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
        self.burp_proxy = burp_proxy
        self.burp_mcp_url = burp_mcp_url
        self.proxy_enabled = proxy_enabled
        self.burp_mcp_enabled = burp_mcp_enabled
        self.max_rounds = max_rounds
        self.request_timeout = request_timeout
        self.agent_custom_prompt = agent_custom_prompt or ""
        self.custom_api_patterns = custom_api_patterns or ""
        self.custom_secret_rules = custom_secret_rules or ""
        for k, v in kwargs.items():
            setattr(self, k, v)

    @classmethod
    def load(cls) -> Config:
        """加载配置（YAML 文件 > 环境变量）。"""
        if cls.DEFAULT_CONFIG_PATH.exists():
            try:
                data = yaml.safe_load(cls.DEFAULT_CONFIG_PATH.read_text()) or {}
                return cls(**data)
            except Exception:
                pass
        return cls.from_env()

    @classmethod
    def from_env(cls) -> Config:
        """从 Claude Code 环境变量创建配置。"""
        api_key = os.getenv("ANTHROPIC_AUTH_TOKEN", "") or os.getenv("ANTHROPIC_API_KEY", "")
        base_url = os.getenv("ANTHROPIC_BASE_URL", "")
        model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
        return cls(api_key=api_key, api_base_url=base_url, model=model)

    def save(self):
        """保存到 ~/.DeepPierce/config.yml。"""
        self.DEFAULT_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.DEFAULT_CONFIG_PATH.write_text(yaml.dump({
            "api_key": self.api_key,
            "api_base_url": self.api_base_url,
            "model": self.model,
            "burp_proxy": self.burp_proxy,
            "burp_mcp_url": self.burp_mcp_url,
            "proxy_enabled": self.proxy_enabled,
            "burp_mcp_enabled": self.burp_mcp_enabled,
            "max_rounds": self.max_rounds,
            "request_timeout": self.request_timeout,
            "agent_custom_prompt": self.agent_custom_prompt,
            "custom_api_patterns": self.custom_api_patterns,
            "custom_secret_rules": self.custom_secret_rules,
        }, allow_unicode=True))

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key)

    @property
    def uses_custom_gateway(self) -> bool:
        return bool(self.api_base_url)
