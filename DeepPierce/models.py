"""核心数据模型 — 精简版，只保留 Agent 需要的数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class HttpRecord:
    """一条 HTTP 请求-响应记录。"""
    id: str
    method: str
    url: str
    host: str
    path: str
    request_headers: dict = field(default_factory=dict)
    request_body: str | None = None
    response_status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str | None = None
    source: str = ""          # "crawler" / "burp" / "agent"
    timestamp: str = ""

    def brief(self) -> str:
        return f"{self.method} {self.path} → {self.response_status}"


@dataclass
class EndpointInfo:
    """Agent 理解后的接口信息。"""
    id: str
    method: str
    path: str
    host: str
    params: list[ParamInfo] = field(default_factory=list)
    purpose: str = ""          # AI 推断的业务功能
    resource: str = ""         # 操作什么资源 (user/order/file...)
    auth_required: bool = False
    response_summary: str = ""
    risk_score: float = 0.0
    sample_request: HttpRecord | None = None


@dataclass
class ParamInfo:
    """Agent 对参数的理解。"""
    name: str
    location: str             # query/body/header/path
    sample_value: str = ""
    type_guess: str = ""      # integer/uuid/email/jwt/md5/timestamp/string
    role: str = ""            # user_id/token/signature/callback/...
    is_id: bool = False
    is_predictable: bool = False
    is_security_critical: bool = False
    attack_surfaces: list[str] = field(default_factory=list)


@dataclass
class Finding:
    """一条漏洞发现。"""
    id: str
    title: str
    attack_type: str         # idor/sqli/xss/ssrf/...
    severity: str            # critical/high/medium/low/info
    confidence: float        # 0.0-1.0
    endpoint: str = ""       # 涉及的接口路径
    description: str = ""    # AI 写的漏洞描述
    poc: str = ""           # 复现步骤
    evidence_request: dict | None = None
    evidence_response: dict | None = None
    timestamp: str = ""


@dataclass
class AgentThought:
    """Agent 的一条思考记录，展示在 GUI 里。"""
    type: str                # "thinking" / "action" / "finding" / "error" / "done"
    content: str
    detail: Any = None
    endpoint_path: str = ""  # 关联的接口路径，用于按接口筛选思考
    timestamp: str = ""
