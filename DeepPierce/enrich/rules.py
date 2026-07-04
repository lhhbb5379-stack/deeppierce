"""可配置规则引擎 — HaE 风格，支持 NFA 正则 + 作用域 + 格式化输出。

整合 HaE 的核心设计:
- Rule: 规则定义 (12字段，含 name/regex/format/color/scope/engine)
- RuleGroup: 规则分组
- RuleEngine: 编译+执行引擎，支持作用域过滤和结果格式化
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class RuleScope(StrEnum):
    """规则匹配作用域，对标 HaE 的 11 种 scope。"""
    ANY = "any"
    ANY_HEADER = "any_header"
    ANY_BODY = "any_body"
    RESPONSE = "response"
    RESPONSE_LINE = "response_line"
    RESPONSE_HEADER = "response_header"
    RESPONSE_BODY = "response_body"
    REQUEST = "request"
    REQUEST_LINE = "request_line"
    REQUEST_HEADER = "request_header"
    REQUEST_BODY = "request_body"


@dataclass
class Rule:
    """单条规则定义，对标 HaE 的 RuleDefinition。"""
    name: str
    regex: str                          # 主正则
    second_regex: str = ""             # 二次匹配正则 (可选)
    format: str = "{0}"                # 输出格式
    scope: RuleScope = RuleScope.ANY_BODY
    color: str = "red"                 # red/orange/yellow/green/cyan/blue/pink/magenta/gray
    engine: str = "nfa"               # nfa / dfa
    sensitive: bool = False            # 大小写敏感
    enabled: bool = True
    description: str = ""


@dataclass
class RuleGroup:
    """规则分组。"""
    name: str
    rules: list[Rule] = field(default_factory=list)
    enabled: bool = True


@dataclass
class RuleMatch:
    """规则匹配结果。"""
    rule_name: str
    group_name: str
    value: str
    formatted: str       # 格式化后的输出
    scope: RuleScope


class RuleEngine:
    """HaE 风格的规则执行引擎。

    流程:
    1. 根据 scope 提取消息的对应部分 (header/body/request_line/...)
    2. 遍历所有启用的规则，用 NFA (Python re) 引擎匹配
    3. 支持二次正则 (second_regex) 做子匹配
    4. 格式化输出
    """

    def __init__(self):
        self._groups: list[RuleGroup] = []

    def add_group(self, group: RuleGroup):
        self._groups.append(group)

    def add_rule(self, group_name: str, rule: Rule):
        for g in self._groups:
            if g.name == group_name:
                g.rules.append(rule)
                return
        self._groups.append(RuleGroup(name=group_name, rules=[rule]))

    # ── 作用域提取 ──────────────────────────────────────────────

    def _extract_by_scope(
        self,
        scope: RuleScope,
        request: str = "",
        response: str = "",
        req_headers: str = "",
        resp_headers: str = "",
    ) -> str | None:
        """根据 scope 提取对应的文本部分。"""
        if scope == RuleScope.ANY:
            return f"{request}\n{response}"
        elif scope == RuleScope.ANY_HEADER:
            return f"{req_headers}\n{resp_headers}"
        elif scope == RuleScope.ANY_BODY:
            return f"{request}\n{response}"
        elif scope == RuleScope.RESPONSE:
            return response
        elif scope == RuleScope.RESPONSE_LINE:
            return response.split("\n")[0] if response else ""
        elif scope == RuleScope.RESPONSE_HEADER:
            return resp_headers
        elif scope == RuleScope.RESPONSE_BODY:
            return response
        elif scope == RuleScope.REQUEST:
            return request
        elif scope == RuleScope.REQUEST_LINE:
            return request.split("\n")[0] if request else ""
        elif scope == RuleScope.REQUEST_HEADER:
            return req_headers
        elif scope == RuleScope.REQUEST_BODY:
            return request
        return None

    # ── 匹配执行 ──────────────────────────────────────────────

    def match(
        self,
        request: str = "",
        response: str = "",
        req_headers: str = "",
        resp_headers: str = "",
    ) -> list[RuleMatch]:
        """对给定的 HTTP 消息执行所有规则。

        Returns:
            匹配结果列表
        """
        results: list[RuleMatch] = []

        for group in self._groups:
            if not group.enabled:
                continue

            for rule in group.rules:
                if not rule.enabled:
                    continue

                # 提取作用域文本
                text = self._extract_by_scope(
                    rule.scope, request, response, req_headers, resp_headers
                )
                if not text:
                    continue

                # 编译正则
                flags = 0 if rule.sensitive else re.IGNORECASE
                try:
                    compiled = re.compile(rule.regex, flags)
                except re.error:
                    continue

                # 主匹配
                for m in compiled.finditer(text):
                    value = m.group(0)

                    # 二次正则
                    if rule.second_regex:
                        try:
                            second = re.compile(rule.second_regex, flags)
                            sub_match = second.search(value)
                            if sub_match:
                                value = sub_match.group(0) if not sub_match.groups() else sub_match.group(1)
                        except re.error:
                            pass

                    # 格式化
                    try:
                        formatted = rule.format.format(value, *m.groups())
                    except (IndexError, KeyError):
                        formatted = value

                    results.append(RuleMatch(
                        rule_name=rule.name,
                        group_name=group.name,
                        value=value,
                        formatted=formatted,
                        scope=rule.scope,
                    ))

        return results

    # ── 内置规则 (HaE 默认) ─────────────────────────────────────

    @classmethod
    def with_default_rules(cls) -> RuleEngine:
        """创建预装 HaE 默认规则的引擎。"""
        engine = cls()

        # 指纹识别组
        fingerprint = RuleGroup("指纹识别", [
            Rule("Shiro", r'(?i)(rememberMe=|deleteMe)', scope=RuleScope.ANY_HEADER, color="orange",
                description="Apache Shiro 框架"),
            Rule("JWT", r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}',
                scope=RuleScope.ANY_BODY, color="cyan", description="JSON Web Token"),
            Rule("Swagger", r'(?i)(swagger-ui|swaggerUi|swaggerVersion|api-docs)',
                scope=RuleScope.ANY_BODY, color="green", description="Swagger API 文档"),
            Rule("Druid", r'(?i)Druid Stat Index', scope=RuleScope.ANY_BODY, color="yellow",
                description="阿里巴巴 Druid 监控"),
            Rule("调试参数", r'(?i)[&?](debug|test|admin|shell|exec)=\w+',
                scope=RuleScope.ANY, color="red", description="调试/后门参数"),
        ])
        engine.add_group(fingerprint)

        # 敏感信息组
        sensitive = RuleGroup("敏感信息", [
            Rule("云密钥", r'(?i)(AKIA|LTAI|AKID|JDC_)[0-9A-Za-z]{10,}',
                scope=RuleScope.ANY_BODY, color="red", format="云服务密钥: {0}"),
            Rule("邮箱", r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
                scope=RuleScope.ANY_BODY, color="cyan", format="邮箱: {0}"),
            Rule("手机号", r'["\' ](1[3-9]\d{9})["\' ]',
                scope=RuleScope.ANY_BODY, color="yellow", format="手机号: {0}"),
            Rule("身份证", r'[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]',
                scope=RuleScope.ANY_BODY, color="magenta", format="身份证: {0}"),
            Rule("内网 IP", r'(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
                scope=RuleScope.ANY_BODY, color="pink", format="内网IP: {0}"),
            Rule("密码字段", r'(?i)(password|passwd|pwd|secret)\s*[:=]\s*["\']?([^\s"\'&]{3,})["\']?',
                scope=RuleScope.ANY_BODY, color="red",
                second_regex=r'(?i)(password|passwd|pwd|secret)\s*[:=]\s*["\']?([^\s"\'&]{3,})["\']?',
                format="疑似密码: {0}"),
        ])
        engine.add_group(sensitive)

        # 漏洞线索组
        vuln_clues = RuleGroup("漏洞线索", [
            Rule("上传表单", r'(?i)type\s*=\s*["\']file["\']',
                scope=RuleScope.RESPONSE_BODY, color="orange", description="文件上传入口"),
            Rule("URL 参数值", r'[&?]\w+=https?://',
                scope=RuleScope.ANY, color="yellow", description="参数值为 URL (SSRF 线索)"),
            Rule("DoS 参数", r'(?i)[&?](size|page|limit|count|num|start|end)\s*=\s*\d+',
                scope=RuleScope.ANY, color="cyan", description="分页/数量参数 (DoS 线索)"),
            Rule("Java 反序列化", r'(?i)javax\.faces\.ViewState',
                scope=RuleScope.RESPONSE_BODY, color="red", description="Java 反序列化入口"),
            Rule("302 跳转", r'(?i)^HTTP/[\d.]+\s+30[12]\s',
                scope=RuleScope.RESPONSE_LINE, color="blue", description="重定向 (开放重定向线索)"),
        ])
        engine.add_group(vuln_clues)

        # URL/路径提取组 (Linkfinder 风格)
        linkfinder = RuleGroup("路径提取", [
            Rule("JS 中的 URL", r'(?i)(?:"|\')((?:https?://|/)[^\s"\'<>]+(?:\.js|\.json|\.map|\.xml))(?:"|\')',
                scope=RuleScope.ANY_BODY, color="cyan", format="资源路径: {0}"),
            Rule("全量 URL", r'(?i)https?://[^\s"\'<>]{5,}',
                scope=RuleScope.ANY_BODY, color="green", format="URL: {0}"),
        ])
        engine.add_group(linkfinder)

        return engine
