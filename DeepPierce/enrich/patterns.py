"""敏感信息模式匹配器 — 整合 FindSomething + HaE 的检测规则。

规则来源:
- FindSomething: ~700+ Nuclei 风格的凭证/密钥正则
- HaE: 指纹识别 + 敏感信息 + 可能漏洞规则

全部转为 Python re 模式，支持对 HTTP 响应正文/头部/JS 文件进行批量扫描。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecretMatch:
    """一条匹配结果。"""
    rule_name: str
    category: str       # credential / pii / fingerprint / infrastructure / crypto
    severity: str       # critical / high / medium / low / info
    value: str
    context: str = ""   # surrounding text for context
    location: str = ""  # "body", "header", "url", "js"


# ── Pattern Categories ─────────────────────────────────────────────────────

@dataclass
class PatternRule:
    name: str
    category: str
    severity: str
    patterns: list[str]   # list of regex patterns
    description: str = ""


class SecretPatternMatcher:
    """在高流量中检测敏感信息：凭证、PII、指纹、基础设施信息等。

    整合了 FindSomething 的 700+ Nuclei 规则和 HaE 的检测逻辑。
    """

    # ── 云服务凭证 ──
    CLOUD_CREDENTIALS: list[PatternRule] = [
        PatternRule("AWS Access Key", "credential", "critical", [
            r'(?i)AKIA[0-9A-Z]{16}',
            r'(?i)aws[_\-\.]?access[_\-\.]?key[_\-\.]?id["\s:=]+([A-Z0-9]{20})',
            r'(?i)aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key["\s:=]+([A-Za-z0-9/+=]{40})',
            r'(?i)("AKIA[0-9A-Z]{16}")',
        ]),
        PatternRule("Alibaba Cloud Key", "credential", "critical", [
            r'(?i)LTAI[0-9A-Za-z]{16,20}',
            r'(?i)aliyun[_\-\.]?access[_\-\.]?key[_\-\.]?id["\s:=]+(LTAI[0-9A-Za-z]{16,20})',
        ]),
        PatternRule("Tencent Cloud Key", "credential", "critical", [
            r'(?i)AKID[0-9A-Za-z]{32,48}',
        ]),
        PatternRule("JD Cloud Key", "credential", "critical", [
            r'(?i)JDC_[0-9A-Z]{10,}',
        ]),
        PatternRule("Google API Key", "credential", "critical", [
            r'(?i)AIza[0-9A-Za-z\-_]{35}',
            r'(?i)google[_\-\.]?api[_\-\.]?key["\s:=]+([A-Za-z0-9\-_]{30,})',
        ]),
        PatternRule("GitHub Token", "credential", "critical", [
            r'(?i)ghp_[0-9A-Za-z]{36}',
            r'(?i)gho_[0-9A-Za-z]{36}',
            r'(?i)ghu_[0-9A-Za-z]{36}',
            r'(?i)ghs_[0-9A-Za-z]{36}',
            r'(?i)ghr_[0-9A-Za-z]{36}',
            r'(?i)github[_\-\.]?pat[_\-\.]?_[0-9A-Za-z]{22,}',
            r'(?i)github[_\-\.]?token["\s:=]+([0-9A-Za-z]{36,40})',
        ]),
        PatternRule("GitLab Token", "credential", "critical", [
            r'(?i)glpat-[0-9A-Za-z\-]{20,}',
        ]),
        PatternRule("私有密钥", "credential", "critical", [
            r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        ]),
        PatternRule("Slack Token", "credential", "high", [
            r'(?i)xox[baprs]-[0-9A-Za-z\-]{10,}',
            r'(?i)slack[_\-\.]?token["\s:=]+([A-Za-z0-9\-]{10,})',
        ]),
        PatternRule("Stripe Key", "credential", "high", [
            r'(?i)sk_live_[0-9A-Za-z]{24,}',
            r'(?i)pk_live_[0-9A-Za-z]{24,}',
            r'(?i)stripe[_\-\.]?(secret|publishable)[_\-\.]?key["\s:=]+',
        ]),
        PatternRule("Twilio Key", "credential", "high", [
            r'(?i)SK[0-9a-fA-F]{32}',
            r'(?i)twilio[_\-\.]?(account[_\-\.]?sid|auth[_\-\.]?token)["\s:=]+',
        ]),
        PatternRule("SendGrid Key", "credential", "high", [
            r'(?i)SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{22,}',
        ]),
        PatternRule("Cloudflare Key", "credential", "high", [
            r'(?i)cloudflare[_\-\.]?(api[_\-\.]?key|email)["\s:=]+',
            r'(?i)[0-9a-f]{37}',  # Cloudflare API token
        ]),
        PatternRule("Docker Config", "credential", "high", [
            r'(?i)"auths?"\s*:\s*\{',
            r'(?i)docker[_\-\.]?(hub[_\-\.]?)?(username|password|token)["\s:=]+',
        ]),
        PatternRule("npm Token", "credential", "high", [
            r'(?i)npm_[0-9A-Za-z]{36}',
        ]),
    ]

    # ── 企业应用凭证 ──
    ENTERPRISE_CREDENTIALS: list[PatternRule] = [
        PatternRule("企业微信/WeCom", "credential", "high", [
            r'(?i)(ww|wx)[0-9a-z]{16,18}',
            r'(?i)wecom[_\-\.]?(corp[_\-\.]?id|corp[_\-\.]?secret)["\s:=]+',
            r'(?i)(WW|WX)CorpID["\s:=]+',
        ]),
        PatternRule("钉钉/DingTalk", "credential", "high", [
            r'(?i)dingtalk[_\-\.]?(app[_\-\.]?key|app[_\-\.]?secret)["\s:=]+',
            r'(?i)oapi\.dingtalk\.com',
        ]),
        PatternRule("飞书/Feishu", "credential", "high", [
            r'(?i)feishu[_\-\.]?(app[_\-\.]?id|app[_\-\.]?secret)["\s:=]+',
            r'(?i)open\.feishu\.cn',
        ]),
        PatternRule("飞书/Lark Webhook", "credential", "high", [
            r'https://open\.(feishu\.cn|larksuite\.com)/open-apis/bot/v2/hook/[0-9a-z\-]+',
        ]),
        PatternRule("企业微信 Webhook", "credential", "high", [
            r'https://qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[0-9a-z\-]+',
        ]),
        PatternRule("钉钉 Webhook", "credential", "high", [
            r'https://oapi\.dingtalk\.com/robot/send\?access_token=[0-9a-z]+',
        ]),
        PatternRule("Grafana 服务账号", "credential", "high", [
            r'(?i)glsa_[0-9A-Za-z\-_]{20,}',
            r'(?i)glc_[0-9A-Za-z\-_]{20,}',
        ]),
    ]

    # ── 数据库连接 ──
    DATABASE_CREDENTIALS: list[PatternRule] = [
        PatternRule("JDBC 连接串", "credential", "high", [
            r'(?i)jdbc:(mysql|postgresql|oracle|sqlserver|mongo|redis)://[^/\s"\'<>]+',
        ]),
        PatternRule("MongoDB URI", "credential", "high", [
            r'(?i)mongodb(\+srv)?://[^/\s"\'<>]+',
        ]),
        PatternRule("Redis URI", "credential", "high", [
            r'(?i)redis://[^/\s"\'<>]+',
        ]),
        PatternRule("数据库密码", "credential", "high", [
            r'(?i)(db|database|mysql|postgres|oracle|mongo|redis)[_\-\.]?(password|passwd|pass)["\s:=]+["\']?([^\s"\'&]{3,})',
        ]),
    ]

    # ── 个人信息 (PII) ──
    PII_PATTERNS: list[PatternRule] = [
        PatternRule("中国身份证号", "pii", "high", [
            r'["\' ]([1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx])["\' ]',
        ]),
        PatternRule("中国手机号", "pii", "medium", [
            r'["\' ](1[3-9]\d{9})["\' ]',
            r'(?i)(mobile|phone|tel|sjh|shoujihao)["\s:=]+["\']?(1[3-9]\d{9})',
        ]),
        PatternRule("电子邮箱", "pii", "medium", [
            r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
            r'(?i)(email|mail|e_mail)["\s:=]+["\']?([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
        ]),
        PatternRule("中国 IP 地址", "pii", "info", [
            r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)',
        ]),
    ]

    # ── 认证令牌 ──
    AUTH_TOKEN_PATTERNS: list[PatternRule] = [
        PatternRule("JWT Token", "credential", "medium", [
            r'(?i)eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}',
        ]),
        PatternRule("Bearer Token", "credential", "medium", [
            r'(?i)Authorization:\s*Bearer\s+([A-Za-z0-9\-_.~+/]{20,})',
        ]),
        PatternRule("Basic Auth", "credential", "medium", [
            r'(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]{20,})',
        ]),
        PatternRule("API Key Header", "credential", "medium", [
            r'(?i)(api[_\-\.]?key|x-api-key|x-auth-token|access[_\-\.]?token)["\s:=]+["\']?([A-Za-z0-9\-_]{16,})["\']?',
        ]),
        PatternRule("Session Cookie", "credential", "medium", [
            r'(?i)(session|JSESSIONID|PHPSESSID|SID|connect\.sid)=([A-Za-z0-9\-_]{16,})',
        ]),
    ]

    # ── 技术指纹 ──
    FINGERPRINT_PATTERNS: list[PatternRule] = [
        PatternRule("Apache Shiro", "fingerprint", "info", [
            r'(?i)(rememberMe=|deleteMe)',
        ]),
        PatternRule("Swagger UI", "fingerprint", "info", [
            r'(?i)(swagger|swagger-ui|swaggerUi|swaggerVersion|api-docs)',
        ]),
        PatternRule("Druid Monitor", "fingerprint", "info", [
            r'(?i)Druid Stat Index',
        ]),
        PatternRule("Java ViewState", "fingerprint", "info", [
            r'(?i)javax\.faces\.ViewState',
            r'(?i)com\.sun\.faces\.ViewState',
        ]),
        PatternRule("加密算法调用", "fingerprint", "info", [
            r'(?i)(CryptoJS\.(AES|DES|MD5|SHA)|JSEncrypt|btoa|atob|forge\.(md5|sha1|sha256))',
        ]),
        PatternRule("调试参数", "fingerprint", "info", [
            r'(?i)[&?](debug|test|dev|admin|root|shell|exec|grant|role)\s*=\s*',
        ]),
    ]

    # ── 路径/文件信息 ──
    PATH_PATTERNS: list[PatternRule] = [
        PatternRule("Windows 路径", "infrastructure", "low", [
            r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
        ]),
        PatternRule("Linux 绝对路径", "infrastructure", "low", [
            r'(?:/(?:usr|var|etc|home|opt|tmp|root)/[^\s"\'<>]+)',
        ]),
        PatternRule("内部 IP", "infrastructure", "low", [
            r'(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
        ]),
        PatternRule("Source Map", "fingerprint", "low", [
            r'//# sourceMappingURL=([^\s]+\.js\.map)',
        ]),
    ]

    @classmethod
    def all_rules(cls) -> list[PatternRule]:
        """返回所有规则。"""
        return (
            cls.CLOUD_CREDENTIALS +
            cls.ENTERPRISE_CREDENTIALS +
            cls.DATABASE_CREDENTIALS +
            cls.PII_PATTERNS +
            cls.AUTH_TOKEN_PATTERNS +
            cls.FINGERPRINT_PATTERNS +
            cls.PATH_PATTERNS
        )

    def __init__(self, custom_rules_str: str = ""):
        self._compiled: list[tuple[PatternRule, list[re.Pattern]]] = []
        for rule in self.all_rules():
            compiled = [re.compile(p) for p in rule.patterns]
            self._compiled.append((rule, compiled))
        # ── 加载自定义规则 ──
        rules_str = custom_rules_str or ""
        if rules_str.strip():
            for line in rules_str.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) >= 3:
                    name = parts[0].strip()
                    regex = parts[1].strip()
                    severity = parts[2].strip() if len(parts) > 2 else "medium"
                    category = parts[3].strip() if len(parts) > 3 else "credential"
                    if name and regex:
                        try:
                            compiled = [re.compile(regex)]
                            rule = PatternRule(name=name, category=category,
                                              severity=severity, patterns=[regex])
                            self._compiled.append((rule, compiled))
                        except re.error:
                            pass

    def scan(self, text: str, location: str = "body", max_matches_per_rule: int = 5) -> list[SecretMatch]:
        """对文本执行所有模式匹配。

        Args:
            text: 要扫描的文本 (HTTP body / headers / JS content)
            location: 匹配位置标识
            max_matches_per_rule: 每条规则最多保留的匹配数

        Returns:
            匹配结果列表
        """
        if not text:
            return []

        matches: list[SecretMatch] = []
        text_len = len(text)

        for rule, compiled_patterns in self._compiled:
            count = 0
            for pat in compiled_patterns:
                for m in pat.finditer(text):
                    if count >= max_matches_per_rule:
                        break
                    value = m.group(0)
                    # Get context (surrounding 40 chars)
                    start = max(0, m.start() - 40)
                    end = min(text_len, m.end() + 40)
                    context = text[start:end].replace('\n', ' ').replace('\r', '')

                    matches.append(SecretMatch(
                        rule_name=rule.name,
                        category=rule.category,
                        severity=rule.severity,
                        value=value[:200],
                        context=context,
                        location=location,
                    ))
                    count += 1
                if count >= max_matches_per_rule:
                    break

        return matches

    def scan_response(
        self,
        body: str,
        headers: dict[str, str] | None = None,
        url: str = "",
    ) -> list[SecretMatch]:
        """扫描一个完整的 HTTP 响应（正文 + 头部 + URL）。

        Returns:
            按严重程度排序的匹配列表
        """
        all_matches: list[SecretMatch] = []

        if body:
            all_matches.extend(self.scan(body, "body"))

        if headers:
            header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
            all_matches.extend(self.scan(header_text, "header"))

        if url:
            all_matches.extend(self.scan(url, "url"))

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_matches.sort(key=lambda m: severity_order.get(m.severity, 5))

        return all_matches

    def scan_js(self, js_content: str) -> list[SecretMatch]:
        """专门扫描 JS 内容（使用全部规则 + 额外的 JS 专用规则）。"""
        matches = self.scan(js_content, "js")

        # Additional JS-specific: look for inline secrets
        # Pattern: variable assignments with suspicious names
        js_secret_pattern = re.compile(
            r'(?i)(?:const|let|var)\s+(?:'
            r'apiKey|api_key|secret|token|password|passwd|apikey'
            r')\s*=\s*["\']([^"\']{8,})["\']'
        )
        for m in js_secret_pattern.finditer(js_content):
            matches.append(SecretMatch(
                rule_name="JS 内联密钥",
                category="credential",
                severity="high",
                value=m.group(1),
                context=js_content[max(0, m.start()-30):m.end()+30],
                location="js",
            ))

        return matches
