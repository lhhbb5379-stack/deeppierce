"""JS 接口提取器 — FindSomething 风格：宽提取 + 后过滤。

从 JS 代码中提取 API 端点、路径、URL、密钥、敏感信息。
核心思路来自 FindSomething:
1. 先宽匹配所有看起来像路径/URL的字符串
2. 再过滤静态资源噪音
3. 叠加 API 特定模式加权标记
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class JsExtractResult:
    """JS 提取结果。"""
    api_endpoints: list[str] = field(default_factory=list)     # API 路径（高置信度）
    base_urls: list[str] = field(default_factory=list)         # baseURL 配置
    secrets: list[dict] = field(default_factory=list)           # 密钥/Token
    web_services: list[str] = field(default_factory=list)      # WebService URL
    all_paths: list[str] = field(default_factory=list)          # 所有提取到的路径（含低置信度）
    all_urls: list[str] = field(default_factory=list)           # 所有提取到的完整 URL


# ── 排除后缀（静态资源）─────────────────────────────────────────
NOISE_EXT = {
    "css", "js", "jpg", "jpeg", "png", "gif", "svg", "ico", "bmp",
    "woff", "woff2", "ttf", "eot", "otf", "mp4", "mp3", "webm", "ogg", "wav",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "tar", "gz", "rar", "7z", "map", "chunk", "bundle",
    "xml", "html", "htm", "swf", "flv",
}

# ── 排除的路径模式（肯定是噪音）─────────────────────────────────
NOISE_PATH_PATTERNS = [
    r'//(?:cdn|static|assets|img|fonts|images|upload|theme|media|resource)s?\.',
    r'//(?:www\.w3\.org|schema\.org|ajax\.googleapis\.com)',
    r'node_modules/',
    r'\.min\.',
    r'polyfills',
    r'/@vite/',
    r'/__webpack_',
    r'jquery',
    r'require\.js',
    r'bootstrap',
    r'/(?:images?|imgs?|fonts?|icons?|css|js|assets?|static|media)/',
    r'\.(?:png|jpg|gif|svg|ico|woff2?|ttf|eot|map|css|js|json)\b',
    r'</',  # HTML 标签残留
    r'^\s*$',
    r'^https?://$',
    # ── minified JS 噪音 ──
    r'^/[a-zA-Z],?$',         # /g, /i, /m 等正则标志
    r'^/[><=!^~,;]$',          # />, /< 等
    r'^/g[,;]?\s*$',           # /g,
    r'^/gi\b',                 # /gi
    r'^/hidpi\b',              # /hidpi
    r'^/if\b',                 # /if (minified JS)
    r'^/each\b',               # /each
    r'^/dist/',                # /dist/
    r'^/opt/',                 # /opt/ (build paths)
    r'^/usr/',                 # /usr/
    r'^/var/',                 # /var/
    r'^/home/',                # /home/
    r'^/tmp/',                 # /tmp/
    r'^/(?:index|login|logout|register)\.html?$',
    # ── 长度/结构明显不是API ──
    r'^/[a-zA-Z0-9._-]{1,3}$',  # 太短（/g, /v1, /a）
]

# 常见 JS/CSS 属性名黑名单（不是路径）
NOISE_WORDS = {
    "saturation", "alpha", "hue", "value", "length", "length2",
    "inverse", "normal", "italic", "bold", "bolder", "lighter",
    "left", "right", "top", "bottom", "center", "middle",
    "none", "block", "inline", "hidden", "visible", "auto",
    "start", "end", "justify", "stretch", "baseline",
    "row", "column", "wrap", "nowrap", "reverse",
    "static", "relative", "absolute", "fixed", "sticky",
    "text", "number", "email", "password", "search", "tel", "url",
    "date", "time", "datetime", "month", "week", "color", "range",
    "submit", "reset", "button", "checkbox", "radio", "file",
    "true", "false", "null", "undefined",
    "success", "error", "warning", "info", "debug",
    "primary", "secondary", "danger", "default",
    "small", "medium", "large", "xlarge", "xxlarge",
    "light", "dark", "darker", "bright",
    "solid", "dashed", "dotted", "double", "groove", "ridge",
    "thin", "thick", "medium",
    "square", "round", "circle", "ellipse",
    "contain", "cover", "fill",
    "ltr", "rtl",
    "asc", "desc", "ascending", "descending",
    "yes", "no", "on", "off", "open", "closed",
    "png", "jpg", "gif", "svg", "webp", "bmp", "ico",
    # minified code fragments
    "labelsEl", "epEnv", "txtBorder", "plain-text", "advCSSClasses",
    "CopyFormatting",
}


def _is_noise(text: str) -> bool:
    """检查是否为噪音（非 API 路径）。"""
    if not text or len(text) < 2:
        return True
    # 纯数字或纯符号
    if not re.search(r'[a-zA-Z]', text):
        return True
    # 匹配噪音模式
    for pat in NOISE_PATH_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    # 后缀检查
    t = text.lower()
    if "." in t:
        ext = t.rsplit(".", 1)[-1]
        if ext in NOISE_EXT:
            return True
    # 单段路径检查（如 /saturation, /alpha）
    stripped = text.strip("/")
    if stripped and "/" not in stripped:
        if len(stripped) <= 2 and stripped.isalpha():
            return True  # /g, /if, /a
        if stripped.lower() in NOISE_WORDS:
            return True  # /saturation, /none
    # MIME 类型噪音（Chrome/66, AM/PM, D/M/YYYY）
    if re.search(r'^[a-zA-Z0-9]+/[a-zA-Z0-9._+-]+$', text):
        return True
    # 日期模式
    if re.search(r'^\d{1,2}/\d{1,2}/\d{2,4}$', text):
        return True
    # 纯属性名（不含路径分隔符、不含下划线前缀的驼峰）
    if "/" not in stripped and re.match(r'^[a-z]+[A-Z][a-zA-Z]+$', text):
        return True  # camelCase JS 属性，如 labelsEl
    return False


def _looks_like_api(path: str) -> bool:
    """判断路径是否看起来像 API 端点（加权标记）。"""
    p = path.lower()
    indicators = [
        "/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/v5/",
        "/rest/", "/graphql", "/service/", "/ws/", "/ajax/",
        ".json", ".do", ".action", ".ajax", ".asmx", ".svc",
        "/query", "/mutation", "/rpc", "/soap", "/oauth",
        "/token", "/login", "/logout", "/auth",
    ]
    return any(ind in p for ind in indicators)


class JsApiExtractor:
    """FindSomething 风格的 JS 信息提取器。

    提取流程:
    1. 宽匹配 — 所有带引号的路径、URL、域名
    2. 去噪音 — 排除静态资源、CDN、已知库路径
    3. 分类 — API 端点 vs 普通路径 vs 完整 URL
    4. 密钥 — SecretPatternMatcher 扫描
    """

    # ── 第一层：宽匹配（FindSomething 核心思路）────────────────

    # 所有以 / ./ ../ 开头的路径
    PATH_RE = re.compile(r"""['\"`]((?:/|\.\./|\./)[^'\"`\s]{2,200})['\"`]""")

    # 模版字符串中的路径
    TEMPLATE_PATH_RE = re.compile(r"""`((?:/|\.\./|\./)[^`\s]{2,200})`""")

    # 完整 URL（带协议 + TLD）
    URL_RE = re.compile(
        r"""['\"`]((?:https?://|//)[a-zA-Z0-9][a-zA-Z0-9\-.]*\.[a-zA-Z]{2,}"""
        r"""(?:/\S{0,200})?)['\"`]""",
        re.IGNORECASE,
    )

    # 域名（含常见 TLD，后面可能跟路径）
    DOMAIN_RE = re.compile(
        r"""['\"`]([a-zA-Z0-9][a-zA-Z0-9\-.]*\.[a-zA-Z]{2,}"""
        r"""(?:/[^\s\"'<>]{0,50})?)['\"`]""",
        re.IGNORECASE,
    )

    # ── 第二层：API 模式加权 ───────────────────────────────────

    API_PATTERNS = [
        # fetch/axios/ajax 调用
        (re.compile(
            r'(?:fetch|axios\.\w+|\.get|\.post|\.put|\.delete|\.patch|\.ajax)'
            r'\s*\(\s*["\'`]([^"\'`\s]{3,})["\'`]',
            re.IGNORECASE,
        ), "HTTP调用"),
        # baseURL / baseUrl
        (re.compile(
            r'''base(?:URL|Url|url)\s*:\s*["\'`]([^"'`\s]{3,})["\'`]''',
            re.IGNORECASE,
        ), "baseURL"),
        # $http / $resource (Angular)
        (re.compile(
            r'''(?:\$http\.\w+|\$resource)\s*\(\s*["\'`]([^"'`\s]{3,})["\'`]''',
            re.IGNORECASE,
        ), "Angular"),
        # wx.request / uni.request (小程序)
        (re.compile(
            r'''(?:wx|uni)\.request\s*\(\s*\{[^}]*url\s*:\s*["\'`]([^"'`\s]{3,})["\'`]''',
            re.IGNORECASE,
        ), "小程序"),
        # WebService
        (re.compile(
            r'''["\'`](https?://[^"'`\s]{3,}\.asmx[^"'`\s]{0,50})["\'`]''',
            re.IGNORECASE,
        ), "WebService"),
        (re.compile(
            r'''["\'`](https?://[^"'`\s]{3,}\.svc[^"'`\s]{0,50})["\'`]''',
            re.IGNORECASE,
        ), "WCF"),
        (re.compile(
            r'''["\'`](https?://[^"'`\s]{3,}/wsdl[^"'`\s]{0,30})["\'`]''',
            re.IGNORECASE,
        ), "WSDL"),
        # 路由定义
        (re.compile(
            r'''(?:path|route|url)\s*:\s*["\'`](/[^"'`\s]{3,60})["\'`]''',
            re.IGNORECASE,
        ), "路由"),
        # 模板字符串 API URL（带变量插值）
        (re.compile(
            r'`((?:https?://)?[^`]*(?:/api/|/v\d/)[^`]{2,80})`',
            re.IGNORECASE,
        ), "模板API"),
    ]

    def __init__(self, custom_patterns: list[str] | None = None):
        from DeepPierce.enrich.patterns import SecretPatternMatcher
        self._secret_matcher = SecretPatternMatcher()
        self._custom_regexes: list = []
        if custom_patterns:
            for p in custom_patterns:
                if isinstance(p, str):
                    p = p.strip()
                    if not p or p.startswith("#"):
                        continue
                    try:
                        self._custom_regexes.append(re.compile(p))
                    except re.error:
                        pass
                else:
                    # 已经是编译好的正则
                    self._custom_regexes.append(p)

    def extract(self, js_code: str, source_label: str = "") -> JsExtractResult:
        """从 JS 代码中提取所有信息。

        Args:
            js_code: JS 源代码
            source_label: 来源标签（如文件名）
        """
        if not js_code or len(js_code) < 10:
            return JsExtractResult()

        result = JsExtractResult()
        seen = set()

        # ── 第一层：宽提取所有路径 ──
        raw_paths: list[str] = []

        for m in self.PATH_RE.finditer(js_code):
            raw_paths.append(m.group(1))
        for m in self.TEMPLATE_PATH_RE.finditer(js_code):
            raw_paths.append(m.group(1))

        # 去重 + 过滤
        all_paths: list[str] = []
        for p in raw_paths:
            p = p.strip().rstrip("\\")
            if p not in seen and not _is_noise(p):
                seen.add(p)
                all_paths.append(p)

        result.all_paths = all_paths

        # 分类：API 端点 vs 普通路径
        for p in all_paths:
            if _looks_like_api(p):
                result.api_endpoints.append(p)
            else:
                # 也加入 api_endpoints，但靠前的是高置信度的
                # 只加入相对路径（不以 http 开头的）
                if not p.startswith(("http://", "https://", "//")):
                    result.api_endpoints.append(p)

        # ── 第一层：宽提取 URL 和域名 ──
        all_urls: list[str] = []
        for m in self.URL_RE.finditer(js_code):
            url = m.group(1).strip()
            if url not in seen:
                seen.add(url)
                all_urls.append(url)
        for m in self.DOMAIN_RE.finditer(js_code):
            d = m.group(1).strip()
            if d not in seen:
                seen.add(d)
                all_urls.append(d)

        result.all_urls = all_urls

        # 完整 URL 分类
        for u in all_urls:
            u_lower = u.lower()
            if any(k in u_lower for k in [".asmx", ".svc", "/wsdl", "webservice", "/soap/"]):
                result.web_services.append(u)
            elif u.startswith(("http://", "https://", "//")):
                if _looks_like_api(u):
                    result.api_endpoints.append(u)

        # ── 第二层：API 模式加权提取（高置信度） ──
        high_conf: set[str] = set()
        for regex, label in self.API_PATTERNS:
            for m in regex.finditer(js_code):
                endpoint = m.group(1).strip()
                if endpoint and not _is_noise(endpoint):
                    high_conf.add(endpoint)
                    if label == "baseURL":
                        if endpoint not in result.base_urls:
                            result.base_urls.append(endpoint)
                    elif label in ("WebService", "WCF", "WSDL"):
                        if endpoint not in result.web_services:
                            result.web_services.append(endpoint)

        # 高置信度端点排前面
        for ep in high_conf:
            if ep in result.api_endpoints:
                result.api_endpoints.remove(ep)
            result.api_endpoints.insert(0, ep)

        # ── 密钥提取 ──
        secrets = self._secret_matcher.scan_js(js_code)
        result.secrets = [
            {"rule": s.rule_name, "value": s.value[:100], "severity": s.severity}
            for s in secrets
        ]

        # 去重（保持顺序）
        result.api_endpoints = list(dict.fromkeys(result.api_endpoints))
        result.base_urls = list(dict.fromkeys(result.base_urls))
        result.web_services = list(dict.fromkeys(result.web_services))
        result.all_paths = list(dict.fromkeys(result.all_paths))
        result.all_urls = list(dict.fromkeys(result.all_urls))

        # ── 自定义规则 ──
        for regex in self._custom_regexes:
            for m in regex.finditer(js_code):
                val = m.group(1) if m.groups() else m.group(0)
                if val and len(val) > 2 and not _is_noise(val):
                    if val not in result.api_endpoints:
                        result.api_endpoints.append(val)

        return result

    def extract_from_files(self, files: dict[str, str]) -> dict[str, JsExtractResult]:
        """批量提取多个 JS 文件。"""
        return {
            name: self.extract(content, name)
            for name, content in files.items()
        }

    @staticmethod
    def filter_js_from_burp(records: list[dict]) -> dict[str, str]:
        """从 Burp 流量中筛选 JS 文件。"""
        js_files = {}
        for r in records:
            url = r.get("url", "")
            path = r.get("path", url)
            mime = r.get("mime_type", r.get("response_mime_type", ""))
            body = r.get("response_body", "")

            is_js = (
                path.lower().endswith(".js") or
                "javascript" in mime.lower() or
                "ecmascript" in mime.lower()
            )
            if is_js and body and len(body) > 100:
                if path not in js_files or len(body) > len(js_files[path]):
                    js_files[path] = body

        return js_files
