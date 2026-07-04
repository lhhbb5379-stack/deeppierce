"""Agent tools — Claude's hands and feet for API fuzzing.

Every tool that discovers data returns a clean "action_items" block at the top
so the Agent knows exactly what to do next. Detailed data is stored server-side
and queryable via get_pending_work / get_fuzz_dictionary.

Wired engines:
- FindSomething (patterns.py): secret/credential scanning
- HaE (rules.py): fingerprint + vuln clue detection
- CaA (dictionary.py): traffic-driven fuzz dictionary
"""

from __future__ import annotations

import json, re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from DeepPierce.enrich.patterns import SecretPatternMatcher
from DeepPierce.enrich.rules import RuleEngine
from DeepPierce.enrich.dictionary import FuzzDictionaryBuilder
from DeepPierce.crawler.js_extractor import JsApiExtractor


TOOL_DEFINITIONS = [
    {
        "name": "fetch_burp_traffic",
        "description": "Pull HTTP traffic from Burp Suite for a hostname. Returns clear action_items: secrets to report, fingerprints found, vuln clues, and a TEST LIST of all discovered endpoints. Use this FIRST.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target hostname, e.g. api.example.com"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "crawl_page",
        "description": "Crawl a URL to discover links, forms, API endpoints in HTML/JS. Returns action_items with new endpoints to test.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Page URL to crawl"},
                "follow_links": {"type": "boolean", "description": "Follow same-domain links, default false"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "fetch_js",
        "description": "Download JS files, extract hidden API endpoints and secrets. Returns action_items with new endpoints discovered in JS.",
        "input_schema": {
            "type": "object",
            "properties": {
                "urls": {"type": "array", "items": {"type": "string"}, "description": "JS file URLs to analyze"},
            },
            "required": ["urls"],
        },
    },
    {
        "name": "send_request",
        "description": "Send an HTTP request (for fuzzing/auth testing). Response auto-scanned for secrets/fingerprints. Returns action_items if new findings detected.",
        "input_schema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "HTTP method"},
                "url": {"type": "string", "description": "Full URL"},
                "headers": {"type": "object", "description": "Request headers as JSON object"},
                "body": {"type": "string", "description": "Request body (optional)"},
                "modification_desc": {"type": "string", "description": "Short description of what was modified and what you're testing for"},
            },
            "required": ["method", "url", "modification_desc"],
        },
    },
    {
        "name": "get_pending_work",
        "description": "Get a list of ALL untested endpoints and unreported findings. Call this when you need to know what's left to do.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "get_fuzz_dictionary",
        "description": "Get the auto-built fuzz dictionary (CaA) — top parameter names, paths, values sorted by frequency. Use for payload ideas.",
        "input_schema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "params / paths / values / files / full_paths"},
                "top_n": {"type": "integer", "description": "Number of entries, default 30"},
            },
            "required": ["category"],
        },
    },
    {
        "name": "lookup_params",
        "description": "Look up what parameters (with sample values) were observed on a specific endpoint in Burp traffic. Use this when testing an endpoint that needs credentials or unknown parameters — it shows exactly what params/headers were used before.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Endpoint path to look up, e.g. /api/user/info"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "mark_endpoint",
        "description": "Mark an endpoint as tested/skipped. This removes it from the pending work list. Call after testing EACH endpoint.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Endpoint path, e.g. /api/user/info"},
                "method": {"type": "string", "description": "HTTP method"},
                "status": {"type": "string", "description": "done (tested, no vuln) / skipped (why?) / testing"},
                "note": {"type": "string", "description": "What was tested or why skipped"},
            },
            "required": ["path", "method", "status", "note"],
        },
    },
    {
        "name": "report_finding",
        "description": "Report a CONFIRMED vulnerability. Requires curl PoC. ONLY the curl command — no '| python3', '| jq', or other pipes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "attack_type": {"type": "string", "description": "idor/sqli/xss/ssrf/ssti/cmdi/lfi/csrf/auth_bypass/info_leak/other"},
                "severity": {"type": "string", "description": "critical/high/medium/low/info"},
                "confidence": {"type": "number", "description": "0.0-1.0"},
                "description": {"type": "string"},
                "poc": {"type": "string", "description": "EXACT curl command to reproduce"},
            },
            "required": ["title", "attack_type", "severity", "confidence", "description", "poc"],
        },
    },
    {
        "name": "report_noise",
        "description": "Log an unverified observation (no PoC). Goes to noise bin for later review.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "category": {"type": "string"},
                "note": {"type": "string", "description": "Why interesting but not confirmed"},
            },
            "required": ["title", "note"],
        },
    },
    {
        "name": "task_done",
        "description": "Mark the penetration test complete. Call ONLY after all endpoints are tested or skipped.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "total_endpoints": {"type": "integer"},
                "total_findings": {"type": "integer"},
            },
            "required": ["summary"],
        },
    },
]


class ToolExecutor:
    DANGEROUS_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

    # 安全豁免：这些路径的操作不需要审批
    SAFE_PATH_PATTERNS = [
        r'/login', r'/signin', r'/auth', r'/token', r'/session',
        r'/logout', r'/register', r'/signup', r'/oauth',
        r'\.aspx', r'\.ashx', r'\.php',
    ]

    # 静态资源 — 直接跳过，不注册为端点
    SKIP_EXTENSIONS = {
        "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "bmp", "webp",
        "woff", "woff2", "ttf", "eot", "otf", "mp4", "mp3", "webm", "ogg", "wav",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "zip", "tar", "gz", "rar", "7z", "map",
    }
    SKIP_PATH_KEYWORDS = ["/images/", "/img/", "/fonts/", "/css/", "/static/", "/assets/",
                          "/media/", "/videos/", "/audio/", "/favicon"]

    @staticmethod
    def _is_static_resource(path: str) -> bool:
        """预过滤：判断路径是否为不需要测试的静态资源。JS 不过滤（可能含接口/密钥）。"""
        p = path.lower().split("?")[0].rstrip("/")
        if "." in p and p.rsplit(".", 1)[-1] in ToolExecutor.SKIP_EXTENSIONS:
            return True
        if any(kw in p for kw in ToolExecutor.SKIP_PATH_KEYWORDS):
            return True
        return False

    @staticmethod
    def _is_safe_operation(url: str) -> bool:
        """判断操作是否安全（不需要审批）。登录、认证等操作豁免。"""
        path = urlparse(url).path.lower()
        for pat in ToolExecutor.SAFE_PATH_PATTERNS:
            if re.search(pat, path):
                return True
        return False

    def __init__(self, proxy_url: str = "http://127.0.0.1:8080", burp_mcp_url: str = "",
                 proxy_enabled: bool = True, burp_mcp_enabled: bool = True,
                 custom_api_patterns: str = "", custom_secret_rules: str = ""):
        self.proxy_url = proxy_url
        self.burp_mcp_url = burp_mcp_url
        self.proxy_enabled = proxy_enabled
        self.burp_mcp_enabled = burp_mcp_enabled
        self._burp_traffic_cache: dict[str, list[dict]] = {}
        self._http_client: httpx.AsyncClient | None = None
        self._burp_mcp: Any = None
        self.on_endpoint: callable | None = None
        self.confirm_dangerous: callable | None = None
        self.on_mark_endpoint: callable | None = None

        # ── 三大富化引擎 ──────────────────────────────────────────
        self._secret_matcher = SecretPatternMatcher(custom_rules_str=custom_secret_rules or "")
        self._rule_engine = RuleEngine.with_default_rules()
        self._fuzz_dict_builder = FuzzDictionaryBuilder()

        # ── 端点 & 发现物追踪 (Agent 的 TODO 列表) ────────────────
        self._endpoints: dict[str, dict] = {}   # key="METHOD:path"
        self._pending_secrets: list[dict] = []   # secrets not yet reported
        self._pending_fingerprints: list[dict] = []  # HaE fingerprints
        self._pending_vuln_clues: list[dict] = []    # HaE vuln clues
        self._param_store: dict[str, dict] = {}  # key=path → {params: {name: [values]}, headers: {}}

        # ── 自定义 API 提取正则 ──
        self._custom_api_regexes: list[re.Pattern] = []
        api_patterns = custom_api_patterns or ""
        if api_patterns.strip():
            for line in api_patterns.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        self._custom_api_regexes.append(re.compile(line))
                    except re.error:
                        pass

    def _apply_custom_api_patterns(self, text: str) -> list[str]:
        """对文本应用用户自定义的 API 提取正则。"""
        results = []
        for pat in self._custom_api_regexes:
            for m in pat.finditer(text):
                val = m.group(0) if not m.groups() else (m.group(1) or m.group(0))
                if val and len(val) > 2:
                    results.append(val)
        return list(dict.fromkeys(results))  # 去重保序

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http_client is None:
            proxy = self.proxy_url if self.proxy_enabled else None
            self._http_client = httpx.AsyncClient(
                proxy=proxy, timeout=httpx.Timeout(30.0),
                follow_redirects=True, verify=False,
                headers={"User-Agent": "DeepPierce/1.0.0"},
            )
        return self._http_client

    async def execute(self, tool_name: str, tool_input: dict, on_thought: callable = None) -> str:
        handlers = {
            "fetch_burp_traffic": self._fetch_burp_traffic,
            "crawl_page": self._crawl_page,
            "fetch_js": self._fetch_js,
            "send_request": self._send_request,
            "get_pending_work": self._get_pending_work,
            "get_fuzz_dictionary": self._get_fuzz_dictionary,
            "lookup_params": self._lookup_params,
            "mark_endpoint": self._mark_endpoint,
            "report_finding": self._report_finding,
            "report_noise": self._report_noise,
            "task_done": self._task_done,
        }
        handler = handlers.get(tool_name)
        if handler:
            return await handler(tool_input, on_thought) if asyncio.iscoroutinefunction(handler) else handler(tool_input, on_thought)
        return f"Unknown tool: {tool_name}"

    # ═══════════════════════════════════════════════════════════════
    # 端点注册 + 行动摘要
    # ═══════════════════════════════════════════════════════════════

    def _register_endpoint(self, method: str, path: str, source: str) -> bool:
        """注册端点。返回 True 表示是新端点。静态资源自动跳过。"""
        if not path or path == "/":
            return False
        if self._is_static_resource(path):
            return False
        key = f"{method}:{path}"
        if key not in self._endpoints:
            self._endpoints[key] = {
                "method": method, "path": path, "source": source,
                "tested": False, "test_history": [], "findings": [],
            }
            return True
        return False

    def _record_test_activity(self, path: str, method: str, action: str, note: str = ""):
        """记录一次测试活动到对应端点。"""
        from datetime import datetime, timezone
        key = f"{method}:{path.split('?')[0].rstrip('/')}"
        # 尝试匹配已注册的端点
        if key not in self._endpoints:
            # 模糊匹配：同 path 不同 method
            for ek, ev in self._endpoints.items():
                if ev["path"].rstrip("/") == path.split("?")[0].rstrip("/"):
                    key = ek
                    break
        if key in self._endpoints:
            self._endpoints[key]["test_history"].append({
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "action": action,
                "note": note,
            })

    def _register_endpoints_batch(self, endpoints: list[tuple[str, str, str]]) -> int:
        """批量注册。返回新端点数。"""
        return sum(1 for m, p, s in endpoints if self._register_endpoint(m, p, s))

    def _get_untested_endpoints(self) -> list[dict]:
        return [v for v in self._endpoints.values() if not v["tested"]]

    def _get_endpoint_stats(self) -> dict:
        tested = sum(1 for v in self._endpoints.values() if v["tested"])
        return {"total": len(self._endpoints), "tested": tested, "pending": len(self._endpoints) - tested}

    def _score_endpoint(self, ep: dict) -> int:
        """给端点打分，Agent 按分数从高到低测试。"""
        score = 0
        path = ep.get("path", "").lower()
        method = ep.get("method", "GET").upper()

        # 路径特征
        if any(k in path for k in ["admin", "manage", "config", "backup", "debug", "secret"]):
            score += 5
        if any(k in path for k in ["user", "account", "auth", "login", "password", "token"]):
            score += 3
        if any(k in path for k in ["order", "pay", "transaction", "wallet", "balance"]):
            score += 3
        if any(k in path for k in ["api/", "/v1/", "/v2/", "/rest/", "/graphql"]):
            score += 2

        # 来源加分（JS提取的接口往往是隐藏接口）
        source = ep.get("source", "")
        if "JS" in source:
            score += 3

        # 方法加分（写操作风险更高）
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            score += 2

        # 有认证信息（测未授权更有价值）
        req_headers = ep.get("request_headers", {})
        has_auth = any(k.lower() in {"authorization", "cookie", "x-auth-token", "x-api-key"}
                      for k in req_headers)
        if has_auth:
            score += 2

        return score

    def _suggested_tests(self, ep: dict, dict_stats: dict) -> list[str]:
        """根据端点特征和 CaA 字典生成测试建议。至少返回基础测试项。"""
        tests = []
        path = ep.get("path", "")
        method = ep.get("method", "GET")
        source = ep.get("source", "")
        req_headers = ep.get("request_headers", {}) or {}
        has_auth = any(k.lower() in {"authorization", "cookie", "x-auth-token", "x-api-key"}
                      for k in req_headers)

        # 未授权测试
        if has_auth:
            tests.append("Unauth: send_request 不带认证信息重放，看是否返回 200")
        elif "/api/" in path:
            tests.append("Unauth: 尝试不带任何 header 重放，检查是否有鉴权")

        # IDOR 检测
        import re as _re
        id_patterns = [r'/id\b', r'/uuid\b', r'/(?:user|order|account|profile|item|product)_?id\b',
                       r'/\d{2,}', r'/[a-f0-9-]{20,}']
        if any(_re.search(p, path, _re.IGNORECASE) for p in id_patterns):
            tests.append("IDOR: 枚举ID参数值 (尝试 1,2,3...)")
            tests.append("IDOR: 尝试负数/零值/超大值")

        # 基础参数测试
        if method in ("POST", "PUT", "PATCH"):
            tests.append("Body参数: 尝试空值 / null / 超长字符串 / 特殊字符")
            tests.append("Content-Type: 尝试切换 application/xml 看是否解析")

        # CaA 隐藏参数发现
        top_params = dict_stats.get("top_params", [])
        hidden_params = [p for p in top_params[:15] if p not in path.lower()][:5]
        if hidden_params:
            tests.append(f"隐藏参数: 尝试添加 {', '.join(hidden_params)} (CaA字典高频参数)")
        elif "JS" in source or not req_headers:
            # JS 提取的裸路径，或没有抓到请求头的接口，鼓励 Agent 主动查字典
            tests.append("⚠ 无已知参数！用 get_fuzz_dictionary('params') 获取高频参数名，拼接测试此接口")

        # 分页/查询参数
        if method == "GET" and any(p in path.lower() for p in ["list", "search", "page", "query", "all"]):
            tests.append("DoS: 尝试 ?page=999999&limit=0&size=-1")

        # 管理员接口
        if "admin" in path.lower():
            tests.append("权限绕过: 尝试不带 admin cookie 直接访问")

        # 至少给一条基础建议
        if not tests:
            if method == "GET":
                tests.append("Baseline: send_request 重放原始请求建立基线响应")
                tests.append("Params: 尝试添加常见调试参数 ?debug=1&test=1")
            else:
                tests.append("Baseline: send_request 重放原始请求建立基线响应")
                tests.append("Body: 尝试修改 body 中的值看响应变化")

        return tests[:6]  # 最多6条建议，避免信息过载

    def _build_action_items(self, new_endpoints: int, enrichment: dict) -> dict:
        """构建 Agent 可执行的操作清单 — 含推荐顺序、端点打分、指纹自动跟进。"""
        items: dict[str, list] = {}
        recommended: list[str] = []

        # ── 1. 凭证泄露 → 最高优先级 ──
        secrets = enrichment.get("secrets", [])
        critical_secrets = [s for s in secrets if s["severity"] in ("critical", "high")]
        if critical_secrets:
            items["secrets_to_report"] = [
                {"severity": s["severity"], "rule": s["rule"], "value": s["value"][:100],
                 "action": f"report_finding — {s['rule']} 泄露"}
                for s in critical_secrets[:10]
            ]
            recommended.append(f"立即上报 {len(critical_secrets)} 个凭证泄露 (secrets_to_report)")

        # ── 2. 技术指纹 → 附自动跟进 URL ──
        fingerprints = [m for m in enrichment.get("hae_matches", []) if m["group"] == "指纹识别"]
        if fingerprints:
            self._pending_fingerprints.extend(fingerprints)
            fp_items = []
            for f in fingerprints[:10]:
                item = {"rule": f["rule"], "value": f["value"][:100],
                        "action": _fingerprint_action(f["rule"]),
                        "auto_urls": _fingerprint_urls(f["rule"], f["value"])}
                fp_items.append(item)
                if item["auto_urls"]:
                    recommended.append(f"指纹 {f['rule']}: 访问 {len(item['auto_urls'])} 个相关URL验证")
            items["fingerprints_found"] = fp_items

        # ── 3. 漏洞线索 ──
        vuln_clues = [m for m in enrichment.get("hae_matches", []) if m["group"] == "漏洞线索"]
        if vuln_clues:
            self._pending_vuln_clues.extend(vuln_clues)
            items["vuln_clues_found"] = [
                {"rule": c["rule"], "value": c["value"][:100],
                 "action": _vuln_clue_action(c["rule"])}
                for c in vuln_clues[:10]
            ]

        # ── 4. 端点按评分排序 + 测试建议 ──
        dict_stats = enrichment.get("fuzz_dictionary", {})
        untested = self._get_untested_endpoints()
        if untested:
            for ep in untested:
                ep["_score"] = self._score_endpoint(ep)
                ep["_suggested_tests"] = self._suggested_tests(ep, dict_stats)
            untested.sort(key=lambda e: e["_score"], reverse=True)

            # 按优先级展示（去掉内部字段的简版）
            items["endpoints_priority_order"] = [
                {"method": ep["method"], "path": ep["path"], "source": ep["source"],
                 "priority_score": ep["_score"],
                 "suggested_tests": ep["_suggested_tests"]}
                for ep in untested[:30]
            ]

            high_priority = [ep for ep in untested if ep["_score"] >= 5]
            if high_priority:
                recommended.append(
                    f"优先测试 {len(high_priority)} 个高风险端点 (评分≥5): "
                    + ", ".join(f"{ep['method']} {ep['path']}" for ep in high_priority[:5])
                )
            if len(untested) > 0:
                recommended.append(f"全部待测: {len(untested)} 个端点，用 get_pending_work 查看完整清单")

        # ── 5. 可用凭证（Agent 在需认证接口上复用）──
        auth_creds = enrichment.get("auth_credentials", [])
        if auth_creds:
            items["available_credentials"] = auth_creds
            recommended.append(
                f"有 {len(auth_creds)} 组凭证可用（Cookie/Token等）。"
                f"遇到需认证的接口时，用这些凭证重放，不要直接标记为 '需认证' 就跳过。"
            )

        # ── 6. CaA 字典利用建议 ──
        top_params = dict_stats.get("top_params", [])
        if top_params:
            items["fuzz_dict_snapshot"] = dict_stats
            items["param_discovery_hint"] = (
                f"这些高频参数在目标应用中反复出现: {', '.join(top_params[:10])}。"
                f"对每个端点，如果原始请求中没有这些参数，尝试添加后再发包 (send_request 时加到 headers/body/query 中)"
            )

        items["recommended_next"] = recommended
        return items

    # ═══════════════════════════════════════════════════════════════
    # 三大引擎富化
    # ═══════════════════════════════════════════════════════════════

    def _enrich_traffic_batch(self, records: list[dict], on_thought: callable = None) -> dict:
        all_secrets: list[dict] = []
        all_hae: list[dict] = []
        hae_seen: set[str] = set()
        secret_seen: set[str] = set()
        auth_creds: dict[str, dict] = {}  # 收集凭证供 Agent 复用

        for r in records:
            url = r.get("url", "")
            method = r.get("method", "GET")
            resp_body = r.get("response_body", "") or ""
            resp_headers = r.get("response_headers", {}) or {}
            req_body = r.get("request_body", "") or ""
            req_headers = r.get("request_headers", {}) or {}

            secrets = self._secret_matcher.scan_response(body=resp_body, headers=resp_headers, url=url)
            for s in secrets:
                key = f"{s.rule_name}:{s.value[:60]}"
                if key not in secret_seen:
                    secret_seen.add(key)
                    all_secrets.append({"rule": s.rule_name, "category": s.category,
                                        "severity": s.severity, "value": s.value[:120],
                                        "context": s.context[:80], "location": s.location})

            hae_matches = self._rule_engine.match(
                request=req_body, response=resp_body,
                req_headers=self._headers_to_text(req_headers),
                resp_headers=self._headers_to_text(resp_headers),
            )
            for m in hae_matches:
                key = f"{m.rule_name}:{m.value[:60]}"
                if key not in hae_seen:
                    hae_seen.add(key)
                    all_hae.append({"rule": m.rule_name, "group": m.group_name,
                                    "value": m.value[:200], "scope": m.scope.value})

            self._fuzz_dict_builder.process_exchange(
                url=url, method=method,
                request_body=req_body,
                request_content_type=req_headers.get("content-type", ""),
                request_headers=req_headers,
                response_body=resp_body,
                response_content_type=resp_headers.get("content-type", ""),
            )

            # ── 收集凭证（供 Agent 在需认证的接口上复用）──
            for key in ("authorization", "cookie", "x-auth-token", "x-api-key"):
                val = req_headers.get(key) or req_headers.get(key.lower()) or req_headers.get(key.upper())
                if val and key not in auth_creds:
                    auth_creds[key] = {"header": key, "value": val[:300], "from_url": url[:120]}

            # ── 入参数商店（per-endpoint params + values）──
            path_key = urlparse(url).path.rstrip("/") or "/"
            if path_key not in self._param_store:
                self._param_store[path_key] = {"params": {}, "headers": {}, "method": method, "full_url": url[:200]}
            ps = self._param_store[path_key]
            # 存headers
            for k, v in req_headers.items():
                if k.lower() not in ("host", "content-length", "accept-encoding", "connection", "user-agent"):
                    ps["headers"].setdefault(k, v)
            # 存params from URL
            parsed = urlparse(url)
            if parsed.query:
                from urllib.parse import parse_qs
                for pname, pvals in parse_qs(parsed.query).items():
                    ps["params"].setdefault(pname, []).extend(pvals)
            # 存params from JSON body
            if req_body and "json" in req_headers.get("content-type", "").lower():
                import json as _json
                try:
                    body_obj = _json.loads(req_body)
                    if isinstance(body_obj, dict):
                        for k, v in body_obj.items():
                            ps["params"].setdefault(k, []).append(str(v)[:200])
                except Exception:
                    pass

        return {"secrets": all_secrets, "hae_matches": all_hae, "fuzz_dictionary": self._dict_stats(),
                "auth_credentials": list(auth_creds.values()) if auth_creds else []}

    def _enrich_single_response(self, url: str, method: str, resp_body: str, resp_headers: dict,
                                req_body: str = "", req_headers: dict | None = None) -> dict:
        req_headers = req_headers or {}
        return self._enrich_traffic_batch([{
            "url": url, "method": method,
            "response_body": resp_body, "response_headers": resp_headers,
            "request_body": req_body, "request_headers": req_headers,
        }])

    def _dict_stats(self) -> dict:
        d = self._fuzz_dict_builder.dictionary
        return {
            "top_params": d.to_payload_list("params", 20),
            "top_paths": d.to_payload_list("paths", 20),
            "top_values": d.to_payload_list("values", 20),
            "total_params": len(d.params), "total_paths": len(d.paths), "total_values": len(d.values),
        }

    @staticmethod
    def _headers_to_text(headers: dict[str, str]) -> str:
        if not headers: return ""
        return "\n".join(f"{k}: {v}" for k, v in headers.items())

    # ═══════════════════════════════════════════════════════════════
    # 工具实现
    # ═══════════════════════════════════════════════════════════════

    async def _fetch_burp_traffic(self, inp: dict, on_thought) -> str:
        host = inp["host"]
        if on_thought: on_thought("action", f"📡 拉取 Burp 流量: {host}")

        all_records = []
        if self.burp_mcp_url and self.burp_mcp_enabled:
            try:
                from DeepPierce.bridge.burp import BurpMCPClient
                if self._burp_mcp is None:
                    self._burp_mcp = BurpMCPClient(self.burp_mcp_url)
                proxy_records = await self._burp_mcp.fetch_proxy_history(host, max_items=99999)
                sitemap_records = await self._burp_mcp.fetch_sitemap(host, max_results=99999)
                seen = set()
                for r in proxy_records + sitemap_records:
                    key = f"{r['method']}:{r['path']}"
                    if key not in seen:
                        seen.add(key)
                        all_records.append(r)
                if all_records:
                    self._burp_traffic_cache[host] = all_records
            except Exception as e:
                if on_thought: on_thought("error", f"BurpMCP: {e}")

        cached = self._burp_traffic_cache.get(host, [])
        for r in cached:
            if f"{r['method']}:{r['path']}" not in {f"{x['method']}:{x['path']}" for x in all_records}:
                all_records.append(r)

        # ── 注册 Burp 流量中的端点 ──
        burp_new = 0
        for r in all_records:
            if self._register_endpoint(r.get("method", "GET"), r.get("path", "/"), "Burp"):
                burp_new += 1

        # ── JS 端点提取 + 注册 ──
        js_new = 0
        js_secrets = []
        if all_records:
            js_files = JsApiExtractor.filter_js_from_burp(all_records)
            if js_files:
                extractor = JsApiExtractor()
                for js_path, js_content in js_files.items():
                    result = extractor.extract(js_content, js_path)
                    for ep in result.api_endpoints + result.base_urls + result.web_services:
                        if ep and self._register_endpoint("?", ep, "JS提取"):
                            js_new += 1
                    js_secrets.extend(result.secrets)
                    # ── 自定义 API 规则 ──
                    for ep in self._apply_custom_api_patterns(js_content):
                        if ep and self._register_endpoint("?", ep, "自定义规则"):
                            js_new += 1

        # ── 三大引擎富化 ──
        enrichment = self._enrich_traffic_batch(all_records, on_thought)

        if self.on_endpoint:
            for ep in self._get_untested_endpoints()[:50]:
                self.on_endpoint(ep["method"], ep["path"], ep["source"])

        action_items = self._build_action_items(burp_new + js_new, enrichment)
        stats = self._get_endpoint_stats()
        untested = self._get_untested_endpoints()

        if not all_records:
            return json.dumps({
                "error": "无法连接 Burp。请确保 Burp Suite 和 BurpMCP 扩展正在运行。",
                "action_items": None, "endpoint_stats": stats,
            }, indent=2, ensure_ascii=False)

        return json.dumps({
            "summary": f"从 Burp 拉取 {len(all_records)} 条流量 ({host})，注册 {stats['total']} 个端点 (Burp: {burp_new}, JS提取: {js_new})",
            "action_items": action_items,
            "endpoint_stats": stats,
            "untested_endpoints": untested[:30],
            "total_untested": len(untested),
            "instructions": "按顺序处理 action_items: 1) secrets_to_report → 用 report_finding 上报 2) fingerprints_found/vuln_clues_found → 用 send_request 验证 3) new_endpoints_to_test → 逐个用 send_request 测试并 mark_endpoint",
        }, indent=2, ensure_ascii=False)

    async def _crawl_page(self, inp: dict, on_thought) -> str:
        url = inp["url"]
        if on_thought: on_thought("action", f"🕷 爬虫: {url}")

        try:
            resp = await self.http.get(url)
            html = resp.text
        except Exception as e:
            try:
                async with httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False) as dc:
                    resp = await dc.get(url)
                    html = resp.text
            except Exception:
                return json.dumps({"error": f"Crawl failed: {e}", "action_items": None}, indent=2, ensure_ascii=False)

        soup = BeautifulSoup(html, "html.parser")
        base_domain = urlparse(url).netloc
        links, forms, js_files, api_from_html, api_from_inline = [], [], [], [], []

        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href", "")
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full = urljoin(url, href)
                parsed = urlparse(full)
                if parsed.netloc == base_domain or inp.get("follow_links", False):
                    links.append({"tag": tag.name, "url": full, "text": tag.get_text(strip=True)[:100]})
                    if _looks_like_api(parsed.path):
                        api_from_html.append(full)

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = (form.get("method", "GET") or "GET").upper()
            inputs = [{"name": t.get("name", ""), "type": t.get("type", "text"), "value": t.get("value", "")}
                      for t in form.find_all(["input", "select", "textarea"])]
            form_url = urljoin(url, action) if action else url
            forms.append({"action": form_url, "method": method, "inputs": inputs})
            # 注册表单为端点
            self._register_endpoint(method, urlparse(form_url).path or form_url, "crawler-form")

        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src: js_files.append(urljoin(url, src))
            elif script.string: api_from_inline.extend(_extract_api_from_js(script.string))

        # 注册端点
        new_count = 0
        for ep in api_from_html[:30]:
            if self._register_endpoint("GET", urlparse(ep).path or ep, "crawler"): new_count += 1
        for ep in api_from_inline[:30]:
            if self._register_endpoint("?", ep, "crawler-inline"): new_count += 1

        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        enrichment = self._enrich_single_response(url=url, method="GET", resp_body=html, resp_headers=resp_headers)
        action_items = self._build_action_items(new_count, enrichment)
        stats = self._get_endpoint_stats()

        for ep in self._get_untested_endpoints()[:30]:
            if self.on_endpoint: self.on_endpoint(ep["method"], ep["path"], ep["source"])

        return json.dumps({
            "summary": f"爬取 {url} — 发现 {len(links)} 链接, {len(forms)} 表单, {len(js_files)} JS文件, {len(api_from_html) + len(api_from_inline)} 个疑似API",
            "action_items": action_items,
            "endpoint_stats": stats,
            "details": {"links": links[:30], "forms": forms[:20], "js_files": js_files[:20],
                        "api_endpoints_in_html": api_from_html[:20], "api_endpoints_in_inline_js": api_from_inline[:20]},
            "instructions": "如果有 js_files，用 fetch_js 下载分析获取更多隐藏接口。如果有 api_endpoints，加入测试列表。",
        }, indent=2, ensure_ascii=False)

    async def _fetch_js(self, inp: dict, on_thought) -> str:
        urls = inp.get("urls", [])[:50]  # 一次最多 50 个 JS 文件
        if on_thought: on_thought("action", f"📦 分析 {len(urls)} 个 JS 文件...")

        extractor = JsApiExtractor()
        all_endpoints, all_secrets, scanned = [], [], 0
        new_endpoints = 0

        for js_url in urls:
            try:
                resp = await self.http.get(js_url)
                js_content = resp.text
                result = extractor.extract(js_content, js_url)
                all_endpoints.extend(result.api_endpoints)
                all_endpoints.extend(result.base_urls)
                all_endpoints.extend(result.web_services)
                all_secrets.extend(result.secrets)
                scanned += 1

                # ── 自定义 API 规则 ──
                custom_eps = self._apply_custom_api_patterns(js_content)
                all_endpoints.extend(custom_eps)

                # 注册提取到的端点
                for ep in set(result.api_endpoints + result.base_urls + result.web_services + custom_eps):
                    if ep and self._register_endpoint("?", ep, "JS提取"):
                        new_endpoints += 1

                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                self._enrich_single_response(url=js_url, method="GET", resp_body=js_content, resp_headers=resp_headers)
            except Exception:
                continue

        enrichment = {"secrets": all_secrets, "hae_matches": [], "fuzz_dictionary": self._dict_stats()}
        action_items = self._build_action_items(new_endpoints, enrichment)
        stats = self._get_endpoint_stats()
        untested = self._get_untested_endpoints()

        if self.on_endpoint:
            for ep in untested[:30]: self.on_endpoint(ep["method"], ep["path"], ep["source"])

        return json.dumps({
            "summary": f"分析 {scanned} 个 JS 文件 — 提取 {len(set(all_endpoints))} 个新端点, {len(all_secrets)} 个密钥",
            "action_items": action_items,
            "endpoint_stats": stats,
            "untested_endpoints": untested[:30],
            "total_untested": len(untested),
            "details": {"api_endpoints": list(set(all_endpoints))[:60], "secrets": all_secrets[:20]},
            "instructions": "检查 secrets 中是否有应上报的凭证。对 untested_endpoints 中的新接口逐个用 send_request 测试。",
        }, indent=2, ensure_ascii=False)

    async def _send_request(self, inp: dict, on_thought) -> str:
        method = inp["method"]
        url_str = inp["url"]
        headers = inp.get("headers", {})
        body = inp.get("body")
        desc = inp.get("modification_desc", "")

        if method.upper() in self.DANGEROUS_METHODS and self.confirm_dangerous \
                and not self._is_safe_operation(url_str):
            approved = await self.confirm_dangerous(method, url_str, desc)
            if not approved:
                return json.dumps({"error": "Operation rejected by user", "status": -1}, indent=2, ensure_ascii=False)

        path = urlparse(url_str).path
        if on_thought: on_thought("action", f"📤 {method} {path} — {desc}")

        # ── 记录测试活动 ──
        self._record_test_activity(path, method, f"{method} {desc}", "")

        try:
            resp = await self.http.request(method=method, url=url_str, headers=headers, content=body)
            resp_body = resp.text[:3000]
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            enrichment = self._enrich_single_response(
                url=url_str, method=method, resp_body=resp_body, resp_headers=resp_headers,
                req_body=body or "", req_headers={k.lower(): v for k, v in headers.items()},
            )

            new_secrets = enrichment.get("secrets", [])
            new_hae = enrichment.get("hae_matches", [])

            action_items = {}
            if new_secrets:
                criticals = [s for s in new_secrets if s["severity"] in ("critical", "high")]
                if criticals:
                    action_items["new_secrets_in_response"] = [
                        {"severity": s["severity"], "rule": s["rule"], "value": s["value"][:100],
                         "action": f"report_finding — {s['rule']} 泄露"}
                        for s in criticals[:5]
                    ]
            fingerprints = [m for m in new_hae if m["group"] == "指纹识别"]
            if fingerprints:
                action_items["fingerprints_in_response"] = [
                    {"rule": f["rule"], "action": _fingerprint_action(f["rule"])} for f in fingerprints[:5]
                ]

            return json.dumps({
                "status": resp.status_code,
                "body_preview": resp_body[:500],
                "body_length": len(resp.text),
                "request_desc": desc,
                "action_items": action_items if action_items else None,
                "enrichment": {"secrets_count": len(new_secrets), "hae_matches_count": len(new_hae)},
            }, indent=2, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": str(e), "status": -1}, indent=2, ensure_ascii=False)

    def _get_pending_work(self, inp: dict, on_thought) -> str:
        """返回待办清单 — 端点按风险评分排序，附带测试建议和指纹跟进URL。"""
        untested = self._get_untested_endpoints()
        stats = self._get_endpoint_stats()
        dict_stats = self._dict_stats()

        # 打分 + 排序
        for ep in untested:
            ep["priority_score"] = self._score_endpoint(ep)
            ep["suggested_tests"] = self._suggested_tests(ep, dict_stats)
        untested.sort(key=lambda e: e["priority_score"], reverse=True)

        # 指纹跟进 URL
        fp_actions = []
        for fp in self._pending_fingerprints[:10]:
            urls = _fingerprint_urls(fp["rule"], fp.get("value", ""))
            if urls:
                fp_actions.append({"fingerprint": fp["rule"], "urls_to_check": urls,
                                   "action": _fingerprint_action(fp["rule"])})

        # 隐藏参数发现建议
        top_params = dict_stats.get("top_params", [])
        param_hint = ""
        if top_params:
            param_hint = (
                f"CaA字典高频参数: {', '.join(top_params[:15])}。"
                f"测试每个端点时，尝试在URL query或POST body中添加这些参数名（值随意），可能发现隐藏功能。"
            )

        if on_thought:
            high = sum(1 for ep in untested if ep.get("priority_score", 0) >= 5)
            on_thought("action",
                       f"📋 待测: {len(untested)} 个 ({high} 个高风险), "
                       f"{len(self._pending_secrets)} 密钥待上报, "
                       f"{len(self._pending_fingerprints)} 指纹待跟进")

        return json.dumps({
            "endpoint_stats": stats,
            "endpoints_by_priority": [
                {"method": ep["method"], "path": ep["path"], "source": ep["source"],
                 "priority_score": ep["priority_score"],
                 "suggested_tests": ep["suggested_tests"]}
                for ep in untested
            ],
            "high_priority_count": sum(1 for ep in untested if ep.get("priority_score", 0) >= 5),
            "pending_secrets": self._pending_secrets[:50],
            "fingerprint_auto_actions": fp_actions,
            "pending_vuln_clues": self._pending_vuln_clues[:20],
            "fuzz_dictionary": dict_stats,
            "param_discovery_hint": param_hint,
            "recommended_next": [
                f"1. 上报 {len(self._pending_secrets)} 个凭证泄露 (如有) — 用 report_finding",
                f"2. 测试 {len(untested)} 个待测端点，从 priority_score 最高的开始",
                f"3. 每个端点先跑 suggested_tests 里的建议",
                f"4. 用 get_fuzz_dictionary('params') 拿高频参数做参数发现",
                f"5. 跟进 fingerprint_auto_actions 中的指纹URL",
            ],
        }, indent=2, ensure_ascii=False)

    def _lookup_params(self, inp: dict, on_thought) -> str:
        """查询指定接口在 Burp 流量中的参数和凭证。支持模糊匹配。"""
        path = inp.get("path", "").rstrip("/") or "/"
        norm = path.lower().rstrip("/")

        # 精确匹配
        if path in self._param_store:
            store = self._param_store[path]
            return json.dumps(self._fmt_param_store(store, path), indent=2, ensure_ascii=False)

        # 模糊匹配
        matches = []
        for k, v in self._param_store.items():
            kn = k.lower().rstrip("/")
            # 同路径不同大小写
            if kn == norm:
                matches.append((k, v, 10))
            # 路径包含
            elif norm in kn or kn in norm:
                score = len(set(norm.split("/")) & set(kn.split("/"))) * 2
                if score > 0:
                    matches.append((k, v, score))

        if matches:
            matches.sort(key=lambda x: x[2], reverse=True)
            result = {"lookup_path": path, "exact_match": False, "similar_endpoints": []}
            for mk, mv, score in matches[:5]:
                result["similar_endpoints"].append(self._fmt_param_store(mv, mk))
            if on_thought:
                on_thought("action", f"🔍 {path}: {len(matches)} 个相似端点")
            return json.dumps(result, indent=2, ensure_ascii=False)

        return json.dumps({"lookup_path": path, "found": False,
                           "message": "该接口在 Burp 流量中没有记录。试试 get_fuzz_dictionary('params') 获取全局高频参数。"},
                          indent=2, ensure_ascii=False)

    @staticmethod
    def _fmt_param_store(store: dict, path: str) -> dict:
        """格式化参数存储为 Agent 可读的结构。"""
        params = {}
        for pname, pvals in store.get("params", {}).items():
            unique = list(dict.fromkeys(pvals))[:5]  # 去重，最多5个样本值
            params[pname] = {"sample_values": unique, "count": len(pvals)}
        return {
            "path": path,
            "method": store.get("method", "?"),
            "full_url": store.get("full_url", ""),
            "params": params,
            "headers": {k: v[:200] for k, v in store.get("headers", {}).items()},
            "usage_hint": "用 send_request 重放时，把这些 params 和 headers 带上。"
        }

    def _get_fuzz_dictionary(self, inp: dict, on_thought) -> str:
        category = inp.get("category", "params")
        top_n = inp.get("top_n", 30)
        valid = {"params", "paths", "values", "files", "full_paths"}
        if category not in valid:
            return json.dumps({"error": f"Invalid category. Choose from: {', '.join(sorted(valid))}"}, indent=2)

        payloads = self._fuzz_dict_builder.dictionary.to_payload_list(category, top_n)
        if on_thought: on_thought("action", f"📖 CaA字典 {category}: {len(payloads)} 条")

        return json.dumps({
            "category": category, "top_n": top_n,
            "payloads": payloads,
            "usage_hint": _dict_usage_hint(category),
        }, indent=2, ensure_ascii=False)

    def _mark_endpoint(self, inp: dict, on_thought) -> str:
        path = inp["path"]; method = inp["method"]; status = inp["status"]; note = inp["note"]
        key = f"{method}:{path}"
        if key in self._endpoints:
            if status in ("done", "skipped"):
                self._endpoints[key]["tested"] = True
                self._endpoints[key]["result"] = status
                self._endpoints[key]["note"] = note
            else:
                self._endpoints[key]["tested"] = False
            # ── 记录到测试历史 ──
            self._record_test_activity(path, method, f"标记: {status}", note)

        if self.on_mark_endpoint: self.on_mark_endpoint(path, method, status, note)
        stats = self._get_endpoint_stats()
        labels = {"done": "✅已测", "skipped": "⏭跳过", "testing": "🔄测试中"}
        if on_thought: on_thought("action", f"{labels.get(status, status)} {method} {path}: {note}")

        return json.dumps({
            "marked": f"{method} {path} → {status}",
            "endpoint_stats": stats,
            "remaining": stats["pending"],
        }, indent=2, ensure_ascii=False)

    def _report_finding(self, inp: dict, on_thought) -> str:
        if on_thought: on_thought("finding", f"[{inp.get('severity', '?').upper()}] {inp.get('title', '')}", inp)
        # ── 关联到当前正在测的端点 ──
        finding = {"title": inp.get("title", ""), "severity": inp.get("severity", ""),
                   "type": inp.get("attack_type", "")}
        # 找到最近有活动的端点
        for key, ev in sorted(self._endpoints.items(), key=lambda x: len(x[1].get("test_history", [])), reverse=True):
            if ev.get("test_history"):
                ev.setdefault("findings", []).append(finding)
                break
        return json.dumps({"recorded": inp.get("title", ""), "severity": inp.get("severity", ""),
                           "status": "✅ 已记录"}, indent=2, ensure_ascii=False)

    def _report_noise(self, inp: dict, on_thought) -> str:
        if on_thought: on_thought("noise", f"[{inp.get('category', '?')}] {inp.get('title', '')}", inp)
        return json.dumps({"recorded": inp.get("title", ""), "status": "📝 已记入噪音"}, indent=2, ensure_ascii=False)

    def _task_done(self, inp: dict, on_thought) -> str:
        stats = self._get_endpoint_stats()
        untested = self._get_untested_endpoints()

        if stats["pending"] > 0:
            # 拒绝收工，列出剩余端点
            high_risk = [ep for ep in untested if self._score_endpoint(ep) >= 3]
            msg = (
                f"❌ 无法结束测试：还有 {stats['pending']} 个接口未测试"
                f"（共 {stats['total']} 个，已测 {stats['tested']} 个）。\n\n"
            )
            if high_risk:
                msg += f"其中 {len(high_risk)} 个值得关注：\n"
                for ep in high_risk[:10]:
                    msg += f"  - {ep['method']} {ep['path']} (评分:{ep.get('_score', self._score_endpoint(ep))})\n"
                if len(high_risk) > 10:
                    msg += f"  ... 还有 {len(high_risk)-10} 个\n"
            msg += "\n用 get_pending_work 查看完整待测清单，所有接口标记为 done/skipped 后再 task_done。"
            if on_thought:
                on_thought("error", f"拒绝收工: {stats['pending']} 个接口未测")
            return json.dumps({"error": "pending_endpoints_remaining", "endpoint_stats": stats,
                               "high_risk_remaining": len(high_risk),
                               "message": msg}, indent=2, ensure_ascii=False)

        if on_thought: on_thought("done", f"渗透测试完成: {inp.get('summary', '')} — 端点 {stats['tested']}/{stats['total']}", inp)
        return json.dumps({"status": "done", "summary": inp.get("summary", ""), "endpoint_stats": stats}, indent=2, ensure_ascii=False)

    def load_burp_traffic(self, records: list[dict]):
        for r in records:
            host = r.get("host", "")
            if host not in self._burp_traffic_cache:
                self._burp_traffic_cache[host] = []
            self._burp_traffic_cache[host].append(r)
            self._register_endpoint(r.get("method", "GET"), r.get("path", "/"), "外部导入")
        self._enrich_traffic_batch(records)

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


# ═══════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════

def _fingerprint_action(rule_name: str) -> str:
    """根据 HaE 指纹给出测试建议。"""
    actions = {
        "Shiro": "send_request — 测试 Shiro rememberMe 反序列化 (CVE-2016-4437)",
        "JWT": "send_request — 测试 JWT none algorithm / 弱密钥",
        "Swagger": "send_request — 访问 Swagger/OpenAPI 文档，检查 API 泄露",
        "Druid": "send_request — 访问 Druid 监控面板，可能泄露 session/数据源",
        "调试参数": "send_request — 测试 debug/test/admin 参数是否开启调试模式",
    }
    return actions.get(rule_name, f"send_request — 针对 {rule_name} 进行深入测试")


def _fingerprint_urls(rule_name: str, value: str = "") -> list[dict]:
    """根据 HaE 指纹生成自动跟进 URL 列表。Agent 可以直接 send_request 这些 URL。"""
    # 尝试从 value 中提取域名
    host = ""
    import re as _re2
    m = _re2.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', value)
    if m:
        host = f"https://{m.group(1)}"

    if rule_name == "Swagger":
        return [
            {"method": "GET", "url": f"{host}/swagger-ui.html", "desc": "Swagger UI"},
            {"method": "GET", "url": f"{host}/swagger-ui/index.html", "desc": "Swagger UI (alt)"},
            {"method": "GET", "url": f"{host}/v2/api-docs", "desc": "OpenAPI v2 spec"},
            {"method": "GET", "url": f"{host}/v3/api-docs", "desc": "OpenAPI v3 spec"},
            {"method": "GET", "url": f"{host}/swagger-resources", "desc": "Swagger resources"},
        ]
    elif rule_name == "Druid":
        return [
            {"method": "GET", "url": f"{host}/druid/index.html", "desc": "Druid 主页"},
            {"method": "GET", "url": f"{host}/druid/websession.html", "desc": "Druid Session"},
            {"method": "GET", "url": f"{host}/druid/sql.html", "desc": "Druid SQL 控制台"},
            {"method": "GET", "url": f"{host}/druid/datasource.html", "desc": "Druid 数据源"},
        ]
    elif rule_name == "Shiro":
        return [
            {"method": "GET", "url": f"{host}/", "desc": "检查 Set-Cookie: rememberMe=deleteMe"},
        ]
    elif rule_name == "JWT":
        return [
            {"method": "GET", "url": f"{host}/.well-known/jwks.json", "desc": "JWKS 公钥端点"},
        ]
    return []


def _vuln_clue_action(rule_name: str) -> str:
    """根据 HaE 漏洞线索给出测试建议。"""
    actions = {
        "上传表单": "send_request — 测试文件上传漏洞 (webshell, 后缀绕过)",
        "URL 参数值": "send_request — 尝试替换为内网地址/evil.com 测试 SSRF/开放重定向",
        "DoS 参数": "send_request — 测试大数值/负数/0 是否触发异常",
        "Java 反序列化": "send_request — 测试 Java 反序列化 (ysoserial payload)",
        "302 跳转": "send_request — 测试开放重定向 (替换 Location 目标)",
    }
    return actions.get(rule_name, f"send_request — 验证 {rule_name}")


def _dict_usage_hint(category: str) -> str:
    hints = {
        "params": "用这些高频参数名去尝试隐藏参数/参数爆破。对每个端点尝试添加不在当前请求中的高频参数。",
        "paths": "用这些路径段做路径爆破/目录扫描。特别是 admin/test/debug 等敏感路径。",
        "values": "用这些高频值替换请求中的参数值，测试不同输入场景。",
        "files": "访问这些文件路径，可能有信息泄露。",
        "full_paths": "直接访问这些完整路径，发现未在流量中直接出现的接口。",
    }
    return hints.get(category, "")


import asyncio  # noqa: E402 — needed for iscoroutinefunction check in execute()


def _looks_like_api(path: str) -> bool:
    return any(ind in path.lower() for ind in
               ["/api/", "/v1/", "/v2/", "/v3/", ".json", ".do", ".action", ".ajax", "graphql", "query", "mutation"])


def _extract_api_from_js(js_code: str) -> list[str]:
    endpoints = set()
    patterns = [
        r'''(?:fetch|axios\.\w+|get|post|put|delete|patch)\s*\(\s*["'`](/[^"'\s`]{2,})["'`]''',
        r'''["'`](/api/[^"'\s]{2,})["'`]''',
        r'''["'`](/v\d/[^"'\s]{2,})["'`]''',
        r'''baseURL\s*:\s*["'`]([^"'\s]{2,})["'`]''',
        r'''["'`](\/[a-zA-Z][a-zA-Z0-9_\-/]{2,})["'`]''',
        r'''(?:\$http\.\w+|\$resource)\s*\(\s*["'`](/[^"'\s]{2,})["'`]''',
        r'''wx\.request\s*\(\s*\{[^}]*url\s*:\s*["'`]([^"'\s]{2,})["'`]''',
    ]
    for pat in patterns:
        for m in re.finditer(pat, js_code, re.IGNORECASE):
            path = m.group(1)
            if not path.endswith((".js", ".css", ".png", ".jpg", ".woff", ".ttf")):
                endpoints.add(path)
    return sorted(endpoints)[:50]
