"""Burp 桥接 — MCP SSE 客户端 + 代理发包。

MCP SSE 协议 (BurpMCP-Ultra):
1. GET / → 建立 SSE 长连接，第一条 event: endpoint 返回 ?sessionId=xxx
2. POST /?sessionId=xxx → 发送 JSON-RPC 请求
3. 响应通过 SSE 流返回

参考: /Users/mac/Downloads/Tools/BurpPlugins/BurpMCP-Ultra-main
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx


class BurpMCPClient:
    """通过 BurpMCP 的 SSE 接口拉流量、查站点地图。"""

    def __init__(self, base_url: str = "http://127.0.0.1:9876"):
        self.base_url = base_url.rstrip("/")
        self._request_id = 0
        self._session_id: str | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._sse_task: asyncio.Task | None = None
        self._http: httpx.AsyncClient | None = None

    async def _ensure_connected(self):
        """确保 SSE 连接已建立并获取 session ID。"""
        if self._session_id and self._http:
            return

        self._http = httpx.AsyncClient(timeout=httpx.Timeout(60, read=120))

        # GET / → 获取 SSE 流和 session ID
        resp = await self._http.send(
            self._http.build_request("GET", f"{self.base_url}/"),
            stream=True,
        )

        if resp.status_code != 200:
            raise ConnectionError(f"BurpMCP 连接失败: HTTP {resp.status_code}")

        # 读取 SSE 流的第一条事件获取 session ID
        line_iter = resp.aiter_lines()
        current_event = ""
        async for line in line_iter:
            if line.startswith("data:"):
                data = line[5:].strip()
                if current_event == "endpoint":
                    # data = ?sessionId=xxx 或 /message?sessionId=xxx
                    self._session_id = data.lstrip("/")
                    break
                current_event = ""
            elif line.startswith("event:"):
                current_event = line[6:].strip()

        if not self._session_id:
            raise ConnectionError("BurpMCP: 无法获取 session ID")

        # 后台持续读取 SSE 流
        self._sse_task = asyncio.create_task(self._read_sse(resp, line_iter))

    async def _read_sse(self, response, line_iter):
        """后台读取 SSE 流，解析响应。"""
        current_event = ""
        current_data = ""
        try:
            async for line in line_iter:
                if line.startswith("event:"):
                    current_event = line[6:].strip()
                elif line.startswith("data:"):
                    current_data += line[5:].strip()
                elif line == "" and current_data:
                    # 完整事件
                    try:
                        msg = json.loads(current_data)
                        msg_id = msg.get("id")
                        if msg_id and msg_id in self._pending:
                            self._pending[msg_id].set_result(msg)
                    except json.JSONDecodeError:
                        pass
                    current_event = ""
                    current_data = ""
        except Exception:
            pass  # SSE 流断开（正常或异常）

    async def _call_tool(self, tool_name: str, arguments: dict) -> dict:
        """通过 MCP JSON-RPC 调用 Burp 工具。"""
        await self._ensure_connected()

        self._request_id += 1
        req_id = self._request_id
        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }

        # 创建 Future 等待响应
        future: asyncio.Future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = future

        try:
            # POST JSON-RPC 到 session endpoint
            post_url = f"{self.base_url}/?sessionId={self._session_id.split('=')[-1] if '=' in self._session_id else self._session_id}"
            await self._http.post(post_url, json=payload)

            # 等待 SSE 响应
            result = await asyncio.wait_for(future, timeout=30)

            # 解析 MCP 响应
            if "result" in result:
                r = result["result"]
                if "content" in r and isinstance(r["content"], list):
                    for item in r["content"]:
                        if item.get("type") == "text":
                            try:
                                return json.loads(item.get("text", "{}"))
                            except json.JSONDecodeError:
                                return {"raw_text": item.get("text", "")}
                return r
            elif "error" in result:
                return {"error": result["error"]}
            return {"error": "unexpected_response", "raw": result}

        except asyncio.TimeoutError:
            return {"error": "timeout"}
        finally:
            self._pending.pop(req_id, None)

    async def fetch_proxy_history(self, host: str, max_items: int = 200) -> list[dict]:
        """从 Burp Proxy History 拉取指定主机的流量。"""
        args = {"max_items": max_items}
        if host:
            args["host"] = host

        try:
            result = await self._call_tool("proxy_history", args)
        except Exception:
            return []

        items = result.get("items", [])
        if not isinstance(items, list):
            return []

        return self._parse_items(items, host, "burp")

    async def fetch_sitemap(self, host: str, max_results: int = 100) -> list[dict]:
        """从 Burp Site Map 拉取端点。"""
        try:
            result = await self._call_tool("sitemap_query", {
                "url_prefix": f"https://{host}",
                "max_results": max_results,
            })
        except Exception:
            return []

        # BurpMCP sitemap_query 可能直接返回 list 或 {items: [...]}
        if isinstance(result, list):
            items = result
        elif isinstance(result, dict):
            items = result.get("items", result.get("entries", []))
        else:
            return []

        if not isinstance(items, list):
            return []

        return self._parse_sitemap_items(items, host)

    def _parse_items(self, items: list, default_host: str, source: str) -> list[dict]:
        """统一解析 BurpMCP 返回的 HTTP 记录。"""
        records = []
        for item in items:
            if not isinstance(item, dict):
                continue

            # 获取 URL 和 host
            url = item.get("url", "")
            hostname = item.get("host", "") or urlparse(url).hostname or default_host

            record = {
                "id": f"{source}_{len(records)}",
                "method": item.get("method", "GET"),
                "url": url,
                "host": hostname,
                "path": item.get("path", urlparse(url).path if url else "/"),
                "request_headers": self._parse_headers(item.get("request_headers", item.get("headers", {}))),
                "request_body": item.get("request_body", item.get("body", "")),
                "response_status": item.get("status_code", item.get("response_status", 0)),
                "response_headers": self._parse_headers(item.get("response_headers", {})),
                "response_body": item.get("response_body", ""),
                "source": source,
                "mime_type": item.get("mime_type", item.get("response_mime_type", "")),
                "response_length": item.get("response_length", 0),
            }
            records.append(record)

        return records

    def _parse_sitemap_items(self, items: list, default_host: str) -> list[dict]:
        """解析 BurpMCP sitemap_query 返回的简化格式 (url, method, status_code 等)。"""
        records = []
        for item in items:
            if not isinstance(item, dict):
                continue
            url = item.get("url", "")
            hostname = urlparse(url).hostname or default_host
            records.append({
                "id": f"sitemap_{len(records)}",
                "method": item.get("method", "GET"),
                "url": url,
                "host": hostname,
                "path": urlparse(url).path if url else "/",
                "request_headers": {},
                "request_body": "",
                "response_status": item.get("status_code", 0),
                "response_headers": {},
                "response_body": "",
                "source": "burp_sitemap",
                "mime_type": item.get("mime_type", ""),
                "response_length": item.get("content_length", 0),
            })
        return records

    async def close(self):
        if self._sse_task:
            self._sse_task.cancel()
            self._sse_task = None
        if self._http:
            await self._http.aclose()
            self._http = None
        self._session_id = None

    # ── Helpers ─────────────────────────────────────────────────

    @staticmethod
    def _parse_headers(headers):
        if isinstance(headers, dict):
            return {k.lower(): str(v) for k, v in headers.items()}
        if isinstance(headers, list):
            return {h.get("name", "").lower(): h.get("value", "") for h in headers}
        return {}

    @staticmethod
    def _parse_raw_http(request_str: str, response_str: str, host: str) -> dict:
        """解析 BurpMCP 返回的 raw HTTP 字符串。"""
        lines = request_str.split("\n")
        req_line = lines[0].strip().split(" ") if lines else ["GET", "/"]
        method = req_line[0]
        path = req_line[1] if len(req_line) > 1 else "/"
        url = f"https://{host}{path}" if host else path

        # 简易解析 headers
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "":
                body_start = i + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""

        return {
            "id": f"raw_{hash(request_str) & 0xFFFF}",
            "method": method,
            "url": url,
            "host": host,
            "path": path,
            "request_headers": headers,
            "request_body": body,
            "response_status": 0,
            "response_headers": {},
            "response_body": response_str[:5000] if response_str else "",
            "source": "burp",
        }
