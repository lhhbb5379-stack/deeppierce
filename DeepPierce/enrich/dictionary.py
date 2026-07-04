"""Fuzz 字典构建器 — CaA 风格，从 HTTP 流量中提取参数/路径/值用于构建 Fuzz 字典。

整合 CaA 的核心设计:
- 从流量自动提取参数名、路径段、文件名、参数值
- 按频次排序，去重
- 生成 Intruder 风格的 payload 字典
- 支持 JSON 递归遍历 (CaA 的 JsonTraverser)
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs


@dataclass
class FuzzDictionary:
    """从流量中提取的 Fuzz 字典。"""
    params: Counter = field(default_factory=Counter)          # 参数名 → 出现次数
    paths: Counter = field(default_factory=Counter)           # 路径段 → 出现次数
    files: Counter = field(default_factory=Counter)           # 文件名 → 出现次数
    full_paths: Counter = field(default_factory=Counter)      # 完整路径 → 出现次数
    values: Counter = field(default_factory=Counter)          # 参数值 → 出现次数
    hosts: Counter = field(default_factory=Counter)           # 主机名 → 出现次数

    def to_payload_list(self, category: str = "params", top_n: int = 100) -> list[str]:
        """导出为 payload 列表（可直接导入 Intruder）。

        Args:
            category: params / paths / files / full_paths / values
            top_n: 取前 N 条
        """
        counter = getattr(self, category, self.params)
        return [item for item, _ in counter.most_common(top_n)]

    def merge(self, other: FuzzDictionary):
        """合并另一个字典。"""
        self.params.update(other.params)
        self.paths.update(other.paths)
        self.files.update(other.files)
        self.full_paths.update(other.full_paths)
        self.values.update(other.values)
        self.hosts.update(other.hosts)


class FuzzDictionaryBuilder:
    """CaA 风格的字典构建器。

    从 HTTP 请求/响应中提取:
    1. 参数名 (URL query + POST body + JSON body + Cookies + XML)
    2. 路径段 (分割 URL path)
    3. 文件名 (带扩展名的路径段)
    4. 参数值 (从请求和 JSON 响应中提取)
    5. 主机名
    """

    # 排除的文件后缀 (对标 CaA 的 ExcludeSuffix)
    EXCLUDED_SUFFIXES = {
        "css", "js", "jpg", "jpeg", "png", "gif", "svg", "ico", "bmp",
        "woff", "woff2", "ttf", "eot", "otf",
        "mp4", "mp3", "webm", "ogg", "wav",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "zip", "tar", "gz", "rar", "7z",
        "map", "chunk", "bundle",
    }

    def __init__(self):
        self._dict = FuzzDictionary()
        self._seen_urls: set[str] = set()  # 去重

    @property
    def dictionary(self) -> FuzzDictionary:
        return self._dict

    def process_exchange(
        self,
        url: str,
        method: str = "GET",
        request_body: str | None = None,
        request_content_type: str | None = None,
        request_headers: dict[str, str] | None = None,
        response_body: str | None = None,
        response_content_type: str | None = None,
    ):
        """处理一个 HTTP 交换（请求-响应对）。

        Args:
            url: 完整 URL
            method: HTTP 方法
            request_body: 请求体
            request_content_type: 请求 Content-Type
            request_headers: 请求头
            response_body: 响应体
            response_content_type: 响应 Content-Type
        """
        # 去重
        req_key = f"{method}:{url}"
        if req_key in self._seen_urls:
            return
        self._seen_urls.add(req_key)

        parsed = urlparse(url)

        # 1. 提取主机名
        if parsed.hostname:
            self._dict.hosts[parsed.hostname] += 1

        # 2. 提取路径段和文件名
        self._extract_path_components(parsed.path)

        # 3. 提取 URL 查询参数
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in params.items():
                if self._is_valid_param(name):
                    self._dict.params[name] += 1
                    for v in values:
                        if v and len(v) < 200:
                            self._dict.values[v] += 1

        # 4. 提取请求体参数
        if request_body and request_content_type:
            self._extract_body_params(request_body, request_content_type)

        # 5. 提取 Cookie 参数
        if request_headers:
            cookie = request_headers.get("cookie", "") or request_headers.get("Cookie", "")
            if cookie:
                for part in cookie.split(";"):
                    if "=" in part:
                        name = part.split("=", 1)[0].strip()
                        if self._is_valid_param(name):
                            self._dict.params[name] += 1

        # 6. 从响应 JSON 提取 key 作为潜在参数
        if response_body and response_content_type and "json" in response_content_type.lower():
            self._extract_json_keys(response_body)

    def _extract_path_components(self, path: str):
        """提取路径组件。"""
        if not path:
            return

        # 完整路径
        self._dict.full_paths[path] += 1

        # 分割
        segments = [s for s in path.split("/") if s]
        for seg in segments:
            if "." in seg and not seg.startswith("."):
                ext = seg.rsplit(".", 1)[-1].lower()
                if ext not in self.EXCLUDED_SUFFIXES:
                    self._dict.files[seg] += 1
            else:
                self._dict.paths[seg] += 1

    def _extract_body_params(self, body: str, content_type: str):
        """从请求体提取参数。"""
        content_type = content_type.split(";")[0].strip().lower()

        if "json" in content_type:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    self._traverse_json(data, self._on_json_key_value)
            except (json.JSONDecodeError, TypeError):
                pass

        elif "x-www-form-urlencoded" in content_type:
            params = parse_qs(body, keep_blank_values=True)
            for name, values in params.items():
                if self._is_valid_param(name):
                    self._dict.params[name] += 1
                    for v in values:
                        if v and len(v) < 200:
                            self._dict.values[v] += 1

        elif "xml" in content_type:
            # 简单 XML 参数提取
            for m in re.finditer(r'<(\w+)[^>]*>([^<]*)</\1>', body):
                name, value = m.group(1), m.group(2)
                if self._is_valid_param(name):
                    self._dict.params[name] += 1
                if value and len(value) < 200:
                    self._dict.values[value] += 1

    def _extract_json_keys(self, body: str):
        """从 JSON 响应中提取所有 key（作为可能的参数名）。"""
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                self._traverse_json(data, self._on_json_key)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        self._traverse_json(item, self._on_json_key)
        except (json.JSONDecodeError, TypeError):
            pass

    def _traverse_json(self, obj: Any, callback, max_depth: int = 10):
        """JSON 递归遍历（对标 CaA 的 JsonTraverser）。

        用栈实现，避免递归过深。
        """
        stack = [(obj, 0)]
        visited = set()

        while stack:
            current, depth = current_obj, current_depth = stack.pop()
            if depth > max_depth:
                continue

            obj_id = id(current)
            if obj_id in visited:
                continue
            visited.add(obj_id)

            if isinstance(current, dict):
                for key, value in current.items():
                    callback(key, value)
                    if isinstance(value, (dict, list)):
                        stack.append((value, depth + 1))
            elif isinstance(current, list):
                for item in current:
                    if isinstance(item, (dict, list)):
                        stack.append((item, depth + 1))

    def _on_json_key_value(self, key: str, value: Any):
        """JSON key-value 回调（用于请求 body）。"""
        if self._is_valid_param(key):
            self._dict.params[key] += 1
        if isinstance(value, str) and 1 < len(value) < 200:
            self._dict.values[value] += 1

    def _on_json_key(self, key: str, value: Any):
        """JSON key 回调（用于响应 body，只收 key）。"""
        if self._is_valid_param(key):
            self._dict.params[key] += 1

    @staticmethod
    def _is_valid_param(name: str) -> bool:
        """检查参数名是否有效（对标 CaA 的参数过滤）。"""
        if not name or len(name) > 128:
            return False
        # 只允许字母数字、下划线、短横线、点
        return bool(re.match(r'^[\w\-\.]+$', name))
