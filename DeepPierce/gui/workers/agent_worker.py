"""Agent Worker — 在后台线程运行 Agent，通过信号通知 GUI。"""

from __future__ import annotations

import asyncio
import traceback
from typing import Any

from PySide6.QtCore import QObject, Signal

from DeepPierce.agent.agent import FuzzAgent
from DeepPierce.config import Config
from DeepPierce.models import AgentThought


class AgentWorker(QObject):
    """后台运行 FuzzAgent，通过 Qt 信号更新 GUI。"""

    thought_emitted = Signal(AgentThought)
    finding_found = Signal(dict)
    noise_found = Signal(dict)
    endpoint_discovered = Signal(dict)
    progress_update = Signal(int, int, int)
    finished = Signal(dict)
    error_occurred = Signal(str)
    agent_paused_on_error = Signal(str)  # Agent 异常暂停，可继续
    confirm_required = Signal(str, str, str, dict)
    endpoint_status_updated = Signal(str, str, str, str)  # path, method, status, note
    test_activity = Signal(str, str, str)  # path, method, action — send_request 活动

    def __init__(self, config: Config, target_url: str):
        super().__init__()
        self._config = config
        self._target_url = target_url
        self._agent: FuzzAgent | None = None
        self._cancelled = False
        self._paused = False
        self._burp_records: list[dict] = []
        self._pre_endpoints: list[tuple[str, str, str]] = []  # (method, path, source)
        self._confirm_result: bool = False
        self._confirm_event: asyncio.Event | None = None

    @property
    def is_paused(self) -> bool:
        return self._paused

    def pause(self):
        self._paused = True
        if self._agent:
            self._agent.pause()

    def resume(self):
        self._paused = False
        if self._agent:
            self._agent.resume()

    def cancel(self):
        self._cancelled = True
        if self._agent:
            self._agent.cancel()

    def continue_after_error(self):
        """用户点击「继续」后，恢复 Agent 测试。"""
        self._cancelled = False
        if self._agent:
            self._agent._cancelled = False
            self._agent._error_occurred = False
            # 注入"继续"提示
            self._agent._messages.append({
                "role": "user",
                "content": "继续测试。刚才出错了，请从上次中断的地方继续，不要重复已经做过的测试。"
            })

    def set_confirm_result(self, approved: bool):
        self._confirm_result = approved
        if self._confirm_event:
            self._confirm_event.set()

    def load_burp_traffic(self, records: list[dict]):
        self._burp_records.extend(records)
        if self._agent:
            self._agent.load_burp_traffic(records)

    def pre_register_endpoints(self, endpoints: list[tuple[str, str, str]]):
        """预注册端点（从 JS 文件预处理提取），Agent 启动后立即可见。"""
        self._pre_endpoints.extend(endpoints)
        if self._agent:
            for method, path, source in endpoints:
                self._agent.tools._register_endpoint(method, path, source)

    def run(self):
        asyncio.run(self._run_agent())

    async def _run_agent(self):
        try:
            await self._do_run()
        except Exception as e:
            self.agent_paused_on_error.emit(f"第 {self._agent._round_count if self._agent else '?'} 轮出错: {e}")

    async def _do_run(self):
        self._agent = FuzzAgent(config=self._config)

        if self._burp_records:
            self._agent.load_burp_traffic(self._burp_records)

        # ── 预注册 JS 提取端点 ──
        if self._pre_endpoints:
            for method, path, source in self._pre_endpoints:
                self._agent.tools._register_endpoint(method, path, source)

        # 桥接 Agent 思考到 GUI — 保留 endpoint_path 关联
        original_emit = self._agent._emit_thought

        def gui_emit(thought_type, content, detail=None, endpoint_path=""):
            thought = AgentThought(
                type=thought_type, content=content, detail=detail,
                endpoint_path=endpoint_path or self._agent._current_ep_path,
            )
            self.thought_emitted.emit(thought)

            # ── send_request 活动同步到端点列表 ──
            if thought_type == "action" and "📤" in content:
                from urllib.parse import urlparse
                import re
                m = re.match(r'📤\s*(\w+)\s+(/\S*)', content)
                if m:
                    act_method, act_path = m.group(1), m.group(2)
                    desc = content.split(" — ")[-1] if " — " in content else content
                    self.test_activity.emit(act_path, act_method, desc)

            # 统计进度
            ep_count = sum(1 for t in self._agent.thoughts if t.type == "action" and
                          any(kw in t.content for kw in ["爬取", "接口", "端点", "API", "发现"]))
            f_count = len(self._agent.findings)
            self.progress_update.emit(ep_count, f_count, len(self._agent.thoughts))

        self._agent._emit_thought = gui_emit

        # 桥接接口发现到 GUI
        def on_endpoint(method, path, source):
            self.endpoint_discovered.emit({
                "method": method, "path": path, "source": source,
            })

        self._agent.tools.on_endpoint = on_endpoint

        # 桥接危险操作确认
        async def on_confirm_dangerous(method, url, desc):
            self.confirm_required.emit(method, url, desc, {
                "method": method, "url": url, "desc": desc,
            })
            return False

        self._agent.tools.confirm_dangerous = on_confirm_dangerous

        self._agent.tools.on_mark_endpoint = lambda p, m, s, n: self.endpoint_status_updated.emit(p, m, s, n)

        try:
            summary = await self._agent.run(target_url=self._target_url)

            if summary.get("can_continue"):
                self.agent_paused_on_error.emit(
                    f"第 {summary.get('rounds', '?')} 轮时出错，点击「继续」恢复测试"
                )
                return

            self.finished.emit(summary)

            for f in self._agent.findings:
                self.finding_found.emit({
                    "title": f.title,
                    "attack_type": f.attack_type,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "description": f.description,
                    "poc": f.poc,
                    "endpoint": getattr(f, "endpoint", ""),
                })

            for n in self._agent._noise:
                self.noise_found.emit({
                    "title": n.get("title", ""),
                    "category": n.get("category", "?"),
                    "note": n.get("note", ""),
                })
        finally:
            await self._agent.close()
