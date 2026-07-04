"""Agent 主循环 — Claude 驱动渗透测试的核心引擎。"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from anthropic import Anthropic

from DeepPierce.agent.prompts import build_system_prompt, SHORT_PROMPT
from DeepPierce.agent.tools import TOOL_DEFINITIONS, ToolExecutor
from DeepPierce.config import Config
from DeepPierce.models import AgentThought, Finding


class FuzzAgent:
    """AI 驱动的渗透测试 Agent。"""

    def __init__(self, config: Config):
        if not config.has_api_key:
            raise ValueError("API key 未设置，Agent 需要 AI 才能运行")

        self.config = config

        client_kwargs = {"api_key": config.api_key}
        if config.api_base_url:
            client_kwargs["base_url"] = config.api_base_url
        self.client = Anthropic(**client_kwargs)

        self.tools = ToolExecutor(
            proxy_url=config.burp_proxy,
            burp_mcp_url=config.burp_mcp_url,
            proxy_enabled=config.proxy_enabled,
            burp_mcp_enabled=config.burp_mcp_enabled,
            custom_api_patterns=config.custom_api_patterns,
            custom_secret_rules=config.custom_secret_rules,
        )

        self._thoughts: list[AgentThought] = []
        self._findings: list[Finding] = []
        self._noise: list[dict] = []
        self._cancelled = False
        self._paused = False
        self._current_ep_path = ""  # 当前正在测试的接口路径
        self._pending_approved_results: list[str] = []  # 用户审批后注入的结果

    @property
    def thoughts(self) -> list[AgentThought]:
        return self._thoughts

    @property
    def findings(self) -> list[Finding]:
        return self._findings

    def cancel(self):
        self._cancelled = True

    def pause(self):
        self._paused = True

    def resume(self):
        self._paused = False

    def load_burp_traffic(self, records: list[dict]):
        self.tools.load_burp_traffic(records)

    def inject_approved_result(self, result_text: str):
        """GUI 调用：用户审批的操作执行完毕后，把结果注入 Agent 对话。"""
        self._pending_approved_results.append(result_text)

    async def run(self, target_url: str) -> dict:
        self._cancelled = False
        self._error_occurred = False
        self._target_url = target_url

        if not hasattr(self, '_messages') or not self._messages:
            # 首次启动
            self._thoughts = []
            self._findings = []
            self._round_count = 0
            self._emit_thought("system", f"🎯 目标: {target_url}")

            user_msg = SHORT_PROMPT.format(target_url=target_url)
            if self.config.burp_mcp_url and self.config.burp_mcp_enabled:
                user_msg += f"\n\nBurpMCP 已配置。目标主机是 {target_url}。先用 fetch_burp_traffic 从 Burp 拉取该域名的已有流量，再爬虫补充。"
            self._messages = [{"role": "user", "content": user_msg}]
        else:
            # 继续之前的会话
            self._emit_thought("system", "🔄 继续测试...")

        round_count = self._round_count
        messages = self._messages
        while not self._cancelled:
            import asyncio
            while self._paused and not self._cancelled:
                await asyncio.sleep(0.5)
            if self._cancelled:
                break

            # ── 轮数上限不终止，注入提示让 Agent 继续 ──
            if round_count >= self.config.max_rounds:
                self._messages = messages
                self._round_count = 0  # 重置，再来一轮
                messages.append({"role": "user", "content": "你已达到最大轮数。请继续测试未完成的接口，不要赶工。用 get_pending_work 确认进度。"})
                self._emit_thought("system", "🔄 轮数上限，自动继续...")
                round_count = 0
                self._messages = messages

            round_count += 1
            self._round_count = round_count
            self._messages = messages

            round_count += 1

            # ── 注入用户审批的操作结果 ──
            if self._pending_approved_results:
                for result in self._pending_approved_results:
                    messages.append({"role": "user", "content": result})
                self._pending_approved_results.clear()

            try:
                response = self.client.messages.create(
                    model=self.config.model,
                    max_tokens=8192,
                    system=build_system_prompt(self.config.agent_custom_prompt),
                    messages=messages,
                    tools=TOOL_DEFINITIONS,
                )
            except Exception as e:
                self._emit_thought("error", f"AI 调用失败: {e}")
                self._error_occurred = True
                # 保存状态以便后续继续
                self._messages = messages
                self._round_count = round_count
                break

            text_content = ""
            tool_uses = []
            for block in response.content:
                if block.type == "text":
                    text_content += block.text
                elif block.type == "tool_use":
                    tool_uses.append(block)

            # ── 文本思考关联到上一个接口上下文 ──
            if text_content.strip():
                self._emit_thought("thinking", text_content.strip())

            if not tool_uses:
                messages.append({"role": "assistant", "content": response.content})
                continue

            messages.append({"role": "assistant", "content": response.content})

            tool_results = []
            for tb in tool_uses:
                # ── 从工具调用中提取接口路径，建立上下文关联 ──
                ep_path = self._extract_endpoint_path(tb)
                if ep_path:
                    self._current_ep_path = ep_path

                # 闭包捕获当前接口路径，让工具内部的 on_thought 自动带上
                captured_path = self._current_ep_path

                def make_on_thought(ep):
                    def wrapper(tt, ct, detail=None):
                        self._emit_thought(tt, ct, detail, endpoint_path=ep)
                    return wrapper

                result_text = await self.tools.execute(
                    tool_name=tb.name,
                    tool_input=tb.input,
                    on_thought=make_on_thought(captured_path),
                )
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tb.id,
                    "content": result_text,
                })

                if tb.name == "report_finding":
                    self._findings.append(Finding(
                        id=str(uuid.uuid4())[:8],
                        title=tb.input.get("title", ""),
                        attack_type=tb.input.get("attack_type", "other"),
                        severity=tb.input.get("severity", "info"),
                        confidence=tb.input.get("confidence", 0.5),
                        description=tb.input.get("description", ""),
                        poc=tb.input.get("poc", ""),
                        endpoint=self._current_ep_path,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))

                if tb.name == "report_noise":
                    self._noise.append({
                        "title": tb.input.get("title", ""),
                        "category": tb.input.get("category", "?"),
                        "note": tb.input.get("note", ""),
                    })

                if tb.name == "task_done":
                    # 检查是否被拒绝（pending 不为 0）
                    import json as _json
                    try:
                        td_result = _json.loads(result_text)
                        if td_result.get("error") == "pending_endpoints_remaining":
                            # 还有未测接口，不退出，让 Agent 看到拒绝消息后继续
                            pass  # 不 break，tool_results 会正常追加到 messages
                        else:
                            messages.append({"role": "user", "content": tool_results})
                            self._cancelled = True
                            break
                    except Exception:
                        # JSON 解析失败也不要终止，继续
                        self._emit_thought("error", "task_done 结果异常，继续测试")
                        pass

            if tool_results:
                messages.append({"role": "user", "content": tool_results})

        summary = {
            "target": target_url,
            "rounds": round_count,
            "total_findings": len(self._findings),
            "error_occurred": self._error_occurred,
            "can_continue": self._error_occurred and not self._cancelled,
            "findings": [
                {"title": f.title, "type": f.attack_type, "severity": f.severity, "confidence": f.confidence}
                for f in self._findings
            ],
        }

        if not self._cancelled:
            self._emit_thought("done", f"完成。{round_count} 轮，发现 {len(self._findings)} 个漏洞。")

        return summary

    @staticmethod
    def _extract_endpoint_path(tb) -> str:
        """从工具调用中提取接口路径。"""
        if tb.name == "send_request":
            url = tb.input.get("url", "")
            return urlparse(url).path if url else ""
        elif tb.name == "mark_endpoint":
            return tb.input.get("path", "")
        return ""

    async def close(self):
        await self.tools.close()

    def _emit_thought(self, thought_type: str, content: str, detail=None, endpoint_path: str = ""):
        self._thoughts.append(AgentThought(
            type=thought_type, content=content, detail=detail,
            endpoint_path=endpoint_path or self._current_ep_path,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ))
