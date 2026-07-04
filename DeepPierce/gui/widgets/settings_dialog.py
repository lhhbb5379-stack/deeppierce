"""设置对话框 — AI 连接 + Burp 连接，含连通性测试和本地配置导入。"""

from __future__ import annotations

import asyncio
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QPushButton, QSpinBox, QTabWidget, QVBoxLayout, QWidget,
)

from DeepPierce.config import Config
from DeepPierce.agent.prompts import PRESET_TEMPLATES


class _TestWorker(QThread):
    result_ready = Signal(str, bool)

    def __init__(self, test_type: str, config: Config):
        super().__init__()
        self.test_type = test_type
        self.config = config

    def run(self):
        if self.test_type == "ai":
            self._test_ai()
        elif self.test_type == "burp":
            self._test_burp()

    def _test_ai(self):
        try:
            from anthropic import Anthropic
            client_kwargs = {"api_key": self.config.api_key}
            if self.config.api_base_url:
                client_kwargs["base_url"] = self.config.api_base_url
            client = Anthropic(**client_kwargs)
            response = client.messages.create(
                model=self.config.model, max_tokens=10,
                messages=[{"role": "user", "content": "ping"}],
            )
            self.result_ready.emit(f"Connected (model: {response.model})", True)
        except Exception as e:
            msg = str(e)
            if "401" in msg or "unauthorized" in msg.lower():
                self.result_ready.emit("Auth failed - check API key", False)
            elif "404" in msg:
                self.result_ready.emit("Endpoint or model not found", False)
            elif "timeout" in msg.lower() or "connect" in msg.lower():
                self.result_ready.emit("Connection timeout - check network/endpoint", False)
            else:
                self.result_ready.emit(f"Failed: {msg[:120]}", False)

    def _test_burp(self):
        try:
            async def _do():
                from DeepPierce.bridge.burp import BurpMCPClient
                client = BurpMCPClient(self.config.burp_mcp_url)
                await client._ensure_connected()
                records = await client.fetch_proxy_history("", max_items=1)
                await client.close()
                return records
            records = asyncio.run(_do())
            self.result_ready.emit(f"Connected ({len(records)} records visible)", True)
        except Exception as e:
            msg = str(e)
            if "connect" in msg.lower() or "refused" in msg.lower():
                self.result_ready.emit("Cannot connect - is Burp Suite running?", False)
            else:
                self.result_ready.emit(f"Failed: {msg[:120]}", False)


class SettingsDialog(QDialog):
    PROVIDERS = {
        "Anthropic (Claude)": {
            "models": ["claude-opus-4-8", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
            "endpoint": "https://api.anthropic.com",
        },
        "OpenAI (GPT)": {
            "models": ["gpt-4o", "gpt-4-turbo", "gpt-4o-mini"],
            "endpoint": "https://api.openai.com",
        },
        "Custom": {"models": [], "endpoint": ""},
    }

    def __init__(self, config: Config, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置 - DeepPierce")
        self.setMinimumWidth(520)
        self.resize(540, 500)
        self._config = config

        layout = QVBoxLayout(self)
        tabs = QTabWidget()

        # ── AI Tab ──
        ai_tab = QWidget()
        ai_layout = QVBoxLayout(ai_tab)

        ai_group = QGroupBox("AI 提供商")
        ai_form = QFormLayout(ai_group)

        self._provider = QComboBox()
        self._provider.addItems(list(self.PROVIDERS.keys()))
        self._provider.currentTextChanged.connect(self._on_provider)
        ai_form.addRow("提供商:", self._provider)

        self._api_key = QLineEdit()
        self._api_key.setEchoMode(QLineEdit.EchoMode.Password)
        if config.api_key:
            self._api_key.setText(config.api_key)
        ai_form.addRow("API 密钥:", self._api_key)

        self._endpoint = QLineEdit()
        self._endpoint.setPlaceholderText("https://api.anthropic.com")
        if config.api_base_url:
            self._endpoint.setText(config.api_base_url)
        ai_form.addRow("端点:", self._endpoint)

        self._model = QComboBox()
        self._model.setEditable(True)
        self._model.setMinimumWidth(250)
        ai_form.addRow("模型:", self._model)

        self._max_rounds = QSpinBox()
        self._max_rounds.setRange(10, 99999)
        self._max_rounds.setValue(config.max_rounds)
        ai_form.addRow("最大轮次:", self._max_rounds)

        ai_layout.addWidget(ai_group)

        # Import button
        import_row = QHBoxLayout()
        self._import_btn = QPushButton("从本地配置导入...")
        self._import_btn.setToolTip("Supports Claude Code settings.json / .env / YAML")
        self._import_btn.clicked.connect(self._on_import_config)
        import_row.addWidget(self._import_btn)
        self._import_status = QLabel("")
        self._import_status.setStyleSheet("color: #64748b; font-size: 11px;")
        import_row.addWidget(self._import_status, stretch=1)
        ai_layout.addLayout(import_row)

        # Test button
        ai_test_row = QHBoxLayout()
        self._ai_test_btn = QPushButton("测试 AI 连接")
        self._ai_test_btn.clicked.connect(self._test_ai_connection)
        ai_test_row.addWidget(self._ai_test_btn)
        self._ai_test_status = QLabel("")
        self._ai_test_status.setStyleSheet("font-size: 12px; padding: 4px;")
        ai_test_row.addWidget(self._ai_test_status, stretch=1)
        ai_layout.addLayout(ai_test_row)

        tabs.addTab(ai_tab, "AI 连接")

        # ── Agent 定制 Tab ──
        agent_tab = QWidget()
        agent_layout = QVBoxLayout(agent_tab)

        agent_info = QLabel(
            "<b>Agent 行为定制（可选）</b><br><br>"
            "为 AI Agent 指定额外的测试策略与业务上下文。<br>"
            "Agent 始终以「API 接口 Fuzz」为核心，自定义内容为叠加策略。<br>"
            "留空则 Agent 按默认策略执行。"
        )
        agent_info.setWordWrap(True)
        agent_info.setStyleSheet("color: #94a3b8; font-size: 12px; line-height: 1.5;")
        agent_layout.addWidget(agent_info)

        # 预设模板
        preset_row = QHBoxLayout()
        preset_row.addWidget(QLabel("预设模板:"))
        self._preset_combo = QComboBox()
        self._preset_combo.addItems(list(PRESET_TEMPLATES.keys()))
        self._preset_combo.currentTextChanged.connect(self._on_preset_changed)
        preset_row.addWidget(self._preset_combo, stretch=1)
        agent_layout.addLayout(preset_row)

        # 文本框
        self._custom_prompt = QPlainTextEdit()
        self._custom_prompt.setPlaceholderText("示例：重点关注金额篡改和越权；所有 POST 接口测试 Content-Type 切换...")
        self._custom_prompt.setMinimumHeight(150)
        if self._config.agent_custom_prompt:
            self._custom_prompt.setPlainText(self._config.agent_custom_prompt)
            # 检测是否匹配某个预设
            matched = False
            for name, text in PRESET_TEMPLATES.items():
                if text and text.strip() == self._config.agent_custom_prompt.strip():
                    self._preset_combo.setCurrentText(name)
                    matched = True
                    break
            if not matched:
                self._preset_combo.setCurrentText("默认（无定制）")
        agent_layout.addWidget(self._custom_prompt)

        hint = QLabel(
            "<span style='color: #64748b; font-size: 11px;'>"
            "支持：测试方向（IDOR / SQL 注入 / SSRF）、业务上下文（金融 / 社交 / IoT）、"
            "探测策略（保守验证 / 激进探测）、具体规则（参数名 / 路径模式）。"
            "</span>"
        )
        hint.setWordWrap(True)
        agent_layout.addWidget(hint)

        tabs.addTab(agent_tab, "Agent 定制")

        # ── 规则 Tab ──
        rules_tab = QWidget()
        rules_layout = QVBoxLayout(rules_tab)

        rules_info = QLabel(
            "<b>自定义提取规则（可选）</b><br><br>"
            "默认规则已内置，此处可追加自定义规则。留空则仅使用默认规则。<br>"
            "填写格式详见各输入框。"
        )
        rules_info.setWordWrap(True)
        rules_info.setStyleSheet("color: #94a3b8; font-size: 12px; line-height: 1.5;")
        rules_layout.addWidget(rules_info)

        # 接口提取规则（雪瞳风格）
        rules_layout.addWidget(QLabel("<b>接口提取规则</b> — 一行一个正则表达式，用于匹配 JS/HTML 中的 API 路径"))
        self._api_patterns = QPlainTextEdit()
        self._api_patterns.setPlaceholderText(
            "示例:\n"
            "/api/v[0-9]+/.*\n"
            "/service/.*\\.asmx\n"
            "/internal/.*"
        )
        self._api_patterns.setMinimumHeight(80)
        if self._config.custom_api_patterns:
            self._api_patterns.setPlainText(self._config.custom_api_patterns)
        rules_layout.addWidget(self._api_patterns)

        # 敏感信息规则（HaE 风格）
        rules_layout.addWidget(QLabel("<b>敏感信息规则</b> — 一行一条，格式: 名称 | 正则表达式 | 严重程度 | 类别"))
        self._secret_rules = QPlainTextEdit()
        self._secret_rules.setPlaceholderText(
            "示例:\n"
            "自定义密钥|CUSTOM_SECRET_[A-Z0-9]{20}|critical|credential\n"
            "内部令牌|INTERNAL_TOKEN_\\w+|high|credential\n"
            "测试环境地址|test\\.internal\\.com|medium|infrastructure\n"
            "严重程度: critical / high / medium / low / info\n"
            "类别: credential / pii / fingerprint / infrastructure / crypto"
        )
        self._secret_rules.setMinimumHeight(80)
        if self._config.custom_secret_rules:
            self._secret_rules.setPlainText(self._config.custom_secret_rules)
        rules_layout.addWidget(self._secret_rules)

        tabs.addTab(rules_tab, "规则")

        # ── Burp Tab ──
        burp_tab = QWidget()
        burp_layout = QVBoxLayout(burp_tab)

        burp_group = QGroupBox("Burp Suite")
        burp_form = QFormLayout(burp_group)

        self._burp_enabled = QCheckBox("启用 Burp 代理（HTTP 流量经过 Burp）")
        self._burp_enabled.setChecked(config.proxy_enabled)
        burp_form.addRow(self._burp_enabled)

        self._burp_mcp_enabled = QCheckBox("启用 BurpMCP（拉取 Burp 流量历史）")
        self._burp_mcp_enabled.setChecked(config.burp_mcp_enabled)
        burp_form.addRow(self._burp_mcp_enabled)

        self._burp_mcp_url = QLineEdit()
        self._burp_mcp_url.setText(config.burp_mcp_url)
        self._burp_mcp_url.setPlaceholderText("http://127.0.0.1:9876")
        burp_form.addRow("BurpMCP 地址:", self._burp_mcp_url)

        self._burp_proxy = QLineEdit()
        self._burp_proxy.setText(config.burp_proxy)
        self._burp_proxy.setPlaceholderText("http://127.0.0.1:8080")
        burp_form.addRow("HTTP 代理:", self._burp_proxy)

        self._timeout = QSpinBox()
        self._timeout.setRange(5, 60)
        self._timeout.setValue(config.request_timeout)
        self._timeout.setSuffix(" 秒")
        burp_form.addRow("超时:", self._timeout)

        burp_layout.addWidget(burp_group)

        burp_test_row = QHBoxLayout()
        self._burp_test_btn = QPushButton("测试 BurpMCP 连接")
        self._burp_test_btn.clicked.connect(self._test_burp_connection)
        burp_test_row.addWidget(self._burp_test_btn)
        self._burp_test_status = QLabel("")
        self._burp_test_status.setStyleSheet("font-size: 12px; padding: 4px;")
        burp_test_row.addWidget(self._burp_test_status, stretch=1)
        burp_layout.addLayout(burp_test_row)

        tabs.addTab(burp_tab, "Burp 连接")

        layout.addWidget(tabs)
        layout.addWidget(QLabel(f"<span style='color:#64748b;font-size:11px;'>Config: {Config.DEFAULT_CONFIG_PATH}</span>"))

        btn = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn.accepted.connect(self._save)
        btn.rejected.connect(self.reject)
        layout.addWidget(btn)

        self._on_provider(self._provider.currentText())

    def _on_provider(self, name):
        p = self.PROVIDERS.get(name, {"models": [], "endpoint": ""})
        self._model.clear()
        for m in p["models"]:
            self._model.addItem(m)
        if not self._endpoint.text():
            self._endpoint.setText(p.get("endpoint", ""))
        if name == "Anthropic (Claude)":
            self._model.setCurrentText(self._config.model)

    def _on_preset_changed(self, name):
        text = PRESET_TEMPLATES.get(name, "")
        if text:
            self._custom_prompt.setPlainText(text.strip())
        # 如果是"默认"选项，不清空用户已写的内容（防止误操作）
        elif name == "默认（无定制）" and self._custom_prompt.toPlainText().strip():
            # 用户切到默认，保持当前内容，让用户手动清空
            pass

    def _on_import_config(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Config", "",
            "Config (settings.json *.env *.yml);;Claude Code (settings.json);;Env (.env);;YAML (*.yml);;All (*)"
        )
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"Cannot read: {e}")
            return

        imported = {}
        # Claude Code settings.json
        if path.endswith("settings.json") or '"env"' in content[:200]:
            try:
                import json
                data = json.loads(content)
                env = data.get("env", {})
                if env.get("ANTHROPIC_AUTH_TOKEN"): imported["api_key"] = env["ANTHROPIC_AUTH_TOKEN"]
                elif env.get("ANTHROPIC_API_KEY"): imported["api_key"] = env["ANTHROPIC_API_KEY"]
                if env.get("ANTHROPIC_BASE_URL"): imported["api_base_url"] = env["ANTHROPIC_BASE_URL"]
                if env.get("ANTHROPIC_MODEL"): imported["model"] = env["ANTHROPIC_MODEL"]
            except Exception:
                pass
        # .env
        if not imported and "=" in content and not content.strip().startswith("{"):
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"): continue
                if "=" in line:
                    k, _, v = line.partition("=")
                    k = k.strip(); v = v.strip().strip('"').strip("'")
                    if k in ("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY"): imported["api_key"] = v
                    elif k == "ANTHROPIC_BASE_URL": imported["api_base_url"] = v
                    elif k == "ANTHROPIC_MODEL": imported["model"] = v
        # YAML
        if not imported and ":" in content:
            try:
                import yaml
                data = yaml.safe_load(content) or {}
                if isinstance(data, dict):
                    for k in ("api_key", "api_base_url", "model"):
                        if data.get(k): imported[k] = data[k]
            except Exception:
                pass

        if not imported:
            QMessageBox.information(self, "Not Found", "No AI config found in file.")
            return

        if imported.get("api_key"): self._api_key.setText(imported["api_key"])
        if imported.get("api_base_url"): self._endpoint.setText(imported["api_base_url"])
        if imported.get("model"): self._model.setCurrentText(imported["model"])
        parts = [k for k in ["api_key", "api_base_url", "model"] if k in imported]
        self._import_status.setText(f"Imported: {', '.join(parts)}")
        self._import_status.setStyleSheet("color: #10b981; font-size: 11px;")

    def _test_ai_connection(self):
        self._ai_test_btn.setEnabled(False)
        self._ai_test_status.setText("Testing...")
        self._ai_test_status.setStyleSheet("color: #f59e0b; font-size: 12px;")
        tmp = Config(api_key=self._api_key.text(), api_base_url=self._endpoint.text(),
                     model=self._model.currentText() or "claude-sonnet-4-6")
        self._worker = _TestWorker("ai", tmp)
        self._worker.result_ready.connect(self._on_ai_test_result)
        self._worker.start()

    def _on_ai_test_result(self, msg, ok):
        self._ai_test_btn.setEnabled(True)
        self._ai_test_status.setText(msg)
        self._ai_test_status.setStyleSheet(f"color: {'#10b981' if ok else '#ef4444'}; font-size: 12px;")

    def _test_burp_connection(self):
        self._burp_test_btn.setEnabled(False)
        self._burp_test_status.setText("Testing...")
        self._burp_test_status.setStyleSheet("color: #f59e0b; font-size: 12px;")
        tmp = Config(burp_mcp_url=self._burp_mcp_url.text())
        self._worker = _TestWorker("burp", tmp)
        self._worker.result_ready.connect(self._on_burp_test_result)
        self._worker.start()

    def _on_burp_test_result(self, msg, ok):
        self._burp_test_btn.setEnabled(True)
        self._burp_test_status.setText(msg)
        self._burp_test_status.setStyleSheet(f"color: {'#10b981' if ok else '#ef4444'}; font-size: 12px;")

    def _save(self):
        self._config.api_key = self._api_key.text()
        self._config.api_base_url = self._endpoint.text()
        self._config.model = self._model.currentText()
        self._config.burp_mcp_url = self._burp_mcp_url.text()
        self._config.burp_proxy = self._burp_proxy.text()
        self._config.proxy_enabled = self._burp_enabled.isChecked()
        self._config.burp_mcp_enabled = self._burp_mcp_enabled.isChecked()
        self._config.max_rounds = self._max_rounds.value()
        self._config.request_timeout = self._timeout.value()
        self._config.agent_custom_prompt = self._custom_prompt.toPlainText().strip()
        self._config.custom_api_patterns = self._api_patterns.toPlainText().strip()
        self._config.custom_secret_rules = self._secret_rules.toPlainText().strip()
        self._config.save()
        self.accept()

    def get_config(self) -> Config:
        return self._config
