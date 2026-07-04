"""DeepPierce — AI Agent 渗透测试工具主窗口。"""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt, QThread
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPushButton, QSplitter, QStatusBar, QTabWidget,
    QVBoxLayout, QWidget,
)

from DeepPierce.config import Config
from DeepPierce.gui.widgets.agent_log import AgentLogView
from DeepPierce.gui.widgets.findings_table import FindingsTable
from DeepPierce.gui.widgets.endpoint_detail import EndpointDetail
from DeepPierce.gui.widgets.endpoint_list import EndpointList
from DeepPierce.gui.widgets.pending_ops import PendingOpsWidget
from DeepPierce.gui.widgets.settings_dialog import SettingsDialog
from DeepPierce.gui.widgets.noise_table import NoiseTable
from DeepPierce.gui.workers.agent_worker import AgentWorker


def _ask(parent, title, text, buttons=None, default=None):
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(text)
    box.setIcon(QMessageBox.Icon.NoIcon)
    if buttons:
        box.setStandardButtons(buttons)
    if default:
        box.setDefaultButton(default)
    return box.exec()


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DeepPierce — AI Agent")
        self.setMinimumSize(1200, 800)

        self.config = Config.load()
        self._worker: AgentWorker | None = None
        self._worker_thread: QThread | None = None
        self._running = False
        self._all_thoughts: list[dict] = []  # 全量思考缓存，供端点详情筛选

        self._setup_topbar()
        self._setup_central()
        self._setup_statusbar()
        self._connect_signals()

    def _setup_topbar(self):
        """顶部控制栏 — 两行合一，按钮靠右。"""
        bar = QWidget()
        bar.setStyleSheet("background: #111827; padding: 8px 12px; border-bottom: 1px solid #1e293b;")
        root = QVBoxLayout(bar)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)

        # ── 第一行：URL + 按钮 ──
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        row1.addWidget(QLabel("目标 URL:"))
        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText("https://api.example.com ...")
        self._url_input.returnPressed.connect(self._on_start)
        row1.addWidget(self._url_input, stretch=4)

        self._btn_start = QPushButton("开始")
        self._btn_start.setObjectName("primaryBtn")
        self._btn_start.clicked.connect(self._on_start)
        row1.addWidget(self._btn_start)

        self._btn_pause = QPushButton("暂停")
        self._btn_pause.setEnabled(False)
        self._btn_pause.clicked.connect(self._on_pause)
        row1.addWidget(self._btn_pause)

        self._btn_stop = QPushButton("停止")
        self._btn_stop.setEnabled(False)
        self._btn_stop.setObjectName("dangerBtn")
        self._btn_stop.clicked.connect(self._on_stop)
        row1.addWidget(self._btn_stop)

        self._btn_continue = QPushButton("继续")
        self._btn_continue.setEnabled(False)
        self._btn_continue.setObjectName("primaryBtn")
        self._btn_continue.clicked.connect(self._on_continue)
        self._btn_continue.setVisible(False)
        row1.addWidget(self._btn_continue)

        self._btn_settings = QPushButton("设置")
        self._btn_settings.clicked.connect(self._on_settings)
        row1.addWidget(self._btn_settings)
        root.addLayout(row1)

        # ── 第二行：JS 文件（可选） ──
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        row2.addWidget(QLabel("JS 文件:"))
        opt = QLabel("(可选)")
        opt.setStyleSheet("color: #64748b; font-size: 11px;")
        row2.addWidget(opt)

        self._js_path_input = QLineEdit()
        self._js_path_input.setPlaceholderText("/path/to/js/ 或留空跳过...")
        self._js_path_input.textChanged.connect(self._on_js_path_changed)
        row2.addWidget(self._js_path_input, stretch=4)

        self._btn_js_browse = QPushButton("浏览...")
        self._btn_js_browse.clicked.connect(self._on_select_js_dir)
        row2.addWidget(self._btn_js_browse)

        self._js_status = QLabel("")
        self._js_status.setStyleSheet("color: #64748b; font-size: 11px;")
        self._js_status.setMinimumWidth(140)
        row2.addWidget(self._js_status)
        root.addLayout(row2)

        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self._wrap_toolbar(bar))

        self._js_files: list[str] = []

    def _wrap_toolbar(self, widget):
        from PySide6.QtWidgets import QToolBar
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.addWidget(widget)
        tb.layout().setContentsMargins(0, 0, 0, 0)
        return tb

    def _setup_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── 垂直分割：上=主Tabs，下=端点详情面板 ──
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setChildrenCollapsible(False)

        # 上方：主 Tab 区
        self._main_tabs = QTabWidget()
        self._dashboard = self._create_dashboard()
        self._main_tabs.addTab(self._dashboard, "仪表盘")

        self.agent_log = AgentLogView()
        self._main_tabs.addTab(self.agent_log, "思考日志")

        self.endpoint_list = EndpointList()
        self._main_tabs.addTab(self.endpoint_list, "测试清单")

        self.pending_ops = PendingOpsWidget()
        self._main_tabs.addTab(self.pending_ops, "待确认操作")

        self.findings_table = FindingsTable()
        self._main_tabs.addTab(self.findings_table, "漏洞汇总")

        self.noise_table = NoiseTable()
        self._main_tabs.addTab(self.noise_table, "疑点记录")

        splitter.addWidget(self._main_tabs)

        # 下方：端点详情面板（替代原来的 DiffView）
        self.endpoint_detail = EndpointDetail()
        splitter.addWidget(self.endpoint_detail)

        splitter.setSizes([550, 250])
        root.addWidget(splitter)

    def _create_dashboard(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("DeepPierce — AI Agent")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e2e8f0;")
        layout.addWidget(title)

        subtitle = QLabel("输入目标 URL，点击开始。Agent 自动收集信息、分析接口、生成策略、执行模糊测试。")
        subtitle.setStyleSheet("color: #94a3b8; font-size: 13px;")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        self._dash_status = QLabel("状态: 空闲")
        self._dash_status.setStyleSheet("color: #94a3b8; font-size: 14px; padding: 8px 0;")
        layout.addWidget(self._dash_status)

        self._dash_stats = QLabel("接口: 0 | 发现: 0 | 请求: 0")
        self._dash_stats.setStyleSheet("color: #3b82f6; font-size: 24px; font-weight: bold;")
        layout.addWidget(self._dash_stats)
        layout.addStretch()

        tips = QLabel(
            "提示:\n"
            "- 先在浏览器中通过 Burp 代理访问目标，积累流量\n"
            "- Agent 会自动从 Burp 拉取相关流量并分析\n"
            "- 点击下方测试清单中的接口，查看 AI 对该接口的思考分析\n"
            "- POST/PUT/DELETE/PATCH 等危险操作会进入待确认列表"
        )
        tips.setStyleSheet("color: #64748b; font-size: 12px;")
        tips.setWordWrap(True)
        layout.addWidget(tips)
        return w

    def _setup_statusbar(self):
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._status_phase = QLabel("空闲")
        self._status_phase.setStyleSheet("color: #94a3b8; padding: 0 8px; font-weight: bold;")
        self._statusbar.addWidget(self._status_phase)
        self._status_endpoints = QLabel("接口: 0")
        self._statusbar.addWidget(self._status_endpoints)
        self._status_findings = QLabel("发现: 0")
        self._statusbar.addWidget(self._status_findings)
        self._status_requests = QLabel("请求: 0")
        self._statusbar.addWidget(self._status_requests)

    def _connect_signals(self):
        # 端点列表点击 → 底部详情面板
        self.endpoint_list.endpoint_selected.connect(self._on_endpoint_selected)
        # 漏洞列表点击 → 底部详情面板
        self.findings_table.finding_selected.connect(self._on_finding_selected)
        # 疑点列表点击 → 底部详情面板
        self.noise_table.noise_selected.connect(self._on_noise_selected)
        # 待确认操作审批
        self.pending_ops.op_approved.connect(self._on_op_approved)

    def _on_start(self):
        url = self._url_input.text().strip()
        if not url:
            _ask(self, "缺少目标", "请输入目标 URL。")
            return
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "https://" + url
            self._url_input.setText(url)
        if not self.config.has_api_key:
            r = _ask(self, "未配置 AI", "API 密钥未设置，是否现在配置？",
                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                     QMessageBox.StandardButton.Yes)
            if r == QMessageBox.StandardButton.Yes:
                self._on_settings()
            return
        self._start_agent(url)

    def _start_agent(self, target_url: str):
        self._running = True
        self._set_running_state(True)
        self.agent_log.clear()
        self.findings_table.clear()
        self.endpoint_list.clear()
        self.endpoint_detail.clear()
        self.pending_ops.clear()
        self.noise_table.clear()
        self._all_thoughts = []

        # ── 预处理：JS 文件提取 ──
        pre_eps: list[tuple[str, str, str]] = []
        if self._js_files:
            self.agent_log.add("system", f"📦 预处理 {len(self._js_files)} 个 JS 文件，提取隐藏接口...")
            from DeepPierce.crawler.js_extractor import JsApiExtractor
            extractor = JsApiExtractor()
            total_endpoints = 0
            total_secrets = 0
            for fpath in self._js_files:
                try:
                    content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                    result = extractor.extract(content, fpath)
                    for ep in result.api_endpoints + result.base_urls + result.web_services:
                        self.endpoint_list.add_endpoint({"method": "?", "path": ep, "source": "JS文件"})
                        pre_eps.append(("?", ep, "JS文件"))
                        total_endpoints += 1
                    for s in result.secrets:
                        total_secrets += 1
                        if s.get("severity") in ("critical", "high"):
                            self.agent_log.add("finding",
                                f"🔑 JS 密钥泄露 [{s['severity']}]: {s.get('rule', '?')} — {s.get('value', '')[:60]}")
                except Exception as e:
                    self.agent_log.add("error", f"读取 {fpath} 失败: {e}")
            self.agent_log.add("system",
                f"✅ JS 预处理完成: {total_endpoints} 个隐藏接口, {total_secrets} 个密钥")
            if total_endpoints > 0:
                self.agent_log.add("action",
                    f"这 {total_endpoints} 个接口已加入测试清单，Agent 启动后立即可测。"
                    f"JS 提取的接口评分更高，会被优先测试。")

        self._main_tabs.setCurrentIndex(1)  # 切到思考日志

        self._dash_status.setText(f"状态: 运行中 — {target_url}")
        self._dash_status.setStyleSheet("color: #10b981; font-size: 14px; padding: 8px 0;")
        self._status_phase.setText("运行中")

        self._worker = AgentWorker(self.config, target_url)
        self._worker_thread = QThread()
        self._worker.moveToThread(self._worker_thread)

        # ── 预注册 JS 提取的端点 ──
        if pre_eps:
            self._worker.pre_register_endpoints(pre_eps)

        self._worker.thought_emitted.connect(self._on_thought)
        self._worker.finding_found.connect(self._on_finding)
        self._worker.noise_found.connect(self.noise_table.add_noise)
        self._worker.endpoint_discovered.connect(self._on_endpoint_discovered)
        self._worker.progress_update.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.agent_paused_on_error.connect(self._on_paused_error)
        self._worker.confirm_required.connect(self._on_confirm_required)
        self._worker.endpoint_status_updated.connect(self._on_endpoint_status)
        self._worker.test_activity.connect(self._on_test_activity)

        self._worker_thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker.error_occurred.connect(self._worker_thread.quit)
        self._worker_thread.finished.connect(self._on_thread_done)
        self._worker_thread.start()

    def _on_pause(self):
        if not self._worker:
            return
        if self._worker.is_paused:
            self._worker.resume()
            self._btn_pause.setText("暂停")
            self._status_phase.setText("运行中")
        else:
            self._worker.pause()
            self._btn_pause.setText("继续")
            self._status_phase.setText("已暂停")

    def _on_stop(self):
        if not self._worker:
            return
        r = _ask(self, "停止 Agent", "确定停止正在运行的 Agent？",
                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                 QMessageBox.StandardButton.No)
        if r == QMessageBox.StandardButton.Yes:
            self._worker.cancel()

    def _on_select_js_dir(self):
        """浏览选择 JS 文件目录。"""
        path = QFileDialog.getExistingDirectory(self, "选择 JS 文件目录")
        if path:
            self._js_path_input.setText(path)

    def _on_js_path_changed(self, text: str):
        """JS 文件路径变更时扫描 .js 文件。"""
        self._scan_js_files(text)

    def _scan_js_files(self, dir_path: str):
        """扫描目录下所有 .js 文件。"""
        self._js_files = []
        if not dir_path or not dir_path.strip():
            self._js_status.setText("")
            return
        p = Path(dir_path.strip())
        if not p.exists():
            self._js_status.setText("路径不存在")
            self._js_status.setStyleSheet("color: #ef4444; font-size: 11px;")
            return
        if not p.is_dir():
            self._js_status.setText("不是目录")
            self._js_status.setStyleSheet("color: #ef4444; font-size: 11px;")
            return

        js_files = list(p.rglob("*.js"))
        # 排除 node_modules 和常见的打包目录
        exclude_dirs = {"node_modules", ".git", "dist", "build", ".next", "__pycache__",
                        "vendor", "bower_components", "coverage"}
        self._js_files = [
            str(f) for f in js_files
            if not any(ex in f.parts for ex in exclude_dirs)
        ]
        n = len(self._js_files)
        if n > 0:
            self._js_status.setText(f"{n} 个 JS 文件")
            self._js_status.setStyleSheet("color: #3b82f6; font-size: 11px; font-weight: bold;")
        else:
            self._js_status.setText("目录下无 JS 文件")
            self._js_status.setStyleSheet("color: #f59e0b; font-size: 11px;")
            # 也尝试非递归扫描
            js_direct = list(p.glob("*.js"))
            if js_direct:
                self._js_files = [str(f) for f in js_direct]
                self._js_status.setText(f"{len(self._js_files)} 个 JS 文件（仅当前目录）")
                self._js_status.setStyleSheet("color: #3b82f6; font-size: 11px; font-weight: bold;")

    def _on_settings(self):
        dlg = SettingsDialog(self.config, self)
        if dlg.exec() == SettingsDialog.DialogCode.Accepted:
            self.config = dlg.get_config()

    def _on_import_har(self):
        path, _ = QFileDialog.getOpenFileName(self, "导入 HAR", "", "HAR (*.har);;All (*)")
        if not path:
            return
        try:
            har = json.loads(Path(path).read_text())
            entries = har.get("log", {}).get("entries", [])
            records = []
            for e in entries:
                req = e.get("request", {})
                resp = e.get("response", {})
                url = req.get("url", "")
                from urllib.parse import urlparse
                host = urlparse(url).hostname or ""
                rh = {h.get("name", "").lower(): h.get("value", "") for h in req.get("headers", [])}
                rsh = {h.get("name", "").lower(): h.get("value", "") for h in resp.get("headers", [])}
                records.append({
                    "id": f"har_{len(records)}", "method": req.get("method", "GET"),
                    "url": url, "host": host, "path": urlparse(url).path,
                    "request_headers": rh, "request_body": (req.get("postData") or {}).get("text", ""),
                    "response_status": resp.get("status", 0), "response_headers": rsh,
                    "response_body": (resp.get("content") or {}).get("text", ""), "source": "har",
                })
            if self._worker:
                self._worker.load_burp_traffic(records)
            _ask(self, "导入成功", f"Loaded {len(records)} records.")
        except Exception as e:
            _ask(self, "导入失败", str(e))

    # ── 信号处理 ──────────────────────────────────────────────

    def _on_thought(self, thought):
        """收到 Agent 思考 — 存入日志 + 全量缓存供端点筛选。"""
        self.agent_log.add_thought(thought)
        self._all_thoughts.append({
            "type": thought.type,
            "content": thought.content,
            "endpoint_path": thought.endpoint_path,
        })
        self.endpoint_detail.set_thoughts_source(self._all_thoughts)

    def _on_finding(self, f: dict):
        self.findings_table.add_finding(f)
        # 尝试关联到端点
        ep_path = f.get("endpoint", "")
        if ep_path:
            self.endpoint_list.add_finding_to_endpoint(ep_path, "?", f)

    def _on_endpoint_selected(self, ep: dict):
        """点击测试清单中的接口 → 底部面板显示详情。"""
        self.endpoint_detail.set_thoughts_source(self._all_thoughts)
        self.endpoint_detail.show_endpoint(ep)

    def _on_finding_selected(self, f: dict):
        """点击漏洞列表 → 底部面板显示漏洞详情。"""
        self.endpoint_detail.set_thoughts_source(self._all_thoughts)
        self.endpoint_detail.show_finding(f)

    def _on_noise_selected(self, noise: dict):
        """点击疑点记录 → 底部面板显示详情。"""
        self.endpoint_detail.set_thoughts_source(self._all_thoughts)
        self.endpoint_detail.show_noise(noise)

    def _on_endpoint_discovered(self, data: dict):
        self.endpoint_list.add_endpoint(data)
        self._update_dashboard()

    def _on_endpoint_status(self, path: str, method: str, status: str, note: str):
        self.endpoint_list.update_status(path, method, status, note)
        self._update_dashboard()

    def _on_test_activity(self, path: str, method: str, action: str):
        self.endpoint_list.add_test_activity(path, method, action)

    def _on_confirm_required(self, method, url, desc, info):
        self.pending_ops.add_pending(method, url, desc, info)

    def _on_op_approved(self, op_id: str, op: dict):
        """用户批准了一个危险操作 — 执行并把结果注入回 Agent 对话。"""
        self.agent_log.add("action", f"用户批准: {op['method']} {op['path']} — {op['desc']}")
        if self._worker and self._worker._agent:
            import asyncio

            async def execute_and_inject():
                agent = self._worker._agent
                # 执行审批的操作
                result = await agent.tools._send_request(
                    {"method": op["method"], "url": op["url"],
                     "headers": op.get("request_info", {}).get("headers", {}),
                     "body": op.get("request_info", {}).get("body"),
                     "modification_desc": f"[用户批准] {op['desc']}"},
                    self.agent_log.add_thought,
                )
                # 把结果注入 Agent 对话，Agent 下一轮会看到
                import json as _json
                try:
                    result_obj = _json.loads(result)
                    status = result_obj.get("status", "?")
                    body_len = result_obj.get("body_length", 0)
                    summary = (
                        f"## 用户批准的操作已执行\n"
                        f"操作: {op['method']} {op['path']} — {op['desc']}\n"
                        f"响应状态: {status}\n"
                        f"响应长度: {body_len}\n"
                        f"完整结果: {result[:1500]}"
                    )
                except Exception:
                    summary = f"## 用户批准的操作已执行\n{op['method']} {op['path']}\n结果: {result[:1000]}"

                agent.inject_approved_result(summary)
                self.agent_log.add("action", f"审批结果已注入 Agent: {op['method']} {op['path']} → {status if 'status' in dir() else '?'}")

            asyncio.create_task(execute_and_inject())

    def _on_progress(self, ep, fn, rq):
        self._status_endpoints.setText(f"接口: {ep}")
        self._status_findings.setText(f"发现: {fn}")
        self._status_requests.setText(f"请求: {rq}")
        self._update_dashboard()

    def _on_finished(self, summary: dict):
        self._running = False
        self._set_running_state(False)
        self._status_phase.setText("完成")
        self._dash_status.setText("状态: 完成")
        self._dash_status.setStyleSheet("color: #10b981; font-size: 14px; padding: 8px 0;")

    def _on_paused_error(self, msg: str):
        """Agent 异常暂停但保留状态，显示继续按钮。"""
        self._status_phase.setText("异常暂停")
        self._status_phase.setStyleSheet("color: #f59e0b; padding: 0 8px; font-weight: bold;")
        self._dash_status.setText(f"状态: {msg}")
        self._dash_status.setStyleSheet("color: #f59e0b; font-size: 14px; padding: 8px 0;")
        self._btn_continue.setVisible(True)
        self._btn_continue.setEnabled(True)
        self._btn_pause.setEnabled(False)
        self._btn_stop.setEnabled(True)

    def _on_continue(self):
        """用户点击继续，恢复 Agent 测试。"""
        if not self._worker:
            return
        self._btn_continue.setVisible(False)
        self._btn_continue.setEnabled(False)
        self._btn_pause.setEnabled(True)
        self._status_phase.setText("运行中")
        self._status_phase.setStyleSheet("color: #94a3b8; padding: 0 8px; font-weight: bold;")
        self._dash_status.setText("状态: 运行中")
        self._dash_status.setStyleSheet("color: #10b981; font-size: 14px; padding: 8px 0;")
        self._worker.continue_after_error()
        # 在新线程中继续运行
        self._worker_thread = QThread()
        self._worker.moveToThread(self._worker_thread)
        self._worker_thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker.error_occurred.connect(self._worker_thread.quit)
        self._worker_thread.finished.connect(self._on_thread_done)
        self._worker_thread.start()

    def _on_error(self, msg: str):
        self._running = False
        self._set_running_state(False)
        self._status_phase.setText("错误")
        self._dash_status.setText("状态: 错误")
        self._dash_status.setStyleSheet("color: #ef4444; font-size: 14px; padding: 8px 0;")

    def _on_thread_done(self):
        # 如果是异常暂停，不删除 worker（等待用户点继续）
        if hasattr(self, '_worker') and self._worker and \
           hasattr(self._worker, '_agent') and self._worker._agent and \
           getattr(self._worker._agent, '_error_occurred', False):
            if self._worker_thread:
                self._worker_thread.deleteLater()
                self._worker_thread = None
            return
        if self._worker_thread:
            self._worker_thread.deleteLater()
            self._worker_thread = None
        if self._worker:
            self._worker.deleteLater()
            self._worker = None

    def _set_running_state(self, running: bool):
        self._running = running
        self._btn_start.setEnabled(not running)
        self._btn_pause.setEnabled(running)
        self._btn_stop.setEnabled(running)
        self._url_input.setEnabled(not running)

    def _update_dashboard(self):
        ep = self.endpoint_list._table.rowCount()
        fn = self.findings_table._table.rowCount()
        self._dash_stats.setText(f"接口: {ep} | 发现: {fn}")

    def closeEvent(self, event):
        if self._running:
            msg = "Agent 运行中，退出将丢失进度，确定退出？"
        else:
            msg = "确定退出 DeepPierce？"
        r = _ask(self, "退出确认", msg,
                 QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                 QMessageBox.StandardButton.No)
        if r == QMessageBox.StandardButton.No:
            event.ignore()
            return
        if self._worker:
            self._worker.cancel()
        event.accept()
