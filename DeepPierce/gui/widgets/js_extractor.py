"""JS 提取器面板 — 粘贴代码 / 上传文件，提取 API 接口。"""

from __future__ import annotations
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFileDialog, QGroupBox, QHBoxLayout, QLabel, QPlainTextEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QTabWidget,
    QTextEdit, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)


class JsExtractorPanel(QWidget):

    endpoints_extracted = Signal(list)
    secrets_found = Signal(list)

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(8)

        # ── File upload ──
        upload_group = QGroupBox("上传 JS 文件")
        upload_layout = QVBoxLayout(upload_group)

        btn_row = QHBoxLayout()
        self._select_files_btn = QPushButton("选择文件...")
        self._select_files_btn.clicked.connect(self._on_select_files)
        btn_row.addWidget(self._select_files_btn)

        self._select_dir_btn = QPushButton("选择文件夹...")
        self._select_dir_btn.clicked.connect(self._on_select_dir)
        btn_row.addWidget(self._select_dir_btn)

        self._batch_extract_btn = QPushButton("批量提取")
        self._batch_extract_btn.setObjectName("primaryBtn")
        self._batch_extract_btn.clicked.connect(self._on_batch_extract)
        self._batch_extract_btn.setEnabled(False)
        btn_row.addWidget(self._batch_extract_btn)

        self._clear_files_btn = QPushButton("清空")
        self._clear_files_btn.clicked.connect(self._on_clear_files)
        btn_row.addWidget(self._clear_files_btn)
        btn_row.addStretch()
        upload_layout.addLayout(btn_row)

        self._file_tree = QTreeWidget()
        self._file_tree.setHeaderLabels(["文件", "大小", "接口", "密钥"])
        self._file_tree.setColumnWidth(0, 280)
        self._file_tree.setColumnWidth(1, 70)
        self._file_tree.setColumnWidth(2, 50)
        self._file_tree.setColumnWidth(3, 60)
        self._file_tree.setMaximumHeight(110)
        self._file_tree.setRootIsDecorated(False)
        upload_layout.addWidget(self._file_tree)

        self._upload_status = QLabel("未加载文件")
        self._upload_status.setStyleSheet("color: #64748b; font-size: 12px;")
        upload_layout.addWidget(self._upload_status)
        layout.addWidget(upload_group)

        # ── Paste area ──
        paste_group = QGroupBox("或粘贴 JS 代码")
        paste_layout = QVBoxLayout(paste_group)
        self._js_input = QPlainTextEdit()
        self._js_input.setPlaceholderText("Paste JS code from DevTools Sources tab...")
        self._js_input.setMaximumHeight(100)
        paste_layout.addWidget(self._js_input)

        paste_btns = QHBoxLayout()
        self._extract_btn = QPushButton("提取接口")
        self._extract_btn.setObjectName("primaryBtn")
        self._extract_btn.clicked.connect(self._on_extract_paste)
        paste_btns.addWidget(self._extract_btn)
        self._clear_paste_btn = QPushButton("清空")
        self._clear_paste_btn.clicked.connect(lambda: self._js_input.clear())
        paste_btns.addWidget(self._clear_paste_btn)
        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: #94a3b8; font-size: 12px;")
        paste_btns.addWidget(self._status_label)
        paste_btns.addStretch()
        paste_layout.addLayout(paste_btns)
        layout.addWidget(paste_group)

        # ── Results ──
        tabs = QTabWidget()
        self._api_table = QTableWidget(0, 3)
        self._api_table.setHorizontalHeaderLabels(["接口路径", "来源", "类型"])
        self._api_table.setColumnWidth(0, 400)
        self._api_table.setColumnWidth(1, 100)
        self._api_table.horizontalHeader().setStretchLastSection(True)
        self._api_table.verticalHeader().setVisible(False)
        tabs.addTab(self._api_table, "发现的接口")

        self._secrets_table = QTableWidget(0, 3)
        self._secrets_table.setHorizontalHeaderLabels(["Type", "Value", "Severity"])
        self._secrets_table.setColumnWidth(0, 180)
        self._secrets_table.setColumnWidth(1, 300)
        self._secrets_table.horizontalHeader().setStretchLastSection(True)
        self._secrets_table.verticalHeader().setVisible(False)
        tabs.addTab(self._secrets_table, "密钥/敏感信息")

        self._interesting_text = QTextEdit()
        self._interesting_text.setReadOnly(True)
        tabs.addTab(self._interesting_text, "其他发现")

        layout.addWidget(tabs)

        self._loaded_files: dict[str, str] = {}
        self._file_results: dict[str, dict] = {}

    def _on_select_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Select JS Files", "", "JavaScript (*.js);;All (*)")
        if paths:
            self._load_files([Path(p) for p in paths])

    def _on_select_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if dir_path:
            js_files = list(Path(dir_path).rglob("*.js"))
            if not js_files:
                self._upload_status.setText("No .js files found in folder")
                return
            self._load_files(js_files)

    def _load_files(self, paths: list[Path]):
        for p in paths:
            if p.name in self._loaded_files: continue
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                if len(content) > 100:
                    self._loaded_files[p.name] = content
                    item = QTreeWidgetItem(self._file_tree, [p.name, f"{len(content)/1024:.1f}KB", "-", "-"])
                    item.setData(0, Qt.ItemDataRole.UserRole, p.name)
            except Exception:
                continue
        self._upload_status.setText(f"Loaded {len(self._loaded_files)} files")
        self._batch_extract_btn.setEnabled(len(self._loaded_files) > 0)

    def _on_clear_files(self):
        self._loaded_files.clear()
        self._file_results.clear()
        self._file_tree.clear()
        self._upload_status.setText("未加载文件")
        self._batch_extract_btn.setEnabled(False)

    def _on_batch_extract(self):
        if not self._loaded_files: return
        from DeepPierce.crawler.js_extractor import JsApiExtractor
        extractor = JsApiExtractor()
        self._file_results.clear()
        all_eps, all_secrets, all_bases, all_ws = [], [], [], []

        for i in range(self._file_tree.topLevelItemCount()):
            item = self._file_tree.topLevelItem(i)
            filename = item.data(0, Qt.ItemDataRole.UserRole)
            if filename not in self._loaded_files: continue
            result = extractor.extract(self._loaded_files[filename], filename)
            self._file_results[filename] = result
            ep_count = len(result.api_endpoints) + len(result.base_urls) + len(result.web_services)
            item.setText(2, str(ep_count))
            item.setText(3, str(len(result.secrets)))
            all_eps.extend(result.api_endpoints)
            all_bases.extend(result.base_urls)
            all_ws.extend(result.web_services)
            all_secrets.extend(result.secrets)

        all_eps = list(dict.fromkeys(all_eps))
        all_bases = list(dict.fromkeys(all_bases))
        all_ws = list(dict.fromkeys(all_ws))
        self._update_results_table(all_eps, all_bases, all_ws, all_secrets)
        total = len(all_eps) + len(all_bases) + len(all_ws)
        self._upload_status.setText(f"{len(self._loaded_files)} files -> {total} APIs, {len(all_secrets)} secrets")
        self.endpoints_extracted.emit(all_eps + all_bases + all_ws)
        self.secrets_found.emit(all_secrets)

    def _on_extract_paste(self):
        js_code = self._js_input.toPlainText().strip()
        if not js_code:
            self._status_label.setText("Paste JS code first")
            return
        from DeepPierce.crawler.js_extractor import JsApiExtractor
        result = JsApiExtractor().extract(js_code, "paste")
        self._update_results_table(result.api_endpoints, result.base_urls, result.web_services, result.secrets)
        total = len(result.api_endpoints) + len(result.base_urls) + len(result.web_services)
        self._status_label.setText(f"Found {total} APIs, {len(result.secrets)} secrets")
        self.endpoints_extracted.emit(result.api_endpoints + result.base_urls + result.web_services)
        self.secrets_found.emit(result.secrets)

    def _update_results_table(self, endpoints, base_urls, web_services, secrets):
        self._api_table.setRowCount(0)
        for ep in endpoints[:300]:
            row = self._api_table.rowCount(); self._api_table.insertRow(row)
            self._api_table.setItem(row, 0, QTableWidgetItem(ep))
            self._api_table.setItem(row, 1, QTableWidgetItem("JS"))
            self._api_table.setItem(row, 2, QTableWidgetItem("API"))

        for url in base_urls[:50]:
            row = self._api_table.rowCount(); self._api_table.insertRow(row)
            self._api_table.setItem(row, 0, QTableWidgetItem(url))
            self._api_table.setItem(row, 1, QTableWidgetItem("JS"))
            self._api_table.setItem(row, 2, QTableWidgetItem("baseURL"))

        for ws in web_services[:50]:
            row = self._api_table.rowCount(); self._api_table.insertRow(row)
            self._api_table.setItem(row, 0, QTableWidgetItem(ws))
            self._api_table.setItem(row, 1, QTableWidgetItem("JS"))
            self._api_table.setItem(row, 2, QTableWidgetItem("WebService"))

        self._secrets_table.setRowCount(0)
        for s in secrets[:100]:
            row = self._secrets_table.rowCount(); self._secrets_table.insertRow(row)
            self._secrets_table.setItem(row, 0, QTableWidgetItem(s.get("rule", "")))
            self._secrets_table.setItem(row, 1, QTableWidgetItem(s.get("value", "")[:100]))
            self._secrets_table.setItem(row, 2, QTableWidgetItem(s.get("severity", "")))

        lines = []
        if base_urls:
            lines.append("=== Base URLs ==="); lines.extend(base_urls)
        if web_services:
            lines.append("\n=== WebServices ==="); lines.extend(web_services)
        self._interesting_text.setText("\n".join(lines))
