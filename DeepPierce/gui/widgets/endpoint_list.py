"""测试清单 — Agent 逐项打钩的接口测试清单。去重合并 + 状态追踪 + 测试历史。"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QBrush, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QHBoxLayout, QHeaderView, QLabel, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

STATUS_ICONS = {"pending": "○", "testing": "◉", "done": "✓", "skipped": "—"}
STATUS_COLORS = {"pending": "#475569", "testing": "#f59e0b", "done": "#22c55e", "skipped": "#64748b"}
STATUS_LABELS = {"pending": "待测", "testing": "测试中", "done": "已测", "skipped": "跳过"}
NOISE_EXT = {".css", ".js", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".mp4", ".mp3", ".pdf"}

METHOD_COLORS = {
    "GET": ("#22c55e", "#14532d"), "POST": ("#3b82f6", "#1e3a5f"),
    "PUT": ("#f59e0b", "#78350f"), "DELETE": ("#ef4444", "#7f1d1d"),
    "PATCH": ("#a855f7", "#3b0764"), "?": ("#94a3b8", "#1e293b"),
}


class EndpointList(QWidget):
    endpoint_selected = Signal(dict)  # 携带完整端点数据（含 test_history, findings）

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 4)
        layout.setSpacing(4)

        header = QHBoxLayout()
        title = QLabel("测试清单")
        header.addWidget(title)
        header.addStretch()
        self._counter = QLabel("")
        self._counter.setStyleSheet("color: #64748b; font-size: 11px;")
        header.addWidget(self._counter)
        layout.addLayout(header)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["", "方法", "路径", "来源", "最近测试"])
        self._table.setColumnWidth(0, 32)
        self._table.setColumnWidth(1, 56)
        self._table.setColumnWidth(2, 300)
        self._table.setColumnWidth(3, 90)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.cellClicked.connect(self._on_click)
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(True)
        layout.addWidget(self._table)
        self._rows: dict[str, dict] = {}

    def clear(self):
        self._table.setRowCount(0)
        self._rows.clear()
        self._counter.setText("")

    def _key(self, method, path):
        return f"{method.upper()}:{path.split('?')[0].rstrip('/')}"

    def _noise(self, path):
        p = path.lower()
        if "." in p and p[p.rfind("."):] in NOISE_EXT:
            return True
        return any(k in p for k in ["/images/", "/img/", "/fonts/", "/static/", "/assets/", "favicon"])

    def add_endpoint(self, ep: dict):
        method = ep.get("method", "?").upper() or "?"
        path = ep.get("path", ep.get("url", "/"))
        source = ep.get("source", "?")
        if self._noise(path):
            return

        key = self._key(method, path)
        if key in self._rows:
            d = self._rows[key]
            if source not in d["sources"]:
                d["sources"].append(source)
            self._table.item(d["_row"], 3).setText(", ".join(d["sources"][:2]))
            return

        row = self._table.rowCount()
        self._table.insertRow(row)

        # 状态图标
        si = QTableWidgetItem(STATUS_ICONS["pending"])
        si.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        si.setForeground(QBrush(QColor(STATUS_COLORS["pending"])))
        si.setFont(QFont("SF Pro Display", 13))
        self._table.setItem(row, 0, si)

        # 方法 Badge
        mc = METHOD_COLORS.get(method, METHOD_COLORS["?"])
        mi = QTableWidgetItem(method)
        mi.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        mi.setForeground(QBrush(QColor(mc[0])))
        mi.setFont(QFont("JetBrains Mono", 10, QFont.Weight.Bold))
        self._table.setItem(row, 1, mi)

        self._table.setItem(row, 2, QTableWidgetItem(path[:120]))
        self._table.setItem(row, 3, QTableWidgetItem(source))
        self._table.setItem(row, 4, QTableWidgetItem(""))

        self._rows[key] = {
            "method": method, "path": path, "sources": [source],
            "status": "pending", "note": "", "_row": row,
            "test_history": [], "findings": [],
        }
        self._update_counter()

    def add_full_record(self, r):
        self.add_endpoint(r)

    def update_status(self, path: str, method: str, status: str, note: str = ""):
        key = self._key(method, path)
        if key not in self._rows:
            return
        d = self._rows[key]
        d["status"] = status
        d["note"] = note

        from datetime import datetime
        d["test_history"].append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "action": f"标记: {status}",
            "note": note,
        })

        row = d["_row"]
        si = QTableWidgetItem(STATUS_ICONS.get(status, "○"))
        si.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        si.setForeground(QBrush(QColor(STATUS_COLORS.get(status, "#64748b"))))
        si.setToolTip(STATUS_LABELS.get(status, ""))
        si.setFont(QFont("SF Pro Display", 13))
        self._table.setItem(row, 0, si)
        self._table.setItem(row, 4, QTableWidgetItem(note[:120]))
        self._update_counter()

    def add_finding_to_endpoint(self, path: str, method: str, finding: dict):
        """关联漏洞到端点。"""
        key = self._key(method, path)
        if key in self._rows:
            self._rows[key].setdefault("findings", []).append(finding)

    def add_test_activity(self, path: str, method: str, action: str):
        """记录一次测试活动。"""
        from datetime import datetime
        key = self._key(method, path)
        if key not in self._rows:
            # 模糊匹配
            norm = path.split("?")[0].rstrip("/")
            for ek, ev in self._rows.items():
                if ev["path"].split("?")[0].rstrip("/") == norm:
                    key = ek
                    break
        if key in self._rows:
            self._rows[key]["test_history"].append({
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "action": action,
                "note": "",
            })
            # 更新"最近测试"列
            row = self._rows[key]["_row"]
            self._table.item(row, 4).setText(action[:80])

    def _on_click(self, row, col):
        for d in self._rows.values():
            if d["_row"] == row:
                ep = {
                    "method": d["method"], "path": d["path"],
                    "sources": d["sources"], "status": d["status"],
                    "note": d.get("note", ""),
                    "test_history": d.get("test_history", []),
                    "findings": d.get("findings", []),
                }
                self.endpoint_selected.emit(ep)
                break

    def _update_counter(self):
        total = len(self._rows)
        tested = sum(1 for v in self._rows.values() if v["status"] in ("done", "skipped"))
        self._counter.setText(f"{tested}/{total}")

    def get_all_data(self) -> list[dict]:
        """导出所有端点数据，供外部查询。"""
        return [
            {"method": v["method"], "path": v["path"], "status": v["status"],
             "sources": v["sources"], "note": v.get("note", ""),
             "test_history": v.get("test_history", []), "findings": v.get("findings", [])}
            for v in self._rows.values()
        ]
