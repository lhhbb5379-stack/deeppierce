"""待确认操作面板 — Agent 危险操作先放这里，用户审批后注入回 Agent 对话。"""

from __future__ import annotations

import uuid
from urllib.parse import urlparse

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)


class PendingOpsWidget(QWidget):
    """待确认操作列表。每项有唯一 ID，审批后发出信号（含操作 ID 和请求数据）。"""

    op_approved = Signal(str, dict)   # op_id, op_data
    op_rejected = Signal(str)          # op_id

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(6)

        header = QHBoxLayout()
        title = QLabel("待确认操作")
        title.setObjectName("sectionTitle")
        header.addWidget(title)
        header.addStretch()
        self._count_label = QLabel("")
        self._count_label.setStyleSheet("color: #f59e0b; font-size: 12px;")
        header.addWidget(self._count_label)
        layout.addLayout(header)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["方法", "路径", "描述", "操作"])
        self._table.setColumnWidth(0, 60)
        self._table.setColumnWidth(1, 260)
        self._table.setColumnWidth(2, 200)
        self._table.setColumnWidth(3, 140)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(36)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        layout.addWidget(self._table)

        # 用 UUID 做主键，不再依赖行号
        self._ops: dict[str, dict] = {}   # op_id → {method, url, path, desc, ...}

    def add_pending(self, method: str, url: str, desc: str, request_info: dict) -> str:
        """添加一个待确认操作。返回操作 ID。"""
        path = urlparse(url).path if url.startswith("http") else url
        op_id = str(uuid.uuid4())[:8]

        row = self._table.rowCount()
        self._table.insertRow(row)

        self._table.setItem(row, 0, QTableWidgetItem(method))
        self._table.setItem(row, 1, QTableWidgetItem(path[:100]))
        self._table.setItem(row, 2, QTableWidgetItem(desc[:100]))

        btn_widget = QWidget()
        btn_layout = QHBoxLayout(btn_widget)
        btn_layout.setContentsMargins(2, 2, 2, 2)
        btn_layout.setSpacing(4)

        approve_btn = QPushButton("批准")
        approve_btn.setObjectName("primaryBtn")
        approve_btn.setToolTip("批准并执行此操作")
        # 用闭包捕获 op_id，不依赖行号
        approve_btn.clicked.connect(lambda checked=False, oid=op_id: self._approve(oid))
        btn_layout.addWidget(approve_btn)

        reject_btn = QPushButton("拒绝")
        reject_btn.setObjectName("dangerBtn")
        reject_btn.setToolTip("拒绝此操作")
        reject_btn.clicked.connect(lambda checked=False, oid=op_id: self._reject(oid))
        btn_layout.addWidget(reject_btn)

        self._table.setCellWidget(row, 3, btn_widget)
        self._table.setRowHeight(row, 36)

        self._ops[op_id] = {
            "method": method, "url": url, "path": path, "desc": desc,
            "request_info": request_info, "_row": row,
        }
        self._update_count()
        return op_id

    def _approve(self, op_id: str):
        if op_id not in self._ops:
            return
        op = self._ops[op_id]
        self.op_approved.emit(op_id, op)
        self._remove_op(op_id)

    def _reject(self, op_id: str):
        if op_id not in self._ops:
            return
        self.op_rejected.emit(op_id)
        self._remove_op(op_id)

    def _remove_op(self, op_id: str):
        if op_id not in self._ops:
            return
        old_row = self._ops[op_id]["_row"]
        self._table.removeRow(old_row)
        del self._ops[op_id]

        # 重排剩余操作的行号，保持 UI 连续
        for i, (oid, op) in enumerate(self._ops.items()):
            op["_row"] = i
        self._update_count()

    def _update_count(self):
        n = len(self._ops)
        self._count_label.setText(f"{n} 个待确认" if n else "")

    def clear(self):
        self._table.setRowCount(0)
        self._ops.clear()
        self._update_count()
