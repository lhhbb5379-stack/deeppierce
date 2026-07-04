"""发现列表 — 实时展示 Agent 发现的漏洞。"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QBrush, QFont
from PySide6.QtWidgets import (
    QAbstractItemView, QHeaderView, QLabel, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)


class FindingsTable(QWidget):

    finding_selected = Signal(dict)

    SEV_COLORS = {
        "critical": ("#ef4444", "#7f1d1d"), "high": ("#f97316", "#7c2d12"),
        "medium": ("#eab308", "#713f12"), "low": ("#22c55e", "#14532d"),
        "info": ("#3b82f6", "#1e3a5f"),
    }
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 4)
        layout.setSpacing(4)

        title = QLabel("漏洞汇总")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["", "类型", "严重度", "详情"])
        self._table.setColumnWidth(0, 24)
        self._table.setColumnWidth(1, 70)
        self._table.setColumnWidth(2, 80)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.cellClicked.connect(self._on_click)

        layout.addWidget(self._table)
        self._findings: list[dict] = []

    def clear(self):
        self._table.setRowCount(0)
        self._findings.clear()

    def add_finding(self, finding: dict):
        sev = finding.get("severity", "info")
        sev_order = self.SEV_ORDER.get(sev, 5)

        # 找到插入位置（保持 severity 降序）
        insert_row = 0
        for i, f in enumerate(self._findings):
            existing_order = self.SEV_ORDER.get(f.get("severity", "info"), 5)
            if sev_order < existing_order:
                break
            insert_row = i + 1

        self._findings.insert(insert_row, finding)
        self._table.insertRow(insert_row)

        text_c, bg_c = self.SEV_COLORS.get(sev, ("#94a3b8", "#1e293b"))

        dot = QTableWidgetItem("●")
        dot.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        dot.setForeground(QBrush(QColor(text_c)))
        dot.setToolTip(sev.upper())
        self._table.setItem(insert_row, 0, dot)

        self._table.setItem(insert_row, 1, QTableWidgetItem(finding.get("attack_type", "?").upper()))

        sev_item = QTableWidgetItem(sev.upper())
        sev_item.setForeground(QBrush(QColor(text_c)))
        sev_item.setFont(QFont("", -1, QFont.Weight.Bold))
        self._table.setItem(insert_row, 2, sev_item)

        conf = finding.get("confidence", 0)
        title = finding.get("title", "")
        detail = f"[{conf:.0%}] {title[:120]}"
        self._table.setItem(insert_row, 3, QTableWidgetItem(detail))

    def get_all_findings(self) -> list[dict]:
        return self._findings

    def _on_click(self, row, col):
        if row < len(self._findings):
            self.finding_selected.emit(self._findings[row])
