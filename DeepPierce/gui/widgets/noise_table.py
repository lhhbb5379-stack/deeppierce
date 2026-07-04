"""疑点记录 — Agent 发现但无法确认的观察。"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QHeaderView, QLabel, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)


class NoiseTable(QWidget):
    """可疑发现列表。点击行发出信号，显示详情。"""

    noise_selected = Signal(dict)

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 4)
        layout.setSpacing(4)

        title = QLabel("疑点记录")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["类别", "标题", "备注"])
        self._table.setColumnWidth(0, 120)
        self._table.setColumnWidth(1, 250)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.cellClicked.connect(self._on_click)

        layout.addWidget(self._table)
        self._items: list[dict] = []

    def clear(self):
        self._table.setRowCount(0)
        self._items.clear()

    def add_noise(self, noise: dict):
        row = self._table.rowCount()
        self._table.insertRow(row)
        cat = noise.get("category", "other")
        self._table.setItem(row, 0, QTableWidgetItem(cat))
        self._table.setItem(row, 1, QTableWidgetItem(noise.get("title", "")))
        self._table.setItem(row, 2, QTableWidgetItem(noise.get("note", "")[:200]))
        self._items.append(noise)
        self._table.scrollToBottom()

    def _on_click(self, row: int, col: int):
        if row < len(self._items):
            self.noise_selected.emit(self._items[row])
