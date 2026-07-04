"""Agent 思考日志 — 实时展示 Agent 的每一步决策和推理。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import QLabel, QPlainTextEdit, QVBoxLayout, QWidget

from DeepPierce.models import AgentThought


class AgentLogView(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 4)
        layout.setSpacing(4)

        title = QLabel("思考日志")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)

        self._log = QPlainTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumBlockCount(2000)
        layout.addWidget(self._log)

        self._thoughts: list[dict] = []
        self._colors = {
            "system": QColor("#94a3b8"),
            "thinking": QColor("#94a3b8"),
            "action": QColor("#10b981"),
            "finding": QColor("#f59e0b"),
            "error": QColor("#ef4444"),
            "done": QColor("#3b82f6"),
        }

    def clear(self):
        self._log.clear()
        self._thoughts.clear()

    def add(self, thought_type: str, content: str):
        color = self._colors.get(thought_type, QColor("#e2e8f0"))
        fmt = QTextCharFormat()
        fmt.setForeground(color)
        if thought_type == "finding":
            fmt.setFontWeight(QFont.Weight.Bold)

        cursor = self._log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        ts_fmt = QTextCharFormat()
        ts_fmt.setForeground(QColor("#475569"))
        cursor.insertText(f"[{ts}] ", ts_fmt)
        cursor.insertText(f"{content}\n", fmt)
        self._log.setTextCursor(cursor)
        self._log.ensureCursorVisible()

        self._thoughts.append({"type": thought_type, "content": content})

    def add_thought(self, thought: AgentThought):
        self.add(thought.type, thought.content)

    def get_all_thoughts(self) -> list[dict]:
        return self._thoughts
