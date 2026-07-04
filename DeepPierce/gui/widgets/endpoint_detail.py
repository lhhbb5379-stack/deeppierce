"""端点详情面板 — 点击接口查看 AI 思考、测试记录、相关漏洞。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QPlainTextEdit, QTabWidget,
    QVBoxLayout, QWidget,
)


class EndpointDetail(QWidget):
    """底部详情面板，显示选中接口的 AI 分析、测试历史、漏洞关联。"""

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 8)
        layout.setSpacing(6)

        # ── 头部：接口信息 ──
        header = QHBoxLayout()
        self._method_label = QLabel("")
        self._method_label.setStyleSheet(
            "font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px;"
        )
        header.addWidget(self._method_label)

        self._path_label = QLabel("选择一个接口查看详情")
        self._path_label.setStyleSheet("font-size: 14px; font-weight: 700; color: #e2e8f0;")
        header.addWidget(self._path_label)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet("font-size: 11px; padding: 2px 8px; border-radius: 3px;")
        header.addWidget(self._status_label)

        header.addStretch()

        self._source_label = QLabel("")
        self._source_label.setStyleSheet("color: #64748b; font-size: 11px;")
        header.addWidget(self._source_label)
        layout.addLayout(header)

        # ── 子 Tab：AI分析 / 测试记录 / 关联漏洞 ──
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet("QTabBar::tab { padding: 4px 12px; font-size: 12px; }")

        self._ai_view = self._mk_text_view()
        self._tabs.addTab(self._ai_view, "AI 思考过程")

        self._test_view = self._mk_text_view()
        self._tabs.addTab(self._test_view, "测试记录")

        self._findings_view = self._mk_text_view()
        self._tabs.addTab(self._findings_view, "关联漏洞")

        layout.addWidget(self._tabs)

        self._current_path = ""
        self._all_thoughts: list[dict] = []  # 外部注入的全量思考

    def set_thoughts_source(self, thoughts: list[dict]):
        """注入全量思考数据源，用于按接口筛选。"""
        self._all_thoughts = thoughts

    def show_endpoint(self, ep: dict):
        """显示指定接口的详情。"""
        path = ep.get("path", "")
        method = ep.get("method", "?")
        status = ep.get("status", "pending")
        source = ep.get("source", ep.get("sources", ["?"])[0] if isinstance(ep.get("sources"), list) else "?")
        test_history = ep.get("test_history", [])
        findings = ep.get("findings", [])

        self._current_path = path

        # ── 头部更新 ──
        method_colors = {"GET": ("#22c55e", "#14532d"), "POST": ("#3b82f6", "#1e3a5f"),
                         "PUT": ("#f59e0b", "#78350f"), "DELETE": ("#ef4444", "#7f1d1d"),
                         "PATCH": ("#a855f7", "#3b0764")}
        mc = method_colors.get(method.upper(), ("#94a3b8", "#1e293b"))
        self._method_label.setText(method.upper())
        self._method_label.setStyleSheet(
            f"font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px; "
            f"color: {mc[0]}; background: {mc[1]};"
        )
        self._path_label.setText(path[:100])

        status_info = {"done": ("✅ 已测", "#22c55e"), "skipped": ("⏭ 跳过", "#64748b"),
                       "testing": ("🔄 测试中", "#f59e0b"), "pending": ("○ 待测", "#475569")}
        st = status_info.get(status, ("?", "#64748b"))
        self._status_label.setText(st[0])
        self._status_label.setStyleSheet(f"font-size: 11px; padding: 2px 8px; border-radius: 3px; color: {st[1]};")

        source_str = source if isinstance(source, str) else ", ".join(source)
        self._source_label.setText(f"来源: {source_str}")

        # ── AI 思考 Tab：筛选与该接口相关的思考 ──
        self._ai_view.clear()
        related_thoughts = self._filter_thoughts(path)
        if related_thoughts:
            for t in related_thoughts:
                self._append_colored(self._ai_view, t["type"], t["content"])
        else:
            self._ai_view.setPlainText("（暂无与该接口直接关联的 AI 思考）")

        # ── 测试记录 Tab ──
        self._test_view.clear()
        if test_history:
            for h in test_history:
                ts = h.get("timestamp", "")
                action = h.get("action", "")
                note = h.get("note", "")
                line = f"[{ts}] {action}"
                if note:
                    line += f" — {note}"
                self._append_text(self._test_view, line, QColor("#94a3b8"))
        else:
            # 尝试从测试清单的状态推断
            note = ep.get("note", "")
            if status == "done":
                self._append_text(self._test_view, f"已测试: {note}" if note else "已测试通过", QColor("#22c55e"))
            elif status == "skipped":
                self._append_text(self._test_view, f"跳过: {note}" if note else "已跳过", QColor("#64748b"))
            elif status == "testing":
                self._append_text(self._test_view, f"测试中: {note}" if note else "正在测试...", QColor("#f59e0b"))
            else:
                self._test_view.setPlainText("（尚未开始测试）")

        # ── 关联漏洞 Tab ──
        self._findings_view.clear()
        if findings:
            for f in findings:
                sev = f.get("severity", "?")
                sev_color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
                             "low": "#22c55e", "info": "#3b82f6"}.get(sev, "#94a3b8")
                ftype = f.get("type", f.get("attack_type", ""))
                line = f"[{sev.upper()}] {f.get('title', '?')}"
                if ftype:
                    line += f" ({ftype})"
                self._append_text(self._findings_view, line, QColor(sev_color))
        else:
            self._findings_view.setPlainText("（该接口暂未发现漏洞）")

        # 默认显示 AI 思考 Tab（如果有内容），否则显示测试记录
        if related_thoughts:
            self._tabs.setCurrentIndex(0)
        elif test_history:
            self._tabs.setCurrentIndex(1)
        else:
            self._tabs.setCurrentIndex(0)

    def show_finding(self, finding: dict):
        """显示漏洞详情（从漏洞列表点击时）。"""
        self._method_label.setText("VULN")
        self._method_label.setStyleSheet(
            "font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px; "
            "color: #ef4444; background: #7f1d1d;"
        )
        self._path_label.setText(finding.get("title", "Untitled"))
        sev = finding.get("severity", "info")
        self._status_label.setText(sev.upper())
        sev_color = {"critical": "#ef4444", "high": "#f59e0b", "medium": "#eab308",
                     "low": "#22c55e", "info": "#3b82f6"}.get(sev, "#94a3b8")
        self._status_label.setStyleSheet(f"font-size: 11px; padding: 2px 8px; border-radius: 3px; color: {sev_color};")
        self._source_label.setText(finding.get("attack_type", ""))

        # AI 思考 Tab
        self._ai_view.clear()
        endpoint_path = finding.get("endpoint", finding.get("path", ""))
        if endpoint_path:
            related = self._filter_thoughts(endpoint_path)
            if related:
                for t in related:
                    self._append_colored(self._ai_view, t["type"], t["content"])
            else:
                self._ai_view.setPlainText("（无关联思考）")
        else:
            self._ai_view.setPlainText("（无关联接口信息）")

        # 测试记录 Tab
        self._test_view.clear()
        self._test_view.setPlainText(finding.get("poc", finding.get("poc_description", finding.get("description", ""))))

        # 漏洞详情 Tab — 显示漏洞完整信息
        self._findings_view.clear()
        desc = finding.get("description", "")
        poc = finding.get("poc", "")
        confidence = finding.get("confidence", 0)
        lines = [
            f"类型: {finding.get('attack_type', '?')}",
            f"严重程度: {sev.upper()}",
            f"置信度: {confidence:.0%}",
            f"",
            f"=== 漏洞描述 ===",
            desc,
        ]
        if poc:
            lines.append("")
            lines.append("=== 复现 PoC ===")
            lines.append(poc)
        self._findings_view.setPlainText("\n".join(lines))

        # 测试记录 Tab 放 PoC
        self._test_view.clear()
        self._test_view.setPlainText(poc if poc else finding.get("description", ""))

        self._tabs.setCurrentIndex(2)  # 默认显示漏洞详情

    def show_noise(self, noise: dict):
        """显示疑点详情（从疑点记录列表点击时）。"""
        self._method_label.setText("NOISE")
        self._method_label.setStyleSheet(
            "font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px; "
            "color: #a78bfa; background: #3b0764;"
        )
        self._path_label.setText(noise.get("title", "Untitled"))
        self._status_label.setText(noise.get("category", "?"))
        self._status_label.setStyleSheet("font-size: 11px; padding: 2px 8px; border-radius: 3px; color: #a78bfa;")
        self._source_label.setText("疑点记录")

        # AI 思考 Tab — 尝试找关联思考
        self._ai_view.clear()
        title = noise.get("title", "")
        note = noise.get("note", "")
        # 用标题关键词匹配思考
        related = []
        for t in self._all_thoughts:
            content = t.get("content", "")
            if title and title[:20] in content:
                related.append(t)
            elif note and note[:30] in content:
                related.append(t)
        if related:
            for t in related[-20:]:
                self._append_colored(self._ai_view, t["type"], t["content"])
        else:
            self._ai_view.setPlainText("（无直接关联的 AI 思考）\n\n疑点内容:\n" + note[:500])

        # 测试记录 Tab — 显示备注
        self._test_view.clear()
        self._test_view.setPlainText(f"类别: {noise.get('category', '?')}\n\n备注:\n{noise.get('note', '')}")

        # 关联漏洞 Tab
        self._findings_view.clear()
        self._findings_view.setPlainText("疑点记录尚未确认为漏洞。如果后续确认，可用 report_finding 上报。")

        self._tabs.setCurrentIndex(1)  # 默认显示测试记录（疑点备注）

    def _filter_thoughts(self, path: str) -> list[dict]:
        """从全量思考中筛选与指定路径相关的。匹配规则：endpoint_path 精确匹配 或 content 包含路径。"""
        if not path:
            return []
        related = []
        norm = path.split("?")[0].rstrip("/")
        for t in self._all_thoughts:
            ep = t.get("endpoint_path", "")
            content = t.get("content", "")
            # 精确匹配
            if ep and (ep.rstrip("/") == norm or ep.rstrip("/").startswith(norm)):
                related.append(t)
            # 内容匹配
            elif norm and norm != "/" and norm in content:
                related.append(t)
        return related[-40:]  # 最多显示最近40条

    def clear(self):
        self._method_label.setText("")
        self._path_label.setText("选择一个接口查看详情")
        self._status_label.setText("")
        self._source_label.setText("")
        self._ai_view.clear()
        self._test_view.clear()
        self._findings_view.clear()

    # ── 辅助 ──

    @staticmethod
    def _mk_text_view() -> QPlainTextEdit:
        v = QPlainTextEdit()
        v.setReadOnly(True)
        v.setMaximumBlockCount(500)
        return v

    @staticmethod
    def _append_text(view: QPlainTextEdit, text: str, color: QColor):
        fmt = QTextCharFormat()
        fmt.setForeground(color)
        cursor = view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(text + "\n", fmt)
        view.setTextCursor(cursor)

    @staticmethod
    def _append_colored(view: QPlainTextEdit, thought_type: str, content: str):
        colors = {
            "system": QColor("#94a3b8"), "thinking": QColor("#94a3b8"),
            "action": QColor("#10b981"), "finding": QColor("#f59e0b"),
            "error": QColor("#ef4444"), "done": QColor("#3b82f6"),
            "noise": QColor("#a78bfa"),
        }
        color = colors.get(thought_type, QColor("#e2e8f0"))
        fmt = QTextCharFormat()
        fmt.setForeground(color)
        if thought_type == "finding":
            fmt.setFontWeight(QFont.Weight.Bold)

        cursor = view.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(content + "\n", fmt)
        view.setTextCursor(cursor)
