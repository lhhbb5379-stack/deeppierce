"""详情面板 — 端点数据包 / 漏洞详情，双模式切换。"""

from __future__ import annotations
import json

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QPlainTextEdit, QSplitter,
    QStackedWidget, QVBoxLayout, QWidget,
)


class DiffView(QWidget):

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        self._stack = QStackedWidget()

        self._ep_view = self._create_endpoint_view()
        self._stack.addWidget(self._ep_view)

        self._vuln_view = self._create_vuln_view()
        self._stack.addWidget(self._vuln_view)

        layout.addWidget(self._stack)

    def _create_endpoint_view(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w); l.setContentsMargins(0,0,0,0); l.setSpacing(2)
        l.addWidget(QLabel("请求/响应"))

        vsplit = QSplitter(Qt.Orientation.Vertical)
        vsplit.setChildrenCollapsible(False)
        rw = QWidget(); rl = QHBoxLayout(rw); rl.setContentsMargins(0,0,0,0)
        self._req_orig = self._mk("原始请求")
        self._req_mod = self._mk("修改后请求")
        rs = QSplitter(Qt.Orientation.Horizontal)
        rs.setChildrenCollapsible(False)
        rs.addWidget(self._req_orig["w"]); rs.addWidget(self._req_mod["w"])
        rl.addWidget(rs); vsplit.addWidget(rw)

        respw = QWidget(); respl = QHBoxLayout(respw); respl.setContentsMargins(0,0,0,0)
        self._resp_orig = self._mk("原始响应")
        self._resp_mod = self._mk("修改后响应")
        rs2 = QSplitter(Qt.Orientation.Horizontal)
        rs2.setChildrenCollapsible(False)
        rs2.addWidget(self._resp_orig["w"]); rs2.addWidget(self._resp_mod["w"])
        respl.addWidget(rs2); vsplit.addWidget(respw)

        vsplit.setSizes([250, 250])
        l.addWidget(vsplit)
        return w

    def _create_vuln_view(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w); l.setContentsMargins(12, 8, 12, 8); l.setSpacing(10)

        title_row = QHBoxLayout()
        self._vuln_severity = QLabel("")
        self._vuln_severity.setStyleSheet("font-size: 11px; font-weight: 700; padding: 3px 10px; border-radius: 4px;")
        title_row.addWidget(self._vuln_severity)
        self._vuln_type = QLabel("")
        self._vuln_type.setStyleSheet("color: #94a3b8; font-size: 12px;")
        title_row.addWidget(self._vuln_type)
        self._vuln_confidence = QLabel("")
        self._vuln_confidence.setStyleSheet("color: #64748b; font-size: 12px;")
        title_row.addWidget(self._vuln_confidence)
        title_row.addStretch()
        l.addLayout(title_row)

        self._vuln_title = QLabel("")
        self._vuln_title.setStyleSheet("font-size: 16px; font-weight: 700; color: #e2e8f0;")
        self._vuln_title.setWordWrap(True)
        l.addWidget(self._vuln_title)

        l.addWidget(QLabel("漏洞描述"))
        self._vuln_desc = QPlainTextEdit(); self._vuln_desc.setReadOnly(True); self._vuln_desc.setMaximumHeight(100)
        l.addWidget(self._vuln_desc)

        l.addWidget(QLabel("复现步骤"))
        self._vuln_poc = QPlainTextEdit(); self._vuln_poc.setReadOnly(True); self._vuln_poc.setMaximumHeight(100)
        l.addWidget(self._vuln_poc)

        l.addWidget(QLabel("证据"))
        ev_split = QSplitter(Qt.Orientation.Horizontal)
        self._vuln_req = self._mk("请求")
        self._vuln_resp = self._mk("响应")
        ev_split.addWidget(self._vuln_req["w"]); ev_split.addWidget(self._vuln_resp["w"])
        l.addWidget(ev_split)

        return w

    def _mk(self, label):
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(0,0,0,0); l.setSpacing(2)
        h = QLabel(label)
        h.setStyleSheet("color:#94a3b8;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px;background:transparent;padding:2px 4px;")
        l.addWidget(h)
        e = QPlainTextEdit(); e.setReadOnly(True); e.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        l.addWidget(e)
        return {"w": w, "e": e}

    def show_finding(self, finding: dict):
        self._stack.setCurrentIndex(1)
        sev = finding.get("severity", "info")
        sev_colors = {
            "critical": ("#ef4444", "#7f1d1d"), "high": ("#f59e0b", "#78350f"),
            "medium": ("#eab308", "#713f12"), "low": ("#22c55e", "#14532d"),
            "info": ("#3b82f6", "#1e3a5f"),
        }
        text_c, bg_c = sev_colors.get(sev, ("#94a3b8", "#1e293b"))
        self._vuln_severity.setText(sev.upper())
        self._vuln_severity.setStyleSheet(f"font-size:11px;font-weight:700;padding:3px 10px;border-radius:4px;color:{text_c};background:{bg_c};")
        self._vuln_type.setText(finding.get("attack_type", "").upper())
        self._vuln_confidence.setText(f"Confidence: {finding.get('confidence', 0):.0%}")
        self._vuln_title.setText(finding.get("title", "Untitled"))
        self._vuln_desc.setPlainText(finding.get("description", ""))
        self._vuln_poc.setPlainText(finding.get("poc", finding.get("poc_description", "")))
        req = finding.get("evidence_request") or finding.get("request", {})
        resp = finding.get("evidence_response") or finding.get("response", {})
        self._vuln_req["e"].setPlainText(self._fmt_req(req))
        self._vuln_resp["e"].setPlainText(self._fmt_resp(resp))

    def show_endpoint(self, ep: dict):
        self._stack.setCurrentIndex(0)
        req = ep.get("request", ep)
        resp = ep.get("response", {})
        self._req_orig["e"].setPlainText(self._fmt_req(req))
        self._req_mod["e"].clear()
        self._resp_orig["e"].setPlainText(self._fmt_resp(resp))
        self._resp_mod["e"].clear()

    def clear(self):
        for p in [self._req_orig, self._req_mod, self._resp_orig, self._resp_mod,
                  self._vuln_req, self._vuln_resp]:
            p["e"].clear()
        self._vuln_desc.clear()
        self._vuln_poc.clear()

    @staticmethod
    def _fmt_req(r):
        if not r: return ""
        m = r.get("method", "GET"); u = r.get("url", "")
        lines = [f"{m} {u}"]
        for k, v in (r.get("headers") or {}).items():
            lines.append(f"{k}: {v}")
        b = r.get("body", "")
        if b: lines.append(""); lines.append(b if isinstance(b, str) else json.dumps(b, indent=2, ensure_ascii=False))
        return "\n".join(lines)

    @staticmethod
    def _fmt_resp(r):
        if not r: return ""
        s = r.get("status_code", r.get("status", "?"))
        lines = [f"HTTP/1.1 {s}"]
        for k, v in (r.get("headers") or {}).items():
            lines.append(f"{k}: {v}")
        b = r.get("body", "")
        if b:
            lines.append("")
            try:
                lines.append(json.dumps(json.loads(b) if isinstance(b, str) else b, indent=2, ensure_ascii=False))
            except Exception:
                lines.append(str(b)[:2000])
        return "\n".join(lines)
