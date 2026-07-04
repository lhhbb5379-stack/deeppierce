"""DeepPierce GUI — PySide6 + SOC Dark Theme."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication

# ── Color Tokens (ref: DESIGN.md) ─────────────────────────────────────────

C = {
    "canvas": "#0a0e1a",
    "surface": "#111827",
    "surface_elevated": "#1a2235",
    "border": "#1e293b",
    "accent": "#3b82f6",
    "accent_hover": "#60a5fa",
    "text": "#e2e8f0",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
    "code_bg": "#060911",
    "critical": "#ef4444",
    "high": "#f59e0b",
    "medium": "#eab308",
    "low": "#22c55e",
    "info": "#3b82f6",
}

DARK_THEME = f"""
/* Canvas */
QMainWindow {{ background-color: {C["canvas"]}; }}

/* Menu */
QMenuBar {{ background-color: {C["surface"]}; color: {C["text"]}; border-bottom: 1px solid {C["border"]}; padding: 4px 8px; font-size: 13px; }}
QMenuBar::item:selected {{ background-color: {C["surface_elevated"]}; border-radius: 4px; }}
QMenu {{ background-color: {C["surface"]}; color: {C["text"]}; border: 1px solid {C["border"]}; border-radius: 6px; padding: 4px; }}
QMenu::item {{ padding: 6px 24px; }}
QMenu::item:selected {{ background-color: {C["surface_elevated"]}; border-radius: 3px; }}

/* Toolbar */
QToolBar {{ background-color: {C["surface"]}; border-bottom: 1px solid {C["border"]}; spacing: 6px; padding: 8px 12px; }}

/* Status Bar */
QStatusBar {{ background-color: {C["surface"]}; color: {C["text_muted"]}; border-top: 1px solid {C["border"]}; font-size: 12px; font-family: "JetBrains Mono", "Menlo", monospace; }}

/* Splitters */
QSplitter::handle {{ background-color: {C["border"]}; width: 1px; height: 1px; }}
QSplitter::handle:hover {{ background-color: {C["accent"]}; }}

/* Tabs */
QTabWidget::pane {{ border: none; background-color: {C["canvas"]}; }}
QTabBar::tab {{ background: transparent; color: {C["text_secondary"]}; padding: 10px 18px; border: none; border-bottom: 2px solid transparent; font-size: 13px; margin-right: 2px; }}
QTabBar::tab:selected {{ color: {C["text"]}; border-bottom: 2px solid {C["accent"]}; }}
QTabBar::tab:hover {{ color: {C["text"]}; }}

/* Tables */
QTableView, QTableWidget {{ background-color: {C["canvas"]}; color: {C["text"]}; border: none; gridline-color: {C["border"]}; font-size: 13px; selection-background-color: rgba(59,130,246,0.12); }}
QTableView::item:hover, QTableWidget::item:hover {{ background-color: {C["surface_elevated"]}; }}
QHeaderView::section {{ background-color: {C["surface"]}; color: {C["text_secondary"]}; border: none; border-bottom: 1px solid {C["border"]}; padding: 8px 12px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}

/* Tree */
QTreeWidget, QTreeView {{ background-color: {C["canvas"]}; color: {C["text"]}; border: none; font-size: 13px; }}
QTreeWidget::item:selected, QTreeView::item:selected {{ background-color: rgba(59,130,246,0.12); }}
QTreeWidget::item:hover, QTreeView::item:hover {{ background-color: {C["surface_elevated"]}; }}

/* Code Editors */
QPlainTextEdit, QTextEdit {{ background-color: {C["code_bg"]}; color: {C["text"]}; border: 1px solid {C["border"]}; border-radius: 6px; font-family: "JetBrains Mono", "Fira Code", "Menlo", monospace; font-size: 12px; selection-background-color: rgba(59,130,246,0.25); padding: 8px; }}

/* Labels */
QLabel {{ color: {C["text"]}; }}
QLabel#sectionTitle {{ color: {C["text_muted"]}; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; padding: 4px 0; }}

/* Line Edit */
QLineEdit {{ background-color: {C["surface"]}; color: {C["text"]}; border: 1px solid {C["border"]}; border-radius: 6px; padding: 8px 14px; font-size: 14px; }}
QLineEdit:focus {{ border: 1px solid {C["accent"]}; }}

/* Buttons */
QPushButton {{ background-color: {C["surface_elevated"]}; color: {C["text"]}; border: none; border-radius: 6px; padding: 8px 16px; font-size: 13px; font-weight: 600; }}
QPushButton:hover {{ background-color: #263148; }}
QPushButton:pressed {{ background-color: #2d3a54; }}
QPushButton#primaryBtn {{ background-color: {C["accent"]}; color: #fff; }}
QPushButton#primaryBtn:hover {{ background-color: {C["accent_hover"]}; }}
QPushButton#dangerBtn {{ background-color: {C["critical"]}; color: #fff; }}
QPushButton#dangerBtn:hover {{ background-color: #f87171; }}
QPushButton:disabled {{ background-color: {C["border"]}; color: {C["text_muted"]}; }}

/* Combo */
QComboBox {{ background-color: {C["surface"]}; color: {C["text"]}; border: 1px solid {C["border"]}; border-radius: 6px; padding: 6px 12px; }}
QComboBox:hover {{ border-color: {C["text_muted"]}; }}
QComboBox QAbstractItemView {{ background-color: {C["surface"]}; border: 1px solid {C["border"]}; selection-background-color: {C["surface_elevated"]}; }}

/* Checkbox */
QCheckBox {{ color: {C["text"]}; spacing: 8px; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {C["border"]}; border-radius: 3px; background: {C["surface"]}; }}
QCheckBox::indicator:checked {{ background: {C["accent"]}; border-color: {C["accent"]}; }}

/* Group Box */
QGroupBox {{ color: {C["text"]}; border: 1px solid {C["border"]}; border-radius: 6px; margin-top: 12px; padding: 16px 12px 12px; font-weight: 600; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; }}

/* Progress */
QProgressBar {{ background-color: {C["border"]}; border: none; border-radius: 3px; text-align: center; color: {C["text"]}; font-size: 11px; height: 16px; }}
QProgressBar::chunk {{ background-color: {C["accent"]}; border-radius: 3px; }}

/* Scroll Bars */
QScrollBar:vertical {{ background: transparent; width: 8px; border: none; }}
QScrollBar::handle:vertical {{ background: {C["border"]}; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {C["text_muted"]}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 8px; border: none; }}
QScrollBar::handle:horizontal {{ background: {C["border"]}; border-radius: 4px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: {C["text_muted"]}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}

/* Tooltip */
QToolTip {{ background-color: {C["surface_elevated"]}; color: {C["text"]}; border: 1px solid {C["border"]}; border-radius: 4px; padding: 4px 8px; font-size: 12px; }}

/* SpinBox */
QSpinBox {{ background-color: {C["surface"]}; color: {C["text"]}; border: 1px solid {C["border"]}; border-radius: 6px; padding: 6px 10px; }}
"""


def run_app():
    app = QApplication(sys.argv)
    app.setApplicationName("DeepPierce")
    app.setStyle("Fusion")
    app.setStyleSheet(DARK_THEME)

    font = QFont()
    font.setPointSize(13)
    font.setFamilies(["SF Pro Display", "Helvetica Neue", "Arial"])
    app.setFont(font)

    from DeepPierce.gui.main_window import MainWindow
    window = MainWindow()
    window.resize(1400, 900)
    window.show()

    sys.exit(app.exec())
