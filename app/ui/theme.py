"""Modern dark-navy cybersecurity theme and programmatic vector icons for Walled AI MCP Guard."""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QIcon, QLinearGradient, QPainter, QPen, QPixmap, QPolygonF

# Color palette
BG_CANVAS = "#0B1220"
BG_PANEL = "#111B2E"
BG_CARD = "#152238"
BG_INPUT = "#0D1729"
BORDER_SUBTLE = "#1E3050"
BORDER_ACCENT = "#2D4A78"

TEXT_PRIMARY = "#F1F5F9"
TEXT_SECONDARY = "#94A3B8"
TEXT_MUTED = "#64748B"

ACCENT_CYAN = "#38BDF8"
STATUS_GREEN = "#10B981"
STATUS_GREEN_BG = "#064E3B"
STATUS_RED = "#EF4444"
STATUS_RED_BG = "#7F1D1D"
STATUS_AMBER = "#F59E0B"
STATUS_AMBER_BG = "#78350F"
STATUS_SLATE = "#64748B"


DARK_NAVY_STYLESHEET = f"""
QMainWindow, QDialog, QWidget {{
    background-color: {BG_CANVAS};
    color: {TEXT_PRIMARY};
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}}

QFrame#HeaderBar {{
    background-color: {BG_PANEL};
    border-bottom: 1px solid {BORDER_SUBTLE};
}}

QFrame#PanelCard {{
    background-color: {BG_PANEL};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: 10px;
}}

QFrame#MetricCard {{
    background-color: {BG_CARD};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: 10px;
}}

QFrame#PopupHeader {{
    background-color: #13203A;
    border-bottom: 1px solid {BORDER_ACCENT};
}}

QFrame#DetailBox {{
    background-color: {BG_PANEL};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: 8px;
}}

QLabel#AppTitle {{
    font-size: 19px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
    background: transparent;
}}

QLabel#AppSubtitle {{
    font-size: 12px;
    color: {TEXT_SECONDARY};
    background: transparent;
}}

QLabel#SectionTitle {{
    font-size: 14px;
    font-weight: 600;
    color: {TEXT_PRIMARY};
    background: transparent;
}}

QLabel#MetricLabel {{
    font-size: 12px;
    font-weight: 600;
    color: {TEXT_SECONDARY};
    background: transparent;
}}

QLabel#MetricValue {{
    font-size: 28px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
    background: transparent;
}}

QLabel#FieldLabel {{
    font-size: 11px;
    font-weight: 600;
    color: {TEXT_SECONDARY};
    background: transparent;
}}

QLabel#FieldValue {{
    font-size: 13px;
    font-weight: 600;
    color: {TEXT_PRIMARY};
    background: transparent;
}}

QLabel#MonoBadge {{
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 13px;
    font-weight: 700;
    color: {ACCENT_CYAN};
    background-color: {BG_INPUT};
    border: 1px solid {BORDER_ACCENT};
    border-radius: 6px;
    padding: 4px 10px;
}}

QLabel#StatusPillProtected {{
    background-color: {STATUS_GREEN_BG};
    color: #6EE7B7;
    border: 1px solid {STATUS_GREEN};
    border-radius: 12px;
    padding: 4px 12px;
    font-weight: 700;
    font-size: 12px;
}}

QLabel#StatusPillStopped {{
    background-color: {STATUS_RED_BG};
    color: #FCA5A5;
    border: 1px solid {STATUS_RED};
    border-radius: 12px;
    padding: 4px 12px;
    font-weight: 700;
    font-size: 12px;
}}

QLabel#StatusPillWarning {{
    background-color: {STATUS_AMBER_BG};
    color: #FDE68A;
    border: 1px solid {STATUS_AMBER};
    border-radius: 12px;
    padding: 4px 10px;
    font-weight: 700;
    font-size: 12px;
}}

QPushButton {{
    background-color: #1E2E4A;
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_ACCENT};
    border-radius: 7px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 13px;
}}

QPushButton:hover {{
    background-color: #263B5E;
}}

QPushButton:pressed {{
    background-color: #17253D;
}}

QPushButton:disabled {{
    background-color: #111A2B;
    color: {TEXT_MUTED};
    border-color: #1A2740;
}}

QPushButton#AllowButton, QPushButton#StartButton {{
    background-color: #059669;
    border: 1px solid {STATUS_GREEN};
    color: #FFFFFF;
}}

QPushButton#AllowButton:hover, QPushButton#StartButton:hover {{
    background-color: #10B981;
}}

QPushButton#AllowButton:disabled, QPushButton#StartButton:disabled {{
    background-color: #14352B;
    border-color: #1D4D3E;
    color: #64748B;
}}

QPushButton#BlockButton, QPushButton#StopButton {{
    background-color: #DC2626;
    border: 1px solid {STATUS_RED};
    color: #FFFFFF;
}}

QPushButton#BlockButton:hover, QPushButton#StopButton:hover {{
    background-color: #EF4444;
}}

QPushButton#BlockButton:disabled, QPushButton#StopButton:disabled {{
    background-color: #3D1A1F;
    border-color: #542229;
    color: #64748B;
}}

QPlainTextEdit {{
    background-color: {BG_INPUT};
    color: #E2E8F0;
    border: 1px solid {BORDER_SUBTLE};
    border-radius: 7px;
    padding: 8px;
    font-family: "Cascadia Code", "Consolas", monospace;
    font-size: 12px;
    selection-background-color: #2563EB;
}}

QTableWidget {{
    background-color: {BG_INPUT};
    alternate-background-color: #111D33;
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_SUBTLE};
    border-radius: 8px;
    gridline-color: #1A2942;
    selection-background-color: #1E3A5F;
    selection-color: {TEXT_PRIMARY};
}}

QTableWidget::item {{
    padding: 6px 8px;
}}

QHeaderView::section {{
    background-color: #14223B;
    color: {TEXT_SECONDARY};
    border: none;
    border-bottom: 1px solid {BORDER_ACCENT};
    border-right: 1px solid {BORDER_SUBTLE};
    padding: 8px 10px;
    font-weight: 700;
    font-size: 12px;
    text-align: left;
}}

QMenu {{
    background-color: {BG_PANEL};
    color: {TEXT_PRIMARY};
    border: 1px solid {BORDER_ACCENT};
    padding: 4px;
}}

QMenu::item {{
    padding: 6px 18px;
    border-radius: 4px;
}}

QMenu::item:selected {{
    background-color: #1E3A5F;
}}
"""


def create_shield_pixmap(size: int = 64, state: str = "protected") -> QPixmap:
    """Render a crisp cybersecurity shield emblem with an optional status badge."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    s = float(size)
    shield = QPolygonF(
        [
            QPointF(s * 0.50, s * 0.08),
            QPointF(s * 0.86, s * 0.22),
            QPointF(s * 0.82, s * 0.56),
            QPointF(s * 0.50, s * 0.92),
            QPointF(s * 0.18, s * 0.56),
            QPointF(s * 0.14, s * 0.22),
        ]
    )

    grad = QLinearGradient(0, 0, s, s)
    grad.setColorAt(0.0, QColor("#1D4ED8"))
    grad.setColorAt(1.0, QColor("#0F172A"))
    painter.setBrush(grad)
    painter.setPen(QPen(QColor(ACCENT_CYAN), max(1.5, s * 0.045)))
    painter.drawPolygon(shield)

    # Inner lock/check glyph
    inner_pen = QPen(QColor("#F8FAFC"), max(2.0, s * 0.06))
    inner_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    inner_pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(inner_pen)
    if state == "stopped":
        painter.drawLine(
            QPointF(s * 0.37, s * 0.37), QPointF(s * 0.63, s * 0.63)
        )
        painter.drawLine(
            QPointF(s * 0.63, s * 0.37), QPointF(s * 0.37, s * 0.63)
        )
    else:
        painter.drawLine(
            QPointF(s * 0.34, s * 0.50), QPointF(s * 0.46, s * 0.62)
        )
        painter.drawLine(
            QPointF(s * 0.46, s * 0.62), QPointF(s * 0.68, s * 0.38)
        )

    # Corner status indicator dot
    dot_color = {
        "protected": QColor(STATUS_GREEN),
        "pending": QColor(STATUS_AMBER),
        "stopped": QColor(STATUS_RED),
    }.get(state, QColor(ACCENT_CYAN))
    dot_r = s * 0.14
    painter.setBrush(dot_color)
    painter.setPen(QPen(QColor(BG_CANVAS), max(1.0, s * 0.03)))
    painter.drawEllipse(QPointF(s * 0.80, s * 0.80), dot_r, dot_r)

    painter.end()
    return pixmap


def create_shield_icon(state: str = "protected") -> QIcon:
    """Create a multi-resolution QIcon for window titlebars and system tray."""
    icon = QIcon()
    for sz in (16, 24, 32, 48, 64):
        icon.addPixmap(create_shield_pixmap(sz, state=state))
    return icon
