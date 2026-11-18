"""Main dashboard window for Walled AI MCP Guard."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.models.request import InterceptedRequest, RequestStatus
from app.ui.approval_popup import ApprovalPopup, sanitize_untrusted_text
from app.ui.theme import (
    ACCENT_CYAN,
    DARK_NAVY_STYLESHEET,
    STATUS_AMBER,
    STATUS_GREEN,
    STATUS_RED,
    TEXT_SECONDARY,
    create_shield_icon,
    create_shield_pixmap,
)


def _format_timestamp(ts: datetime | str | None) -> str:
    if ts is None:
        return "-"
    if isinstance(ts, datetime):
        return ts.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        parsed = datetime.fromisoformat(str(ts))
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return sanitize_untrusted_text(str(ts), max_length=40)


def _execution_result_for_request(req: InterceptedRequest) -> str:
    if req.status is RequestStatus.PENDING:
        return "awaiting_user"
    if req.status is RequestStatus.APPROVED:
        return "approved"
    if req.status is RequestStatus.EXECUTING:
        return "executing"
    if req.status is RequestStatus.COMPLETED:
        return "success"
    if req.status in (
        RequestStatus.BLOCKED,
        RequestStatus.TIMED_OUT,
        RequestStatus.CANCELLED,
    ):
        return "not_executed"
    return "failed"


def _status_color(status_text: str) -> QColor:
    upper = status_text.upper()
    if upper in ("COMPLETED", "APPROVED", "ALLOW", "SUCCESS"):
        return QColor(STATUS_GREEN)
    if upper in ("BLOCKED", "BLOCK", "FAILED", "ERROR"):
        return QColor(STATUS_RED)
    if upper in ("PENDING", "TIMED_OUT", "TIMEOUT", "CANCELLED", "EXECUTING"):
        return QColor(STATUS_AMBER)
    return QColor(TEXT_SECONDARY)


def load_recent_audit_entries(log_path: Path, limit: int = 100) -> list[dict[str, Any]]:
    """Read recent deduplicated request summaries from the JSONL audit log safely."""
    if not log_path.is_file():
        return []
    by_internal_id: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    try:
        lines = log_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(rec, dict):
            continue
        internal_id = str(rec.get("internal_id", "")).strip()
        if not internal_id:
            continue
        if internal_id not in by_internal_id:
            order.append(internal_id)
        by_internal_id[internal_id] = {
            "internal_id": internal_id,
            "request_id": rec.get("request_id"),
            "server_name": str(rec.get("server_name", "-")),
            "tool_name": str(rec.get("tool_name", "-")),
            "decision": rec.get("decision") or "-",
            "status": str(rec.get("status", "-")),
            "timestamp": rec.get("timestamp"),
            "execution_result": str(rec.get("execution_result", "-")),
        }

    recent_ids = order[-limit:] if limit > 0 else []
    return [by_internal_id[rid] for rid in reversed(recent_ids)]


class MainWindow(QMainWindow):
    """Walled AI MCP Guard main desktop security dashboard."""

    HISTORY_COLUMNS = (
        "Request ID",
        "MCP Server",
        "Tool Name",
        "Decision",
        "Status",
        "Timestamp",
        "Execution Result",
    )

    def __init__(
        self,
        *,
        controller: Any,
        minimize_to_tray: bool = True,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._controller = controller
        self._minimize_to_tray = minimize_to_tray
        self._force_quit = False
        self._popups: dict[str, ApprovalPopup] = {}
        self._historical_audit_rows: list[dict[str, Any]] = []

        self.setWindowTitle("Walled AI MCP Guard")
        self.setWindowIcon(create_shield_icon("stopped"))
        self.setStyleSheet(DARK_NAVY_STYLESHEET)
        self.setMinimumSize(980, 640)
        self.resize(1140, 740)

        self._build_ui()
        self._connect_controller_signals()
        self._load_initial_audit_history()
        self.refresh_dashboard()

    @property
    def active_popups(self) -> dict[str, ApprovalPopup]:
        """Return currently open approval popups keyed by internal_id."""
        return dict(self._popups)

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # --------------------------------------------------------------
        # Header Bar
        # --------------------------------------------------------------
        header = QFrame()
        header.setObjectName("HeaderBar")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(22, 16, 22, 16)
        header_layout.setSpacing(14)

        self.header_icon = QLabel()
        self.header_icon.setPixmap(create_shield_pixmap(42, state="stopped"))
        self.header_icon.setStyleSheet("background: transparent;")
        header_layout.addWidget(self.header_icon)

        brand_col = QVBoxLayout()
        brand_col.setSpacing(2)
        title = QLabel("Walled AI MCP Guard")
        title.setObjectName("AppTitle")
        subtitle = QLabel("Real-Time MCP Communication Monitoring & User Authorization")
        subtitle.setObjectName("AppSubtitle")
        brand_col.addWidget(title)
        brand_col.addWidget(subtitle)
        header_layout.addLayout(brand_col, 1)

        self.protection_badge = QLabel("STOPPED")
        self.protection_badge.setObjectName("StatusPillStopped")
        header_layout.addWidget(self.protection_badge)

        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setObjectName("StartButton")
        self.start_button.setMinimumHeight(36)
        self.start_button.clicked.connect(self._controller.start_monitoring)
        header_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setObjectName("StopButton")
        self.stop_button.setMinimumHeight(36)
        self.stop_button.clicked.connect(self._controller.stop_monitoring)
        header_layout.addWidget(self.stop_button)

        root.addWidget(header)

        # --------------------------------------------------------------
        # Main Content Body
        # --------------------------------------------------------------
        content = QVBoxLayout()
        content.setContentsMargins(22, 18, 22, 20)
        content.setSpacing(16)

        # Connection Status Strip
        conn_panel = QFrame()
        conn_panel.setObjectName("PanelCard")
        conn_layout = QHBoxLayout(conn_panel)
        conn_layout.setContentsMargins(16, 12, 16, 12)
        conn_layout.setSpacing(24)

        self.proxy_status_value = self._add_status_column(
            conn_layout, "MCP PROXY STATUS", "Stopped"
        )
        self.server_info_value = self._add_status_column(
            conn_layout,
            "CONNECTED MCP SERVER",
            sanitize_untrusted_text(self._controller.configured_server_summary),
        )
        self.audit_path_value = self._add_status_column(
            conn_layout,
            "AUDIT LOG",
            str(self._controller.audit_log_path),
        )
        conn_layout.addStretch(1)

        self.focus_popups_button = QPushButton("Focus Pending Popups (0)")
        self.focus_popups_button.setVisible(False)
        self.focus_popups_button.clicked.connect(self._focus_all_popups)
        conn_layout.addWidget(self.focus_popups_button)

        content.addWidget(conn_panel)

        # KPI Metric Cards
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(14)

        self.total_count_label = self._create_metric_card(
            kpi_row, "TOTAL REQUESTS", ACCENT_CYAN
        )
        self.approved_count_label = self._create_metric_card(
            kpi_row, "APPROVED", STATUS_GREEN
        )
        self.blocked_count_label = self._create_metric_card(
            kpi_row, "BLOCKED / DENIED", STATUS_RED
        )
        self.pending_count_label = self._create_metric_card(
            kpi_row, "PENDING APPROVAL", STATUS_AMBER
        )
        content.addLayout(kpi_row)

        # Activity / Request History Panel
        history_panel = QFrame()
        history_panel.setObjectName("PanelCard")
        history_layout = QVBoxLayout(history_panel)
        history_layout.setContentsMargins(16, 14, 16, 16)
        history_layout.setSpacing(10)

        history_header_row = QHBoxLayout()
        history_title = QLabel("Recent MCP Activity & Authorization History")
        history_title.setObjectName("SectionTitle")
        history_note = QLabel(
            "Live RequestManager records & redacted audit trail (secrets/file contents hidden)"
        )
        history_note.setObjectName("AppSubtitle")
        history_header_row.addWidget(history_title)
        history_header_row.addStretch(1)
        history_header_row.addWidget(history_note)
        history_layout.addLayout(history_header_row)

        self.history_table = QTableWidget(0, len(self.HISTORY_COLUMNS))
        self.history_table.setHorizontalHeaderLabels(list(self.HISTORY_COLUMNS))
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.history_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.history_table.verticalHeader().setVisible(False)

        header_view = self.history_table.horizontalHeader()
        header_view.setStretchLastSection(True)
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )

        history_layout.addWidget(self.history_table, 1)
        content.addWidget(history_panel, 1)

        root.addLayout(content, 1)

    def _add_status_column(
        self, layout: QHBoxLayout, label_text: str, initial_value: str
    ) -> QLabel:
        col = QVBoxLayout()
        col.setSpacing(3)
        lbl = QLabel(label_text)
        lbl.setObjectName("FieldLabel")
        val = QLabel()
        val.setObjectName("FieldValue")
        val.setTextFormat(Qt.TextFormat.PlainText)
        val.setText(initial_value)
        col.addWidget(lbl)
        col.addWidget(val)
        layout.addLayout(col)
        return val

    def _create_metric_card(
        self, layout: QHBoxLayout, label_text: str, accent_hex: str
    ) -> QLabel:
        card = QFrame()
        card.setObjectName("MetricCard")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 14, 16, 14)
        card_layout.setSpacing(6)

        lbl = QLabel(label_text)
        lbl.setObjectName("MetricLabel")
        val = QLabel("0")
        val.setObjectName("MetricValue")
        val.setStyleSheet(
            f"font-size: 28px; font-weight: 700; color: {accent_hex}; background: transparent;"
        )

        card_layout.addWidget(lbl)
        card_layout.addWidget(val)
        layout.addWidget(card, 1)
        return val

    def _connect_controller_signals(self) -> None:
        self._controller.pending_request_arrived.connect(
            self._on_pending_request_arrived
        )
        self._controller.request_updated.connect(self._on_request_updated)
        self._controller.request_resolved.connect(self._on_request_resolved)
        self._controller.monitoring_changed.connect(self._on_monitoring_changed)
        self._controller.proxy_status_changed.connect(self._on_proxy_status_changed)

    def _load_initial_audit_history(self) -> None:
        self._historical_audit_rows = load_recent_audit_entries(
            self._controller.audit_log_path, limit=100
        )

    # ------------------------------------------------------------------
    # Slots wired to GuardController (always executed on Qt GUI thread)
    # ------------------------------------------------------------------

    def _on_monitoring_changed(self, is_protected: bool, broker_detail: str) -> None:
        self._update_protection_indicators(is_protected, broker_detail)

    def _on_proxy_status_changed(
        self, state: str, server_name: str, detail: str
    ) -> None:
        clean_server = sanitize_untrusted_text(server_name, max_length=128)
        clean_detail = sanitize_untrusted_text(detail, max_length=160)
        if state == "connected":
            self.proxy_status_value.setText("Connected (Active MCP Session)")
            self.proxy_status_value.setStyleSheet(
                f"color: {STATUS_GREEN}; font-weight: 700; background: transparent;"
            )
            info_text = f"{clean_server} — {clean_detail}" if clean_detail else clean_server
            self.server_info_value.setText(info_text)
        elif state == "disconnected":
            if self._controller.is_monitoring:
                self.proxy_status_value.setText("Listening (Awaiting MCP Proxy)")
                self.proxy_status_value.setStyleSheet(
                    f"color: {ACCENT_CYAN}; font-weight: 600; background: transparent;"
                )
            else:
                self.proxy_status_value.setText("Stopped")
                self.proxy_status_value.setStyleSheet(
                    f"color: {STATUS_RED}; font-weight: 600; background: transparent;"
                )
            self.server_info_value.setText(
                sanitize_untrusted_text(self._controller.configured_server_summary)
            )
        else:
            self.proxy_status_value.setText(f"Error: {clean_detail or 'Proxy error'}")
            self.proxy_status_value.setStyleSheet(
                f"color: {STATUS_RED}; font-weight: 700; background: transparent;"
            )

    def _on_pending_request_arrived(self, request: InterceptedRequest) -> None:
        self.refresh_dashboard()
        if request.internal_id in self._popups:
            self._popups[request.internal_id].bring_to_front()
            return

        popup = ApprovalPopup(
            request=request,
            timeout_seconds=self._controller.timeout_seconds,
            on_allow=self._controller.approve_request,
            on_block=self._controller.block_request,
            parent=None,
        )
        self._popups[request.internal_id] = popup
        self._position_popup_cascaded(popup, len(self._popups) - 1)
        popup.bring_to_front()
        self._update_pending_popup_button()

    def _on_request_updated(self, request: InterceptedRequest) -> None:
        self.refresh_dashboard()

    def _on_request_resolved(self, request: InterceptedRequest) -> None:
        popup = self._popups.pop(request.internal_id, None)
        if popup is not None:
            reason = request.decision.reason if request.decision is not None else ""
            if not popup.is_decided:
                popup.handle_external_resolution(request.status, reason=reason)
            popup.deleteLater()
        self._update_pending_popup_button()
        self.refresh_dashboard()

    # ------------------------------------------------------------------
    # Rendering & Refresh Helpers
    # ------------------------------------------------------------------

    def _position_popup_cascaded(self, popup: ApprovalPopup, index: int) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            return
        geo = screen.availableGeometry()
        offset = (index % 6) * 34
        x = geo.center().x() - popup.width() // 2 + offset
        y = geo.center().y() - popup.height() // 2 + offset
        popup.move(max(geo.left() + 20, x), max(geo.top() + 20, y))

    def _focus_all_popups(self) -> None:
        for popup in self._popups.values():
            popup.bring_to_front()

    def _update_pending_popup_button(self) -> None:
        count = len(self._popups)
        self.focus_popups_button.setVisible(count > 0)
        self.focus_popups_button.setText(f"Focus Pending Popups ({count})")

    def _update_protection_indicators(
        self, is_protected: bool, broker_detail: str = ""
    ) -> None:
        pending_count = self._controller.request_manager.get_stats()["pending"]
        if is_protected:
            self.protection_badge.setText("PROTECTED")
            self.protection_badge.setObjectName("StatusPillProtected")
            icon_state = "pending" if pending_count > 0 else "protected"
            self.header_icon.setPixmap(create_shield_pixmap(42, state=icon_state))
            self.setWindowIcon(create_shield_icon(icon_state))
            if "Connected" not in self.proxy_status_value.text():
                status_text = (
                    f"Listening ({broker_detail})"
                    if broker_detail
                    else "Listening (Ready for MCP Proxy)"
                )
                self.proxy_status_value.setText(status_text)
                self.proxy_status_value.setStyleSheet(
                    f"color: {ACCENT_CYAN}; font-weight: 600; background: transparent;"
                )
        else:
            self.protection_badge.setText("STOPPED")
            self.protection_badge.setObjectName("StatusPillStopped")
            self.header_icon.setPixmap(create_shield_pixmap(42, state="stopped"))
            self.setWindowIcon(create_shield_icon("stopped"))
            self.proxy_status_value.setText("Stopped (Fail-Closed)")
            self.proxy_status_value.setStyleSheet(
                f"color: {STATUS_RED}; font-weight: 600; background: transparent;"
            )

        # Re-polish QSS after changing dynamic objectName
        self.protection_badge.style().unpolish(self.protection_badge)
        self.protection_badge.style().polish(self.protection_badge)
        self.start_button.setEnabled(not is_protected)
        self.stop_button.setEnabled(is_protected)

    def refresh_dashboard(self) -> None:
        """Refresh all KPI counters and the recent request history table from real state."""
        stats = self._controller.request_manager.get_stats()
        self.total_count_label.setText(str(stats["total"]))
        self.approved_count_label.setText(str(stats["approved_total"]))
        self.blocked_count_label.setText(str(stats["blocked_total"]))
        self.pending_count_label.setText(str(stats["pending"]))

        self._update_protection_indicators(
            self._controller.is_monitoring, self._controller.broker_endpoint_label
        )
        self._refresh_history_table()

    def _refresh_history_table(self) -> None:
        live_requests = self._controller.request_manager.list_recent(limit=100)
        live_ids = {req.internal_id for req in live_requests}

        rows: list[dict[str, Any]] = []
        for req in live_requests:
            rows.append(
                {
                    "request_id": req.jsonrpc_request_id,
                    "internal_id": req.internal_id,
                    "server_name": req.server_name,
                    "tool_name": req.tool_name,
                    "decision": req.decision.outcome.value if req.decision else "PENDING",
                    "status": req.status.value,
                    "timestamp": req.created_at,
                    "execution_result": _execution_result_for_request(req),
                }
            )

        # Append persisted historical JSONL records from prior runs (deduplicated).
        for hist in self._historical_audit_rows:
            if hist["internal_id"] not in live_ids:
                rows.append(hist)

        rows = rows[:100]
        self.history_table.setUpdatesEnabled(False)
        try:
            self.history_table.setRowCount(len(rows))

            for row_idx, entry in enumerate(rows):
                rpc_id = entry["request_id"]
                req_id_display = (
                    f"#{rpc_id}" if rpc_id is not None else entry["internal_id"][:8]
                )
                values = (
                    sanitize_untrusted_text(req_id_display, max_length=32),
                    sanitize_untrusted_text(entry["server_name"], max_length=64),
                    sanitize_untrusted_text(entry["tool_name"], max_length=96),
                    sanitize_untrusted_text(str(entry["decision"]), max_length=32),
                    sanitize_untrusted_text(str(entry["status"]), max_length=32),
                    _format_timestamp(entry["timestamp"]),
                    sanitize_untrusted_text(str(entry["execution_result"]), max_length=32),
                )
                for col_idx, cell_text in enumerate(values):
                    item = QTableWidgetItem(cell_text)
                    item.setFlags(
                        Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled
                    )
                    if col_idx in (3, 4):
                        item.setForeground(_status_color(cell_text))
                    self.history_table.setItem(row_idx, col_idx, item)
        finally:
            self.history_table.setUpdatesEnabled(True)

    # ------------------------------------------------------------------
    # Window lifecycle & System Tray close handling
    # ------------------------------------------------------------------

    def prepare_for_exit(self) -> None:
        """Close all open popups cleanly and allow window close on explicit app Exit."""
        self._force_quit = True
        for popup in list(self._popups.values()):
            popup.handle_external_resolution(
                RequestStatus.CANCELLED, reason="Application exiting."
            )
            popup.deleteLater()
        self._popups.clear()
        self._update_pending_popup_button()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._minimize_to_tray and not self._force_quit:
            event.ignore()
            self.hide()
            return
        self.prepare_for_exit()
        event.accept()
