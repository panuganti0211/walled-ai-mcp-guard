"""Always-on-top PySide6 authorization popup for intercepted MCP tool calls."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import timezone

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCloseEvent, QKeyEvent
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
)

from app.models.request import InterceptedRequest, RequestStatus
from app.monitoring.audit_logger import redact_sensitive_data
from app.ui.theme import (
    DARK_NAVY_STYLESHEET,
    create_shield_icon,
    create_shield_pixmap,
)

# Strip non-printable control chars (keep newline and tab) from untrusted MCP strings.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_untrusted_text(text: str | None, *, max_length: int = 1000) -> str:
    """Sanitize untrusted MCP text for safe plain-text display in Qt widgets."""
    if not text:
        return ""
    cleaned = _CONTROL_CHAR_RE.sub("", str(text))
    if len(cleaned) > max_length:
        return cleaned[:max_length] + f"... [truncated {len(cleaned) - max_length} chars]"
    return cleaned


def format_safe_parameters(arguments: dict) -> str:
    """Redact sensitive fields and format MCP tool parameters as readable plain JSON."""
    if not arguments:
        return "{}"
    redacted = redact_sensitive_data(arguments)
    try:
        rendered = json.dumps(redacted, indent=2, ensure_ascii=False, sort_keys=True)
    except Exception:
        rendered = "{}"
    return sanitize_untrusted_text(rendered, max_length=4000)


class ApprovalPopup(QDialog):
    """Dedicated always-on-top authorization dialog bound to a single InterceptedRequest.

    Security UX invariants:
    - Always displays above other active Windows applications (`WindowStaysOnTopHint`).
    - All untrusted MCP fields render strictly as `Qt.TextFormat.PlainText` (no HTML/RichText).
    - Sensitive parameter fields and bulky payloads are redacted via `redact_sensitive_data`.
    - Cannot be silently dismissed with `Esc` or `X` while pending; requires an explicit
      Allow or Block click, or an external policy resolution (timeout / shutdown).
    - Decision buttons disable immediately after a single click to prevent duplicate calls.
    """

    def __init__(
        self,
        *,
        request: InterceptedRequest,
        timeout_seconds: float,
        on_allow: Callable[[str], None],
        on_block: Callable[[str], None],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._internal_id = request.internal_id
        self._request = request
        self._on_allow = on_allow
        self._on_block = on_block
        self._decided = False
        self._allow_close = False
        self._remaining_seconds = max(0, int(round(timeout_seconds)))

        self.setObjectName("ApprovalPopup")
        self.setWindowTitle("Walled AI MCP Guard — Authorization Required")
        self.setWindowIcon(create_shield_icon("pending"))
        self.setStyleSheet(DARK_NAVY_STYLESHEET)

        # Stay above other active applications without locking the entire desktop modal loop
        # so multiple concurrent requests can each display and be decided independently.
        self.setWindowFlags(
            Qt.WindowType.Window
            | Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.WindowTitleHint
            | Qt.WindowType.CustomizeWindowHint
        )
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.setMinimumSize(560, 480)
        self.resize(620, 540)

        self._build_ui(request)

        # Visual countdown timer (enforcement remains strictly in ApprovalManager).
        self._countdown_timer = QTimer(self)
        self._countdown_timer.setInterval(1000)
        self._countdown_timer.timeout.connect(self._tick_countdown)
        self._countdown_timer.start()

    @property
    def internal_id(self) -> str:
        return self._internal_id

    @property
    def is_decided(self) -> bool:
        return self._decided

    def _plain_label(self, text: str, object_name: str = "FieldValue") -> QLabel:
        label = QLabel()
        label.setObjectName(object_name)
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setText(text)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        return label

    def _build_ui(self, request: InterceptedRequest) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header banner
        header = QFrame()
        header.setObjectName("PopupHeader")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(18, 14, 18, 14)
        header_layout.setSpacing(12)

        icon_label = QLabel()
        icon_label.setPixmap(create_shield_pixmap(38, state="pending"))
        icon_label.setStyleSheet("background: transparent;")
        header_layout.addWidget(icon_label)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_lbl = self._plain_label("MCP Tool Execution Request", "AppTitle")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 700; background: transparent;")
        subtitle_lbl = self._plain_label(
            "Review untrusted request details carefully before allowing execution.",
            "AppSubtitle",
        )
        title_col.addWidget(title_lbl)
        title_col.addWidget(subtitle_lbl)
        header_layout.addLayout(title_col, 1)

        self.countdown_badge = self._plain_label(
            f"Timeout: {self._remaining_seconds}s", "StatusPillWarning"
        )
        self.countdown_badge.setWordWrap(False)
        self.countdown_badge.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed
        )
        header_layout.addWidget(
            self.countdown_badge,
            0,
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
        )
        root.addWidget(header)

        # Body content
        body = QVBoxLayout()
        body.setContentsMargins(18, 16, 18, 16)
        body.setSpacing(12)

        # Metadata card
        meta_frame = QFrame()
        meta_frame.setObjectName("DetailBox")
        meta_grid = QGridLayout(meta_frame)
        meta_grid.setContentsMargins(14, 12, 14, 12)
        meta_grid.setHorizontalSpacing(14)
        meta_grid.setVerticalSpacing(8)

        server_text = sanitize_untrusted_text(request.server_name, max_length=128)
        tool_text = sanitize_untrusted_text(request.tool_name, max_length=256)
        rpc_id_text = (
            str(request.jsonrpc_request_id)
            if request.jsonrpc_request_id is not None
            else "N/A"
        )
        short_internal = request.internal_id[:12]
        ts_text = request.created_at.astimezone(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )

        meta_grid.addWidget(self._plain_label("MCP SERVER", "FieldLabel"), 0, 0)
        self.server_label = self._plain_label(server_text, "FieldValue")
        meta_grid.addWidget(self.server_label, 0, 1)

        meta_grid.addWidget(self._plain_label("TOOL NAME", "FieldLabel"), 1, 0)
        self.tool_label = self._plain_label(tool_text, "MonoBadge")
        self.tool_label.setWordWrap(False)
        self.tool_label.setMinimumHeight(28)
        self.tool_label.setSizePolicy(
            QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed
        )
        meta_grid.addWidget(self.tool_label, 1, 1, Qt.AlignmentFlag.AlignLeft)

        meta_grid.addWidget(self._plain_label("REQUEST ID", "FieldLabel"), 2, 0)
        self.request_id_label = self._plain_label(
            f"JSON-RPC #{rpc_id_text}  (Internal: {short_internal})",
            "FieldValue",
        )
        meta_grid.addWidget(self.request_id_label, 2, 1)

        meta_grid.addWidget(self._plain_label("TIMESTAMP", "FieldLabel"), 3, 0)
        self.timestamp_label = self._plain_label(ts_text, "FieldValue")
        meta_grid.addWidget(self.timestamp_label, 3, 1)

        meta_grid.setColumnStretch(1, 1)
        body.addWidget(meta_frame)

        # Description section
        desc_header = self._plain_label(
            "TOOL DESCRIPTION (Untrusted Server Metadata)", "FieldLabel"
        )
        body.addWidget(desc_header)

        desc_text = sanitize_untrusted_text(
            request.tool_description, max_length=600
        ) or "No description provided by upstream MCP server."
        self.description_box = QPlainTextEdit()
        self.description_box.setReadOnly(True)
        self.description_box.setPlainText(desc_text)
        self.description_box.setMaximumHeight(74)
        body.addWidget(self.description_box)

        # Parameters section (redacted)
        params_header = self._plain_label(
            "REQUEST PARAMETERS (Sensitive Values & Raw Bodies Redacted)",
            "FieldLabel",
        )
        body.addWidget(params_header)

        self.parameters_box = QPlainTextEdit()
        self.parameters_box.setReadOnly(True)
        self.parameters_box.setPlainText(format_safe_parameters(request.arguments))
        body.addWidget(self.parameters_box, 1)

        # Status feedback line
        self.status_label = self._plain_label(
            "Pending your decision — upstream tool execution is held.",
            "AppSubtitle",
        )
        body.addWidget(self.status_label)

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)
        btn_row.addStretch(1)

        self.block_button = QPushButton("Block Execution")
        self.block_button.setObjectName("BlockButton")
        self.block_button.setMinimumWidth(150)
        self.block_button.setMinimumHeight(38)
        self.block_button.clicked.connect(self._handle_block_clicked)
        btn_row.addWidget(self.block_button)

        self.allow_button = QPushButton("Allow Execution")
        self.allow_button.setObjectName("AllowButton")
        self.allow_button.setMinimumWidth(150)
        self.allow_button.setMinimumHeight(38)
        self.allow_button.clicked.connect(self._handle_allow_clicked)
        btn_row.addWidget(self.allow_button)

        body.addLayout(btn_row)
        root.addLayout(body, 1)

    def _tick_countdown(self) -> None:
        if self._decided:
            self._countdown_timer.stop()
            return
        if self._remaining_seconds > 0:
            self._remaining_seconds -= 1
            self.countdown_badge.setText(f"Timeout: {self._remaining_seconds}s")
        else:
            self.countdown_badge.setText("Timed out")
            self._countdown_timer.stop()

    def _disable_decision_buttons(self) -> None:
        self.allow_button.setEnabled(False)
        self.block_button.setEnabled(False)

    def _handle_allow_clicked(self) -> None:
        if self._decided:
            return
        self._decided = True
        self._allow_close = True
        self._countdown_timer.stop()
        self._disable_decision_buttons()
        self.status_label.setText("Approved by user. Forwarding request upstream...")
        try:
            self._on_allow(self._internal_id)
        finally:
            self.close()

    def _handle_block_clicked(self) -> None:
        if self._decided:
            return
        self._decided = True
        self._allow_close = True
        self._countdown_timer.stop()
        self._disable_decision_buttons()
        self.status_label.setText("Blocked by user. Upstream execution prevented.")
        try:
            self._on_block(self._internal_id)
        finally:
            self.close()

    def handle_external_resolution(self, status: RequestStatus, reason: str = "") -> None:
        """Close popup safely when resolved externally (timeout, shutdown, etc.)."""
        self._decided = True
        self._allow_close = True
        self._countdown_timer.stop()
        self._disable_decision_buttons()
        clean_reason = sanitize_untrusted_text(reason, max_length=200)
        self.status_label.setText(
            f"Resolved ({status.value}){': ' + clean_reason if clean_reason else ''}"
        )
        self.close()

    def bring_to_front(self) -> None:
        """Show and raise the popup above active Windows applications."""
        self.show()
        self.raise_()
        self.activateWindow()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        # Never allow Escape to dismiss an undecided security authorization popup.
        if event.key() == Qt.Key.Key_Escape and not self._allow_close:
            event.ignore()
            return
        super().keyPressEvent(event)

    def closeEvent(self, event: QCloseEvent) -> None:
        # Prevent closing while still awaiting an explicit user decision.
        if not self._allow_close:
            self.status_label.setText(
                "Please choose Allow Execution or Block Execution to resolve this request."
            )
            event.ignore()
            return
        self._countdown_timer.stop()
        event.accept()
