"""Windows system tray integration for Walled AI MCP Guard."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from app.ui.theme import create_shield_icon


class GuardSystemTray(QSystemTrayIcon):
    """System tray icon with Dashboard, Start/Stop Monitoring, and Exit actions."""

    def __init__(
        self,
        *,
        on_open_dashboard: Callable[[], None],
        on_start_monitoring: Callable[[], None],
        on_stop_monitoring: Callable[[], None],
        on_exit: Callable[[], None],
        parent=None,
    ) -> None:
        super().__init__(create_shield_icon("stopped"), parent)
        self._on_open_dashboard = on_open_dashboard
        self.setToolTip("Walled AI MCP Guard — Stopped")

        self.menu = QMenu()
        self.open_action = QAction("Open Dashboard", self.menu)
        self.open_action.triggered.connect(on_open_dashboard)
        self.menu.addAction(self.open_action)

        self.menu.addSeparator()

        self.start_action = QAction("Start Monitoring", self.menu)
        self.start_action.triggered.connect(on_start_monitoring)
        self.menu.addAction(self.start_action)

        self.stop_action = QAction("Stop Monitoring", self.menu)
        self.stop_action.triggered.connect(on_stop_monitoring)
        self.menu.addAction(self.stop_action)

        self.menu.addSeparator()

        self.exit_action = QAction("Exit Walled AI MCP Guard", self.menu)
        self.exit_action.triggered.connect(on_exit)
        self.menu.addAction(self.exit_action)

        self.setContextMenu(self.menu)
        self.activated.connect(self._handle_activated)
        self.update_state(is_protected=False, pending_count=0)

    def _handle_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._on_open_dashboard()

    def update_state(self, *, is_protected: bool, pending_count: int = 0) -> None:
        """Update tray icon badge, tooltip, and enabled menu items."""
        if not is_protected:
            state_key = "stopped"
            tooltip = "Walled AI MCP Guard — Stopped"
        elif pending_count > 0:
            state_key = "pending"
            tooltip = (
                f"Walled AI MCP Guard — Protected ({pending_count} pending approval"
                f"{'s' if pending_count != 1 else ''})"
            )
        else:
            state_key = "protected"
            tooltip = "Walled AI MCP Guard — Protected"

        self.setIcon(create_shield_icon(state_key))
        self.setToolTip(tooltip)
        self.start_action.setEnabled(not is_protected)
        self.stop_action.setEnabled(is_protected)
