"""Capture real screenshots of the Walled AI MCP Guard dashboard and approval popup.

Drives the genuine StdioMCPProxy -> tests.test_mcp_server -> LocalAuthorizationBroker
-> GuardController -> PySide6 MainWindow & ApprovalPopup flow in offscreen mode and
renders crisp PNGs to docs/screenshots/.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.shared.exceptions import MCPError
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QApplication

from app.main import GuardController
from app.ui.main_window import MainWindow


def _load_windows_fonts_for_offscreen(app: QApplication) -> None:
    """Register standard Windows TTF fonts so Qt offscreen rendering draws crisp glyphs."""
    fonts_dir = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
    for fname in ("segoeui.ttf", "segoeuib.ttf", "consola.ttf", "consolab.ttf"):
        fpath = fonts_dir / fname
        if fpath.is_file():
            QFontDatabase.addApplicationFont(str(fpath))
    app.setFont(QFont("Segoe UI", 10))


def _pump_until(app: QApplication, pred, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if pred():
            return
        time.sleep(0.02)
    app.processEvents()
    if not pred():
        raise TimeoutError("Timed out waiting for Qt UI state.")


def capture(output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication(["capture-screenshots"])
    _load_windows_fonts_for_offscreen(app)

    with tempfile.TemporaryDirectory(prefix="mcp_guard_shots_") as tmp:
        tmp_path = Path(tmp)
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        broker_file = tmp_path / "broker.json"
        audit_file = tmp_path / "audit.jsonl"
        cfg_file = tmp_path / "servers.json"
        cfg_file.write_text(
            json.dumps(
                {
                    "default_server": "safe-test-server",
                    "approval_timeout_seconds": 60,
                    "servers": {
                        "safe-test-server": {
                            "description": "Safe local test MCP server",
                            "transport": "stdio",
                            "command": sys.executable,
                            "args": [
                                "-m",
                                "tests.test_mcp_server",
                                "--sandbox-dir",
                                str(sandbox),
                            ],
                            "enabled": True,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        controller = GuardController(
            audit_log_path=audit_file,
            timeout_seconds=60.0,
            configured_server_summary="Configured default: safe-test-server",
            broker_runtime_file=broker_file,
        )
        window = MainWindow(controller=controller, minimize_to_tray=False)
        window.show()

        try:
            controller.start_monitoring_sync(timeout=5.0)
            _pump_until(app, lambda: window.protection_badge.text() == "PROTECTED")

            async def _run_real_mcp() -> None:
                params = StdioServerParameters(
                    command=sys.executable,
                    args=[
                        "-m",
                        "app.proxy.stdio_proxy",
                        "--config",
                        str(cfg_file),
                        "--server",
                        "safe-test-server",
                        "--use-desktop-guard",
                        "--broker-file",
                        str(broker_file),
                    ],
                )
                async with stdio_client(params) as (r, w):
                    async with ClientSession(r, w) as session:
                        await session.initialize()
                        await session.list_tools()

                        # 1. Approved request
                        await session.call_tool("get_current_time", {})

                        # 2. Blocked request
                        try:
                            await session.call_tool(
                                "create_test_file",
                                {
                                    "filename": "unauthorized_write.txt",
                                    "content": "secret_value",
                                },
                            )
                        except MCPError:
                            pass

                        # 3. Pending request (kept open for popup screenshot, then allowed)
                        await session.call_tool(
                            "create_test_file",
                            {
                                "filename": "quarterly_report.txt",
                                "content": "Sensitive report text redacted in UI",
                            },
                        )

            fut = controller.worker.submit(_run_real_mcp())

            # Approve #1
            _pump_until(app, lambda: len(window.active_popups) == 1)
            p1 = next(iter(window.active_popups.values()))
            p1.allow_button.click()
            _pump_until(app, lambda: p1.internal_id not in window.active_popups)

            # Block #2
            _pump_until(app, lambda: len(window.active_popups) == 1)
            p2 = next(iter(window.active_popups.values()))
            p2.block_button.click()
            _pump_until(app, lambda: p2.internal_id not in window.active_popups)

            # Hold #3 open to capture live popup + dashboard screenshots
            _pump_until(app, lambda: len(window.active_popups) == 1)
            p3 = next(iter(window.active_popups.values()))
            for _ in range(5):
                app.processEvents()
                time.sleep(0.03)

            popup_path = output_dir / "approval_popup.png"
            p3.grab().save(str(popup_path))

            # Approve #3 and capture completed dashboard
            p3.allow_button.click()
            _pump_until(app, lambda: fut.done())
            _pump_until(app, lambda: window.total_count_label.text() == "3")
            for _ in range(5):
                app.processEvents()
                time.sleep(0.03)

            dashboard_path = output_dir / "dashboard.png"
            window.grab().save(str(dashboard_path))

            return dashboard_path, popup_path
        finally:
            window.prepare_for_exit()
            window.close()
            controller.shutdown_sync()


if __name__ == "__main__":
    dash, pop = capture(Path("docs/screenshots"))
    print("Saved screenshots:", dash, pop)
