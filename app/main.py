"""Desktop application controller, asyncio worker thread, and entrypoint for Walled AI MCP Guard."""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import logging
import sys
import threading
from pathlib import Path
from typing import Any, Coroutine, TypeVar

from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication, QSystemTrayIcon

from app.authorization.approval_manager import (
    ApprovalManager,
    DuplicateDecisionError,
    UnknownRequestError,
)
from app.authorization.ipc_broker import (
    LocalAuthorizationBroker,
    default_broker_runtime_file,
)
from app.authorization.request_manager import RequestManager
from app.config import GuardConfig, load_config
from app.models.request import InterceptedRequest
from app.monitoring.audit_logger import AuditLogger
from app.ui.main_window import MainWindow
from app.ui.system_tray import GuardSystemTray

logger = logging.getLogger(__name__)
T = TypeVar("T")


class AsyncioWorkerThread:
    """Dedicated background daemon thread running a native asyncio event loop.

    Architecture decision:
        On Windows + Python 3.14 + PySide6 6.12 + MCP SDK 2.3.0 (`anyio`),
        running a dedicated native `asyncio.ProactorEventLoop` thread keeps
        Qt's GUI thread 100% responsive and preserves full native Windows IOCP
        subprocess/socket behavior without third-party `qasync` compatibility
        risks. Cross-thread communication uses `loop.call_soon_threadsafe`,
        `asyncio.run_coroutine_threadsafe`, and Qt queued signals.
    """

    def __init__(self, name: str = "mcp-guard-asyncio") -> None:
        self._name = name
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._stopped = threading.Event()

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            raise RuntimeError("AsyncioWorkerThread has not been started.")
        return self._loop

    @property
    def is_running(self) -> bool:
        return (
            self._thread is not None
            and self._thread.is_alive()
            and self._loop is not None
            and self._loop.is_running()
        )

    def start(self, timeout: float = 5.0) -> None:
        if self.is_running:
            return
        self._ready.clear()
        self._stopped.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name=self._name, daemon=True
        )
        self._thread.start()
        if not self._ready.wait(timeout=timeout):
            raise RuntimeError("Timed out starting AsyncioWorkerThread.")

    def _run_loop(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        loop.call_soon(self._ready.set)
        try:
            loop.run_forever()
        finally:
            try:
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                logger.debug("Error draining worker loop tasks on shutdown.", exc_info=True)
            finally:
                loop.close()
                self._stopped.set()

    def submit(
        self, coro: Coroutine[Any, Any, T]
    ) -> concurrent.futures.Future[T]:
        """Schedule a coroutine onto the background asyncio loop (thread-safe)."""
        if not self.is_running:
            coro.close()
            raise RuntimeError("AsyncioWorkerThread is not running.")
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the background event loop cleanly and join the worker thread."""
        if self._loop is not None and self._loop.is_running():
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except RuntimeError:
                pass
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._thread = None
        self._loop = None


class GuardController(QObject):
    """Thread-safe bridge connecting ApprovalManager/Broker (asyncio thread) to PySide6 UI."""

    pending_request_arrived = Signal(object)  # InterceptedRequest
    request_updated = Signal(object)  # InterceptedRequest
    request_resolved = Signal(object)  # InterceptedRequest
    monitoring_changed = Signal(bool, str)  # is_protected, broker_endpoint_label
    proxy_status_changed = Signal(str, str, str)  # state, server_name, detail

    def __init__(
        self,
        *,
        audit_log_path: str | Path = "logs/audit.jsonl",
        timeout_seconds: float = 120.0,
        configured_server_summary: str = "Configured MCP Server (Awaiting Proxy)",
        broker_runtime_file: str | Path | None = None,
        enable_local_broker: bool = True,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._audit_log_path = Path(audit_log_path)
        self._timeout_seconds = float(timeout_seconds)
        self._configured_server_summary = configured_server_summary
        self._enable_local_broker = enable_local_broker
        self._is_monitoring = False
        self._broker_endpoint_label = ""
        self._shutdown_lock = threading.Lock()
        self._closed = False

        self._worker = AsyncioWorkerThread()
        self._worker.start()

        self._audit_logger = AuditLogger(self._audit_log_path)
        self._request_manager = RequestManager(
            on_change=self._handle_request_manager_change
        )
        self._approval_manager = ApprovalManager(
            request_manager=self._request_manager,
            audit_logger=self._audit_logger,
            timeout_seconds=self._timeout_seconds,
            on_pending_request=self._handle_pending_request,
            on_request_resolved=self._handle_request_resolved,
        )
        # Start in stopped state until Start Monitoring is triggered.
        self._broker = LocalAuthorizationBroker(
            approval_manager=self._approval_manager,
            runtime_file=broker_runtime_file or default_broker_runtime_file(),
            on_proxy_status=self._handle_proxy_status,
        )

    @property
    def worker(self) -> AsyncioWorkerThread:
        return self._worker

    @property
    def request_manager(self) -> RequestManager:
        return self._request_manager

    @property
    def approval_manager(self) -> ApprovalManager:
        return self._approval_manager

    @property
    def audit_logger(self) -> AuditLogger:
        return self._audit_logger

    @property
    def audit_log_path(self) -> Path:
        return self._audit_log_path

    @property
    def timeout_seconds(self) -> float:
        return self._timeout_seconds

    @property
    def configured_server_summary(self) -> str:
        return self._configured_server_summary

    @property
    def broker(self) -> LocalAuthorizationBroker:
        return self._broker

    @property
    def is_monitoring(self) -> bool:
        return self._is_monitoring

    @property
    def broker_endpoint_label(self) -> str:
        return self._broker_endpoint_label

    # ------------------------------------------------------------------
    # Thread-safe callbacks invoked from asyncio thread -> Qt signals
    # ------------------------------------------------------------------

    def _handle_pending_request(self, request: InterceptedRequest) -> None:
        if not self._closed:
            self.pending_request_arrived.emit(request)

    def _handle_request_manager_change(self, request: InterceptedRequest) -> None:
        if not self._closed:
            self.request_updated.emit(request)

    def _handle_request_resolved(self, request: InterceptedRequest) -> None:
        if not self._closed:
            self.request_resolved.emit(request)

    def _handle_proxy_status(self, state: str, server_name: str, detail: str) -> None:
        if not self._closed:
            self.proxy_status_changed.emit(state, server_name, detail)

    # ------------------------------------------------------------------
    # GUI controls (called on Qt main thread; non-blocking)
    # ------------------------------------------------------------------

    def start_monitoring(self) -> concurrent.futures.Future[str]:
        """Start monitoring and the authenticated localhost broker without blocking Qt."""
        self._approval_manager.resume()
        self._is_monitoring = True

        async def _start() -> str:
            if self._enable_local_broker:
                info = await self._broker.start()
                return info.url
            return "in-process"

        fut = self._worker.submit(_start())

        def _done(f: concurrent.futures.Future[str]) -> None:
            if self._closed:
                return
            try:
                endpoint = f.result()
                self._broker_endpoint_label = endpoint
                self.monitoring_changed.emit(True, endpoint)
            except Exception as exc:
                logger.error("Failed to start monitoring broker: %s", exc)
                self._is_monitoring = False
                self._broker_endpoint_label = ""
                self.monitoring_changed.emit(False, "")

        fut.add_done_callback(_done)
        return fut

    def start_monitoring_sync(self, timeout: float = 5.0) -> str:
        """Start monitoring and wait (used for deterministic startup/tests)."""
        fut = self.start_monitoring()
        endpoint = fut.result(timeout=timeout)
        self._broker_endpoint_label = endpoint
        self.monitoring_changed.emit(True, endpoint)
        return endpoint

    def stop_monitoring(self) -> concurrent.futures.Future[list[str]]:
        """Stop monitoring, cancel all pending approvals, and stop the local broker."""
        self._is_monitoring = False
        self._broker_endpoint_label = ""

        async def _stop() -> list[str]:
            cancelled = await self._approval_manager.shutdown(
                reason="Monitoring stopped by user."
            )
            if self._enable_local_broker:
                await self._broker.stop()
            return cancelled

        fut = self._worker.submit(_stop())

        def _done(f: concurrent.futures.Future[list[str]]) -> None:
            if not self._closed:
                self.monitoring_changed.emit(False, "")

        fut.add_done_callback(_done)
        return fut

    def approve_request(self, internal_id: str) -> None:
        """Invoke ApprovalManager.approve() safely from the Qt UI thread."""
        try:
            self._approval_manager.approve(
                internal_id, reason="Approved via Walled AI MCP Guard popup", decided_by="user"
            )
        except (DuplicateDecisionError, UnknownRequestError) as exc:
            logger.debug("Ignored stale approve click for %s: %s", internal_id, exc)

    def block_request(self, internal_id: str) -> None:
        """Invoke ApprovalManager.block() safely from the Qt UI thread."""
        try:
            self._approval_manager.block(
                internal_id, reason="Blocked via Walled AI MCP Guard popup", decided_by="user"
            )
        except (DuplicateDecisionError, UnknownRequestError) as exc:
            logger.debug("Ignored stale block click for %s: %s", internal_id, exc)

    def shutdown_sync(self, timeout: float = 5.0) -> None:
        """Gracefully cancel pending requests, stop broker, close audit log, stop worker."""
        with self._shutdown_lock:
            if self._closed:
                return
            self._closed = True
            self._is_monitoring = False

        if self._worker.is_running:
            async def _teardown() -> None:
                await self._approval_manager.shutdown(
                    reason="Walled AI MCP Guard shutting down."
                )
                if self._enable_local_broker:
                    await self._broker.stop()

            try:
                fut = self._worker.submit(_teardown())
                fut.result(timeout=timeout)
            except Exception:
                logger.debug("Teardown coroutine completed with error.", exc_info=True)
            self._worker.stop(timeout=timeout)

        self._audit_logger.close()


def _load_optional_config(config_path: str | None) -> GuardConfig | None:
    if config_path:
        return load_config(config_path)
    for candidate in (Path("config/servers.json"), Path("config/servers.example.json")):
        if candidate.is_file():
            try:
                return load_config(candidate)
            except Exception:
                logger.warning("Failed to parse %s; falling back to defaults.", candidate)
    return None


def main(argv: list[str] | None = None) -> int:
    """Launch the Walled AI MCP Guard PySide6 desktop application."""
    parser = argparse.ArgumentParser(
        description="Walled AI MCP Guard — Desktop Security Application"
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Optional path to Guard JSON config (defaults to config/servers.json or servers.example.json).",
    )
    parser.add_argument(
        "--broker-file",
        default=None,
        help="Optional path for the local authenticated IPC broker runtime file.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Override approval timeout in seconds.",
    )
    parser.add_argument(
        "--start-minimized",
        action="store_true",
        help="Start minimized to the Windows system tray.",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    cfg = _load_optional_config(args.config)
    timeout_seconds = (
        args.timeout
        if args.timeout is not None
        else (cfg.approval_timeout_seconds if cfg is not None else 120.0)
    )
    audit_log_path = cfg.audit_log_path if cfg is not None else "logs/audit.jsonl"
    server_summary = (
        f"Configured default: {cfg.default_server}"
        if cfg is not None
        else "Awaiting MCP Proxy Connection"
    )

    app = QApplication.instance()
    created_app = app is None
    if app is None:
        app = QApplication(sys.argv)
    app.setApplicationName("Walled AI MCP Guard")
    app.setQuitOnLastWindowClosed(False)

    controller = GuardController(
        audit_log_path=audit_log_path,
        timeout_seconds=timeout_seconds,
        configured_server_summary=server_summary,
        broker_runtime_file=args.broker_file,
    )

    tray_available = QSystemTrayIcon.isSystemTrayAvailable()
    window = MainWindow(controller=controller, minimize_to_tray=tray_available)

    def _open_dashboard() -> None:
        window.showNormal()
        window.raise_()
        window.activateWindow()

    def _exit_app() -> None:
        window.prepare_for_exit()
        controller.shutdown_sync()
        if tray is not None:
            tray.hide()
        app.quit()

    tray: GuardSystemTray | None = None
    if tray_available:
        tray = GuardSystemTray(
            on_open_dashboard=_open_dashboard,
            on_start_monitoring=controller.start_monitoring,
            on_stop_monitoring=controller.stop_monitoring,
            on_exit=_exit_app,
        )

        def _sync_tray(*_args: Any) -> None:
            if tray is not None:
                stats = controller.request_manager.get_stats()
                tray.update_state(
                    is_protected=controller.is_monitoring,
                    pending_count=stats["pending"],
                )

        controller.monitoring_changed.connect(_sync_tray)
        controller.request_updated.connect(_sync_tray)
        controller.request_resolved.connect(_sync_tray)
        tray.show()

    app.aboutToQuit.connect(controller.shutdown_sync)

    # Automatically start monitoring on desktop app launch.
    controller.start_monitoring()

    if not args.start_minimized or not tray_available:
        window.show()

    if created_app:
        return app.exec()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
