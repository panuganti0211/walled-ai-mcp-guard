# Walled AI MCP Guard — Demonstration Video Script & Submission Checklist

Target duration: **3.5 – 4.5 minutes** (1080p, crisp dark-theme desktop capture, microphone audio).

---

## 1. Pre-Recording Setup (1 Minute Before Recording)

1. Open two PowerShell terminals side by side (left/bottom) and keep the upper-right screen clear for the Walled AI dashboard and always-on-top popups.
2. Clean any previous demo sandbox directory so file creation and non-creation are unmistakably clear:
   ```powershell
   Remove-Item -Recurse -Force "$env:TEMP\walled_ai_mcp_guard_demo" -ErrorAction SilentlyContinue
   ```
3. Keep `docs/ARCHITECTURE.md` or `README.md` open in a clean tab if you want to briefly flash the architecture diagram.

---

## 2. Minute-by-Minute Recording Script

### Segment 1 — Introduction & Problem Statement (0:00 – 0:35)
- **Talking points:**
  - Introduce yourself and **Walled AI MCP Guard**, a Python desktop security application for real-time Model Context Protocol (MCP) monitoring and human-in-the-loop authorization.
  - Explain the problem: AI agents calling MCP tools (filesystem writes, API calls) can be steered by untrusted context or prompt injection. Without an intermediary security boundary, tools execute silently with no human approval or redacted audit trail.

### Segment 2 — Architecture Overview (0:35 – 1:10)
- **Visual:** Show the Mermaid architecture diagram in `README.md` / `docs/ARCHITECTURE.md`.
- **Talking points:**
  - Built on the **official MCP Python SDK 2.3.0** (`StdioMCPProxy` + `RemoteMCPGateway`), **PySide6**, **asyncio**, and **FastAPI/Uvicorn**.
  - Every `tools/call` passes through a single enforcement boundary (`RequestHandler` -> `ApprovalManager` -> 8-state `RequestManager` -> always-on-top PySide6 popup).
  - Strictly **fail-closed**: blocked, timed-out, cancelled, or erroring authorizations never reach the upstream MCP server.

### Segment 3 — Launching Walled AI MCP Guard (1:10 – 1:35)
- **Terminal 1 command:**
  ```powershell
  cd D:\walled-ai-mcp-guard
  D:\walled-ai-mcp-guard\.venv\Scripts\python.exe run.py
  ```
- **Visual & Talking points:**
  - Point out the dark-navy dashboard: **PROTECTED** status badge, live MCP Proxy status, zero initial KPI counters backed by `RequestManager`, empty recent activity table, and the shield icon in the Windows system tray.

### Segment 4 — Tool Discovery & ALLOW Demonstration (1:35 – 2:25)
- **Terminal 2 command:**
  ```powershell
  cd D:\walled-ai-mcp-guard
  D:\walled-ai-mcp-guard\.venv\Scripts\python.exe scripts\demo_mcp_client.py --tool create_test_file --filename approved_demo.txt --content "Approved by user in Walled AI demo"
  ```
- **Visual & Talking points:**
  - Show Terminal 2 output: genuine `StdioMCPProxy` connecting to `tests.test_mcp_server`, completing `initialize`, and discovering all 4 tools (`get_current_time`, `read_test_file`, `create_test_file`, `list_test_directory`).
  - Highlight the **always-on-top authorization popup** appearing above Terminal 2:
    - MCP server name (`safe-test-server`), tool badge (`create_test_file`), JSON-RPC Request ID, UTC timestamp, untrusted tool description warning, live timeout countdown, and **redacted parameters** (`"content": "[REDACTED_CONTENT len=34]"`).
  - Click **Allow Execution**.
  - Show Terminal 2 printing `ALLOWED & EXECUTED (is_error=False)`.
  - Verify the file actually exists on disk:
    ```powershell
    Get-Content "$env:TEMP\walled_ai_mcp_guard_demo\approved_demo.txt"
    ```

### Segment 5 — BLOCK Demonstration & Marker-File Proof (2:25 – 3:10)
- **Terminal 2 command:**
  ```powershell
  D:\walled-ai-mcp-guard\.venv\Scripts\python.exe scripts\demo_mcp_client.py --tool create_test_file --filename blocked_marker.txt --content "MUST_NOT_BE_CREATED"
  ```
- **Visual & Talking points:**
  - When the popup appears, point out the new JSON-RPC Request ID and click **Block Execution**.
  - Show Terminal 2 receiving `DENIED/ERROR (code=-32003)`.
  - Prove the upstream tool NEVER executed by checking for the marker file:
    ```powershell
    Test-Path "$env:TEMP\walled_ai_mcp_guard_demo\blocked_marker.txt"
    ```
    *(Returns `False`.)*

### Segment 6 — Live Request History, Security & Concurrency Highlights (3:10 – 3:55)
- **Visual:** Focus the Walled AI dashboard and run the automated test summary (or show `pytest` output).
- **Talking points:**
  - Show dashboard live KPI counters (`Total: 2`, `Approved: 1`, `Blocked / Denied: 1`, `Pending: 0`) and color-coded activity history (`ALLOW`/`COMPLETED`, `BLOCK`/`BLOCKED`) with sensitive file contents completely absent.
  - Mention security & reliability highlights verified by **107 passing automated tests**:
    - 10 / 25 / 50 simultaneous MCP requests handled concurrently out of order with independent decisions.
    - Windows owner-only DACL token file, DNS-rebinding `Host`/`Origin` protection, recursive secret redaction in `logs/audit.jsonl`, upstream crash survival, and fail-closed shutdown.

### Segment 7 — Honest Compatibility Status & Closing (3:55 – 4:25)
- **Talking points:**
  - Be transparent about current testing boundaries:
    - **Local STDIO proxy & `@modelcontextprotocol/server-filesystem`:** Verified end-to-end on Windows, with a backup-first configurator (`scripts/configure_claude_desktop.py`) ready for Claude Desktop; live Claude Desktop GUI Tests A–E are pending installation of Claude Desktop on this machine.
    - **Remote Streamable HTTP Gateway (`app/proxy/http_gateway.py`):** Verified locally with the official MCP 2.3.0 Streamable HTTP client + desktop popup flow; live **Claude Web** integration requires public HTTPS termination (Caddy/Nginx/Cloudflare Tunnel) and OAuth 2.1 Protected Resource Metadata (RFC 9728) and has not yet been tested against hosted `claude.ai`.
  - Thank the reviewer and close cleanly via the system tray (**Exit Walled AI MCP Guard**).

---

## 3. Screenshot Checklist

### Already Captured (Real Live Runs)
- [x] `docs/screenshots/dashboard.png` — Live dark-navy dashboard with real counters and color-coded request history.
- [x] `docs/screenshots/approval_popup.png` — Live always-on-top authorization popup with redacted parameters and timeout badge.

### Optional Live Screenshots to Capture Once You Install Claude Desktop
*(Never fabricate screenshots — only add these after running live Claude Desktop Tests A–E.)*
- [ ] Claude Desktop showing `walled-ai-mcp-guard` connected with discovered sandboxed filesystem tools (Test A).
- [ ] Always-on-top Walled AI popup triggered directly by a Claude Desktop prompt (Test B — Allow).
- [ ] Claude Desktop displaying the denial response after clicking **Block Execution**, alongside PowerShell confirming `Test-Path` returns `False` (Test C — Block).
- [ ] Walled AI dashboard showing **MCP Proxy Status: Connected (Active MCP Session)** while Claude Desktop is open.

---

## 4. Hiring Assignment Submission Checklist

Complete each item before submitting your application form:

- [ ] **CV Link:** Up-to-date resume / CV URL (verified public/viewable permissions).
- [ ] **GitHub Repository URL:** Public repository link after your review and explicit push.
- [ ] **Demo Video URL:** Unlisted YouTube / Loom / Drive link to your recorded 3–5 minute walkthrough (verified viewable without sign-in).
- [ ] **Email Address:** Your active contact email.
- [ ] **LinkedIn Profile:** Your current LinkedIn URL.
- [ ] **Tested MCP Clients (Honest Summary):**
  - Official MCP Python SDK 2.3.0 STDIO client (`ClientSession` + `stdio_client`) against both `tests.test_mcp_server` and official `@modelcontextprotocol/server-filesystem` (`npx`).
  - Official MCP Python SDK 2.3.0 Streamable HTTP client (`streamable_http_client`) against `RemoteMCPGateway`.
  - *(Update once you run live Claude Desktop Tests A–E on your machine; clearly note Claude Web requires public HTTPS + OAuth 2.1.)*
- [ ] **Architecture Description:** Reference `README.md` and `docs/ARCHITECTURE.md` (official `mcp 2.3.0` STDIO proxy + Streamable HTTP gateway -> single `RequestHandler` boundary -> `ApprovalManager` + 8-state `RequestManager` + redacted `AuditLogger` -> authenticated `127.0.0.1` broker -> PySide6 desktop GUI on dedicated `AsyncioWorkerThread`).
- [ ] **Limitations & Security Considerations:** Explicitly state fail-closed design, same-user local threat model, owner-only Windows DACL token file, recursive audit redaction, pending live Claude Desktop GUI test (until installed), and pending live Claude Web public HTTPS + OAuth 2.1 deployment.
- [ ] **Earliest Joining Date:** Your confirmed availability date.
