# Walled AI MCP Guard — Demonstration Video Script & Submission Checklist

Target duration: **3.5 – 4.5 minutes** (1080p, crisp dark-theme desktop capture, microphone audio).

---

## 1. Pre-Recording Setup (1 Minute Before Recording)

1. Arrange windows cleanly:
   - Left half: Claude Desktop (primary demonstration application).
   - Right half: Walled AI MCP Guard dashboard (`run.py`) and a PowerShell verification terminal.
2. Clean previous test files in `sandbox_files` so file creation and non-creation are unmistakably clear:
   ```powershell
   Remove-Item -Force "sandbox_files\claude_*.txt" -ErrorAction SilentlyContinue
   ```
3. Keep `docs/ARCHITECTURE.md` or `README.md` open in a browser tab to briefly display the architecture diagram.

---

## 2. Minute-by-Minute Recording Script

### Segment 1 — Introduction & Problem Statement (0:00 – 0:35)
- **Talking points:**
  - Introduce yourself and **Walled AI MCP Guard**, an unbypassable human-in-the-loop authorization proxy for Model Context Protocol (MCP) clients on Windows.
  - Explain the security problem: AI assistants like Claude Desktop invoke external tools (filesystems, code execution, databases). Without an intermediary enforcement boundary, prompt injection or untrusted data can trigger silent, unauthorized tool execution.
  - Walled AI MCP Guard intercepts every `tools/call` and requires explicit user approval before execution, with strict fail-closed guarantees.

### Segment 2 — Architecture Overview (0:35 – 1:05)
- **Visual:** Display the Mermaid architecture diagram in `README.md` / `docs/ARCHITECTURE.md`.
- **Talking points:**
  - Built with the **official MCP Python SDK 2.3.0** (`StdioMCPProxy` and `RemoteMCPGateway`), **PySide6**, **asyncio**, and **FastAPI/Uvicorn**.
  - Operates as a genuine intermediary MCP server/client proxy. Every `tools/call` must pass through the `RequestHandler` enforcement boundary, an independent `asyncio.Future` in `ApprovalManager`, and an 8-state `RequestManager` state machine.
  - Communications between the proxy and desktop UI are authenticated over local loopback using a 256-bit Bearer token protected by Windows owner-only DACLs and DNS-rebinding guards.

### Segment 3 — Launching Walled AI MCP Guard (1:05 – 1:30)
- **PowerShell command:**
  ```powershell
  cd D:\walled-ai-mcp-guard
  D:\walled-ai-mcp-guard\.venv\Scripts\python.exe run.py
  ```
- **Visual & Talking points:**
  - Highlight the dark-navy cybersecurity dashboard:
    - Protection status badge: **PROTECTED** (green).
    - MCP Proxy status: **Connected** / listening on authenticated local broker.
    - Live KPI counters: Total: 0, Approved: 0, Blocked / Denied: 0, Pending: 0 (backed by `RequestManager`).
    - Shield icon in the Windows system tray with minimize-to-tray and quit controls.

### Segment 4 — Live Claude Desktop ALLOW Demonstration (1:30 – 2:30)
- **Action:** Open Claude Desktop on Windows.
  - Verify Claude Desktop detects `walled-ai-mcp-guard` with status **Running** in settings.
- **Claude Prompt 1 (Directory Discovery):**
  - Prompt: *"List the allowed directories."*
  - An always-on-top popup appears for `list_allowed_directories`. Click **Allow Execution**. Claude lists the directory.
- **Claude Prompt 2 (File Creation):**
  - Prompt: *"Create a file named claude_approved_test.txt with the content: Created through Claude Desktop and protected by Walled AI MCP Guard."*
- **Visual & Talking points:**
  - Focus on the **always-on-top authorization popup**:
    - Server badge: `filesystem-sandbox`
    - Tool badge: `write_file`
    - Metadata: JSON-RPC ID, UTC timestamp, untrusted description warning, and live countdown timer.
    - Redacted parameters: Sensitive content is scrubbed (`"content": "[REDACTED_CONTENT len=69]"`).
  - Click **Allow Execution**.
  - Show Claude confirming file creation.
  - In PowerShell, verify the file on disk:
    ```powershell
    Get-Content ".\sandbox_files\claude_approved_test.txt"
    ```
    *(Output matches: `"Created through Claude Desktop and protected by Walled AI MCP Guard."`)*

### Segment 5 — Live Claude Desktop BLOCK Demonstration (2:30 – 3:15)
- **Claude Prompt 3 (Blocked File Creation):**
  - Prompt: *"Create a file named claude_blocked_test.txt with the content: This file should never be created because it will be blocked by Walled AI MCP Guard."*
- **Visual & Talking points:**
  - When the authorization popup appears, point out the new request and click **Block Execution**.
  - Show Claude receiving JSON-RPC denial code `-32003` and reporting cleanly: *"The tool call to write_file was blocked by the user or security policy."*
  - **Irrefutable Proof of Non-Execution:** In PowerShell, check for the blocked file:
    ```powershell
    Test-Path ".\sandbox_files\claude_blocked_test.txt"
    ```
    *(Returns `False`. The upstream server was never invoked).*

*(Optional CLI Alternative: The same Allow/Block interception can also be demonstrated in terminal-only environments using `scripts/demo_mcp_client.py`).*

### Segment 6 — Dashboard Metrics, Audit Trail & Concurrency (3:15 – 3:55)
- **Visual:** Focus the Walled AI dashboard and show `logs/audit.jsonl`.
- **Talking points:**
  - Live counters updated in real time: **Total: 3**, **Approved: 2**, **Blocked / Denied: 1**, **Pending: 0**.
  - Recent activity table displays every request, timestamp, and status.
  - Structured JSONL audit log (`logs/audit.jsonl`): Shows blocked request with `execution_result: "not_executed"` and credentials recursively redacted.
  - Mention verified robustness: **107 passing automated tests**, including 10, 25, and 50 simultaneous requests stress-tested out of order, upstream crash survival, and fail-closed shutdown.

### Segment 7 — Honest Compatibility Status & Closing (3:55 – 4:25)
- **Talking points:**
  - Clearly disclose current testing boundaries:
    - **Claude Desktop on Windows:** Fully verified live with official `@modelcontextprotocol/server-filesystem` (`npx`), demonstrating end-to-end tool discovery, Allow, and Block operations.
    - **Remote Streamable HTTP Gateway (`RemoteMCPGateway`):** Fully implemented in `app/proxy/http_gateway.py` and locally verified (6/6 tests passing in `tests/test_http_gateway.py`); live hosted **Claude Web** (`claude.ai`) integration has not yet been tested and requires public HTTPS reverse proxy hosting and RFC 9728 OAuth 2.1 metadata.
  - Close cleanly by exiting through the dashboard or system tray.

---

## 3. Verified Screenshot & Artifact Checklist

### Captured & Tracked in Repository
- [x] `docs/screenshots/dashboard.png` — Dark-navy cybersecurity dashboard with live metrics and color-coded recent activity.
- [x] `docs/screenshots/approval_popup.png` — Always-on-top authorization popup with redacted parameters and timeout countdown.

### Verified Claude Desktop Integration Evidence
- [x] Claude Desktop detected `walled-ai-mcp-guard` with status **Running** in Settings.
- [x] Always-on-top Walled AI popup intercepted Claude Desktop `write_file` requests in real time.
- [x] Allowed tool call created `sandbox_files/claude_approved_test.txt` with verified disk content.
- [x] Blocked tool call received JSON-RPC denial `-32003` with confirmed absence of `sandbox_files/claude_blocked_test.txt` (`Test-Path` returned `False`).
- [x] Live dashboard recorded exact metrics (`Total: 3`, `Approved: 2`, `Blocked / Denied: 1`, `Pending: 0`) and audit log recorded `execution_result: "not_executed"`.

---

## 4. Hiring Assignment Submission Checklist

Complete each item before submitting your application form:

- [ ] **CV Link:** Up-to-date resume / CV URL (verified public/viewable permissions).
- [ ] **GitHub Repository URL:** Public repository link after your review and explicit push (`https://github.com/panuganti0211/walled-ai-mcp-guard`).
- [ ] **Demo Video URL:** Unlisted YouTube / Loom / Drive link to your recorded 3–5 minute walkthrough (verified viewable without sign-in).
- [ ] **Email Address:** Your active contact email.
- [ ] **LinkedIn Profile:** Your current LinkedIn URL.
- [ ] **Tested MCP Clients (Honest Summary):**
  - **Claude Desktop on Windows (Primary):** Fully verified live end-to-end with official `@modelcontextprotocol/server-filesystem` (`npx`), approving and blocking tool calls with confirmed disk state.
  - **Official MCP Python SDK 2.3.0 STDIO Client (Optional CLI Alternative):** Tested end-to-end over real Windows pipes with `scripts/demo_mcp_client.py` and pytest.
  - **Official MCP Python SDK 2.3.0 Streamable HTTP Client:** Tested locally against `RemoteMCPGateway` over HTTP (6/6 automated tests passing).
  - *(Honest note: Live hosted Claude Web (`claude.ai`) integration has not been tested and requires public HTTPS reverse proxy deployment and RFC 9728 OAuth 2.1 metadata).*
- [ ] **Architecture Description:** Reference `README.md` and `docs/ARCHITECTURE.md` (official `mcp 2.3.0` STDIO proxy + Streamable HTTP gateway -> single `RequestHandler` boundary -> `ApprovalManager` + 8-state `RequestManager` + redacted `AuditLogger` -> authenticated `127.0.0.1` broker -> PySide6 desktop GUI on dedicated `AsyncioWorkerThread`).
- [ ] **Limitations & Security Considerations:** Explicitly state fail-closed design, same-user local threat model, owner-only Windows DACL token file, recursive audit redaction, Claude Desktop restart requirement, and hosted Claude Web public HTTPS + OAuth 2.1 deployment prerequisites.
- [ ] **Earliest Joining Date:** Your confirmed availability date.
