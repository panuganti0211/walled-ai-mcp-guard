# Walled AI MCP Guard — Demonstration Video Script & Submission Checklist

Target duration: **4.5–5.5 minutes** (1080p screen recording, clear microphone audio).

---

## 1. Pre-Recording Setup

1. Arrange the following windows:
   - Claude Desktop.
   - Claude Web in a browser.
   - Walled AI MCP Guard dashboard.
   - PowerShell verification terminal.
2. Ensure the desktop application and required MCP processes are running.
3. For the Claude Web demonstration, ensure the authenticated gateway and temporary Cloudflare Quick Tunnel are running.
4. Clean previous demonstration files if needed:
   ```powershell
   Remove-Item -Force ".\sandbox_files\claude_*.txt" -ErrorAction SilentlyContinue
   ```
5. Keep `README.md` or `docs/ARCHITECTURE.md` available to show the architecture diagram.

---

## 2. Minute-by-Minute Recording Script

### Segment 1 — Introduction and Problem Statement (0:00–0:35)

**Talking points:**

- Introduce yourself and Walled AI MCP Guard, a human-in-the-loop authorization proxy for Model Context Protocol (MCP) clients on Windows.
- Explain the security problem: AI assistants can invoke external tools such as filesystem operations. Without an authorization boundary, untrusted instructions or prompt injection could lead to unwanted tool execution.
- Walled AI MCP Guard intercepts tool calls and requires explicit user approval before execution.
- Its authorization flow is fail-closed: without explicit approval, an intercepted tool call cannot execute.

### Segment 2 — Architecture Overview (0:35–1:05)

**Visual:** Display the architecture diagram in `README.md` or `docs/ARCHITECTURE.md`.

**Talking points:**

- Built using the official MCP Python SDK 2.3.0, Python, PySide6, asyncio, and FastAPI.
- Supports two integration paths:
  - Claude Desktop through STDIO.
  - Claude Web through authenticated Streamable HTTP.
- Both paths converge at the `RequestHandler` enforcement boundary.
- The desktop application manages approval requests through `ApprovalManager`, the 8-state `RequestManager` state machine, and the redacted audit logger.
- Remote authorization requests communicate with the desktop application through an authenticated local authorization broker.

### Segment 3 — Launching Walled AI MCP Guard (1:05–1:25)

**PowerShell command:**

```powershell
cd D:\walled-ai-mcp-guard
D:\walled-ai-mcp-guard\.venv\Scripts\python.exe run.py
```

**Visual and talking points:**

- Show the desktop dashboard.
- Highlight the protection status and MCP connection status.
- Point out the live request counters.
- Show the recent activity area and Windows system tray integration.

### Segment 4 — Claude Desktop: Allow and Block (1:25–2:35)

**Action:** Open Claude Desktop and show the configured Walled AI MCP Guard connection.

**Test 1 — Approved directory discovery**

Prompt:

> List the allowed directories.

- The Walled AI approval popup appears for `list_allowed_directories`.
- Click **Allow Execution**.
- Show Claude returning the configured sandbox directory.

**Test 2 — Approved file creation**

Prompt:

> Create a file named claude_approved_test.txt with the content: Created through Claude Desktop and protected by Walled AI MCP Guard.

- Show the approval popup.
- Point out the server name, tool name, request metadata, and redacted parameters.
- Click **Allow Execution**.
- Show Claude confirming the operation.

Verify the file in PowerShell:

```powershell
Get-Content ".\sandbox_files\claude_approved_test.txt"
```

**Test 3 — Blocked file creation**

Prompt:

> Create a file named claude_blocked_test.txt with the content: This file should never be created because it will be blocked by Walled AI MCP Guard.

- Click **Block Execution** in the approval popup.
- Show Claude receiving the denial response.
- Verify that the file was not created:

```powershell
Test-Path ".\sandbox_files\claude_blocked_test.txt"
```

Expected output: `False`.

### Segment 5 — Claude Web: Remote Allow and Block (2:35–3:45)

**Action:** Switch to Claude Web and show the configured Walled AI MCP Guard connector.

Briefly explain:

- Claude Web connects through the authenticated Streamable HTTP gateway.
- A temporary Cloudflare Quick Tunnel provides HTTPS access to the local gateway for this demonstration.
- Authorization still happens in the native Walled AI desktop application.

**Test 1 — Approved request**

Prompt:

> List the allowed directories.

- Show the native Walled AI approval popup.
- Click **Allow Execution**.
- Show Claude Web returning the sandbox directory path.

**Test 2 — Blocked request**

Prompt:

> Create a file named claude_web_blocked_test.txt with the content: This file must not be created.

- Show the native approval popup.
- Click **Block Execution**.
- Show Claude Web receiving the denial response.

Verify in PowerShell:

```powershell
Test-Path ".\sandbox_files\claude_web_blocked_test.txt"
```

Expected output: `False`.

**Important:** The temporary Quick Tunnel is a demonstration setup, not a permanent production deployment.

### Segment 6 — Dashboard, Audit Trail, and Testing (3:45–4:30)

**Visual:** Return to the Walled AI dashboard and show the audit log.

**Talking points:**

- Show the request history and current approval statuses.
- Explain how approved and blocked requests are recorded.
- Show `logs/audit.jsonl` and point out sensitive-value redaction.
- Explain that blocked tool calls are denied before the upstream `call_tool` operation.
- Mention the automated test result: **107 passed, 0 failed, 0 skipped, 0 errors**.
- Briefly mention concurrency testing, upstream crash handling, and fail-closed shutdown behavior.

Do not claim a specific dashboard counter total unless the displayed counters match the actual test session.

### Segment 7 — Closing and Compatibility Summary (4:30–5:00)

**Talking points:**

- Claude Desktop on Windows: verified live end-to-end for approval and denial.
- Claude Web: verified live end-to-end through the authenticated remote gateway, temporary Cloudflare Quick Tunnel, and local desktop approval popup.
- Official MCP Python SDK 2.3.0 STDIO and Streamable HTTP clients were also tested.
- The remote demonstration used a temporary tunnel. A production deployment requires a stable HTTPS endpoint and appropriate authentication, access controls, and secret management.
- Close by showing the dashboard and the project repository.

---

## 3. Verified Screenshot and Artifact Checklist

### Core desktop application

- [x] `docs/screenshots/dashboard.png`
- [x] `docs/screenshots/approval_popup.png`

### Claude Web integration evidence

- [x] `docs/screenshots/claude-web/01-claude-web-approved.png`
- [x] `docs/screenshots/claude-web/02-walled-ai-approval-popup.png`
- [x] `docs/screenshots/claude-web/03-claude-web-blocked.png`
- [x] `docs/screenshots/claude-web/04-desktop-dashboard-after-broker-restart.png`

### Verified Claude Desktop integration

- [x] Claude Desktop detected the configured MCP server.
- [x] Approved directory discovery through the native approval popup.
- [x] Approved file creation with verified file content.
- [x] Blocked file creation with confirmed file absence.
- [x] Dashboard and audit logging verified.

### Verified Claude Web integration

- [x] Connected through the authenticated remote MCP gateway.
- [x] Local authorization broker heartbeat returned HTTP 200.
- [x] Approved directory discovery through the native approval popup.
- [x] Blocked file creation through the native approval popup.
- [x] Confirmed the blocked file was not created.

---

## 4. Hiring Assignment Submission Checklist

Complete these items before submitting the application:

- [ ] **CV Link:** Updated resume URL with public/viewable permissions.
- [ ] **GitHub Repository URL:** Verify the final public repository after committing and pushing the latest changes:
  `https://github.com/panuganti0211/walled-ai-mcp-guard`
- [ ] **Demo Video URL:** Unlisted YouTube, Loom, or Drive link with access verified.
- [ ] **Email Address:** Active contact email.
- [ ] **LinkedIn Profile:** Current LinkedIn URL.
- [ ] **Tested MCP Clients:**
  - Claude Desktop on Windows — live end-to-end approval and denial verified.
  - Claude Web — live end-to-end approval and denial verified through the remote gateway.
  - Official MCP Python SDK 2.3.0 STDIO client — tested.
  - Official MCP Python SDK 2.3.0 Streamable HTTP client — tested locally.
- [ ] **Architecture Description:** Reference `README.md` and `docs/ARCHITECTURE.md`.
- [ ] **Limitations and Security Considerations:** Explain the fail-closed authorization design, local broker security, audit redaction, temporary Quick Tunnel demonstration setup, and production deployment requirements.
- [ ] **Earliest Joining Date:** Confirm your availability before submission.