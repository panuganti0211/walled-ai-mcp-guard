"""Phase 5 dedicated security hardening verification tests."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import httpx
import pytest

from app.authorization.approval_manager import ApprovalManager
from app.authorization.ipc_broker import (
    LocalAuthorizationBroker,
    is_valid_loopback_broker_url,
    read_broker_runtime_file,
)
from app.config import ConfigError, UpstreamServerConfig, load_config, resolve_sandbox_path
from app.monitoring.audit_logger import AuditLogger, redact_sensitive_data


# ======================================================================
# 1. Localhost-Only Binding, URL Validation, Host & Origin Protection
# ======================================================================


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://0.0.0.0:8000",
        "http://192.168.1.10:8000",
        "https://127.0.0.1:8000",
        "http://127.0.0.1:80@evil.example",
        "http://127.0.0.1:8000/extra/path",
        "http://127.0.0.1:8000?q=1",
        "http://localhost:8000",
        "http://127.0.0.1",
        "http://127.0.0.1:99999",
        "",
    ],
)
def test_loopback_broker_url_validator_blocks_unsafe_urls(bad_url: str) -> None:
    assert is_valid_loopback_broker_url(bad_url) is False


def test_loopback_broker_url_validator_accepts_strict_loopback() -> None:
    assert is_valid_loopback_broker_url("http://127.0.0.1:54321") is True


@pytest.mark.asyncio
async def test_broker_host_header_origin_header_and_token_entropy(
    tmp_path: Path,
) -> None:
    """Verify Host DNS-rebinding defense, Origin CSRF block, and 256-bit token entropy."""
    audit = AuditLogger(tmp_path / "sec_audit.jsonl")
    manager = ApprovalManager(audit_logger=audit, timeout_seconds=5.0)
    broker_file = tmp_path / "sec_broker.json"
    broker = LocalAuthorizationBroker(approval_manager=manager, runtime_file=broker_file)
    info = await broker.start()

    try:
        # 256-bit token_urlsafe(32) yields 43 URL-safe base64 chars
        assert len(info.token) >= 43
        assert info.url == f"http://127.0.0.1:{info.port}"

        valid_headers = {"Authorization": f"Bearer {info.token}"}

        async with httpx.AsyncClient(timeout=3.0) as client:
            # Valid request succeeds
            ok = await client.get(f"{info.url}/health", headers=valid_headers)
            assert ok.status_code == 200

            # DNS-rebinding Host header attacks MUST be blocked with 403 even with valid token
            for bad_host in ("evil.example", "127.0.0.1.evil.example", "0.0.0.0:1234"):
                resp = await client.get(
                    f"{info.url}/health",
                    headers={**valid_headers, "Host": bad_host},
                )
                assert resp.status_code == 403, f"Host {bad_host!r} was not blocked!"

            # Browser Origin header MUST be rejected with 403 even with valid token
            resp_origin = await client.get(
                f"{info.url}/health",
                headers={**valid_headers, "Origin": "https://evil.example"},
            )
            assert resp_origin.status_code == 403

            # OpenAPI/Swagger docs endpoints MUST be disabled (404)
            for doc_path in ("/docs", "/redoc", "/openapi.json"):
                resp_doc = await client.get(f"{info.url}{doc_path}", headers=valid_headers)
                assert resp_doc.status_code == 404
    finally:
        await broker.stop()
        audit.close()


@pytest.mark.asyncio
async def test_runtime_token_file_owner_only_acl_and_tamper_rejection(
    tmp_path: Path,
) -> None:
    """Verify runtime token file has owner-only Windows ACLs and tampered files are rejected."""
    audit = AuditLogger(tmp_path / "acl_audit.jsonl")
    manager = ApprovalManager(audit_logger=audit, timeout_seconds=5.0)
    broker_file = tmp_path / "acl_broker.json"
    broker = LocalAuthorizationBroker(approval_manager=manager, runtime_file=broker_file)
    await broker.start()

    try:
        assert broker_file.is_file()
        if sys.platform == "win32":
            import win32api
            import win32security

            sd = win32security.GetFileSecurity(
                str(broker_file), win32security.DACL_SECURITY_INFORMATION
            )
            dacl = sd.GetSecurityDescriptorDacl()
            assert dacl is not None
            current_user_sid, _, _ = win32security.LookupAccountName(
                None, win32api.GetUserNameEx(win32api.NameSamCompatible)
            )
            system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
            allowed_sids = {
                win32security.ConvertSidToStringSid(current_user_sid),
                win32security.ConvertSidToStringSid(system_sid),
            }
            ace_sids = set()
            for i in range(dacl.GetAceCount()):
                _, _, sid = dacl.GetAce(i)
                ace_sids.add(win32security.ConvertSidToStringSid(sid))
            assert ace_sids.issubset(allowed_sids), (
                f"Unexpected non-owner SIDs in runtime token file ACL: {ace_sids - allowed_sids}"
            )
    finally:
        await broker.stop()
        audit.close()

    # Tampered runtime file with @evil.com URL or short token MUST return None
    tampered = tmp_path / "tampered_broker.json"
    tampered.write_text(
        json.dumps(
            {
                "url": "http://127.0.0.1:80@evil.example",
                "token": "a" * 48,
                "port": 80,
                "pid": os.getpid(),
            }
        ),
        encoding="utf-8",
    )
    assert read_broker_runtime_file(tampered) is None


# ======================================================================
# 2. Configuration Validation & Shell Command Injection Defense
# ======================================================================


@pytest.mark.parametrize(
    "shell_cmd",
    [
        "cmd",
        "cmd.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh.exe",
        "sh",
        "bash",
        "wscript.exe",
        "cscript.exe",
        "python.exe; calc.exe",
        "python.exe & calc.exe",
        "python.exe | more",
        "python.exe `id`",
        "python.exe $(whoami)",
    ],
)
def test_upstream_config_blocks_shell_injection_and_interpreters(
    shell_cmd: str,
) -> None:
    with pytest.raises(Exception):
        UpstreamServerConfig(command=shell_cmd, args=[])


def test_config_rejects_extra_fields_bad_env_and_null_bytes(tmp_path: Path) -> None:
    # Extra unknown top-level field
    cfg1 = tmp_path / "extra.json"
    cfg1.write_text(
        json.dumps(
            {
                "default_server": "s",
                "unexpected_key": True,
                "servers": {"s": {"command": sys.executable, "args": []}},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(cfg1)

    # Bad environment variable key
    with pytest.raises(Exception):
        UpstreamServerConfig(
            command=sys.executable,
            env={"BAD=KEY": "1"},
        )

    # Null byte in args
    with pytest.raises(Exception):
        UpstreamServerConfig(
            command=sys.executable,
            args=["-m", "tests\x00evil"],
        )


# ======================================================================
# 3. Redaction Edge Cases, Sandbox Symlinks & No Secrets in Repo / Gitignore
# ======================================================================


def test_redaction_handles_circular_refs_and_deep_nesting() -> None:
    cyclic: dict = {"password": "secret", "label": "ok"}
    cyclic["self"] = cyclic
    res = redact_sensitive_data(cyclic)
    assert res["password"] == "[REDACTED]"
    assert res["self"] == "[CIRCULAR_REF]"

    # Deeply nested dict hits depth cap safely without RecursionError
    deep: dict = {"token": "abc"}
    for _ in range(30):
        deep = {"layer": deep}
    redacted_deep = redact_sensitive_data(deep)
    assert "abc" not in json.dumps(redacted_deep)


def test_gitignore_excludes_sensitive_configs_and_logs() -> None:
    gitignore = Path(".gitignore").read_text(encoding="utf-8")
    for required_pattern in ("config/servers.json", ".env", "logs/*.jsonl", "logs/*.log"):
        assert required_pattern in gitignore


def test_no_hardcoded_secrets_in_source_code() -> None:
    """Scan app/ source files to confirm no hardcoded API keys or private keys exist."""
    secret_patterns = (
        re.compile(r"\bsk-(?:live|proj|ant)-[A-Za-z0-9_-]{16,}\b"),
        re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bAIza[0-9A-Za-z\-_]{25,}\b"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    )
    for py_file in Path("app").rglob("*.py"):
        content = py_file.read_text(encoding="utf-8")
        for pat in secret_patterns:
            assert not pat.search(content), f"Potential hardcoded secret in {py_file}"
