"""Configuration loader and strict validation for Walled AI MCP Guard."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


# Characters that indicate shell command chaining, redirection, or injection attempts.
_FORBIDDEN_COMMAND_CHARS = re.compile(r"[;&|`$<>!\r\n\x00]")
_VALID_SERVER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_VALID_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DISALLOWED_SHELL_EXECUTABLES = frozenset(
    {
        "cmd",
        "cmd.exe",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "sh",
        "bash",
        "bash.exe",
        "zsh",
        "wscript",
        "wscript.exe",
        "cscript",
        "cscript.exe",
    }
)


class ConfigError(ValueError):
    """Raised when configuration loading or security validation fails."""


def resolve_sandbox_path(sandbox_root: str | Path, requested_path: str) -> Path:
    """Resolve a relative path strictly inside sandbox_root.

    Rejects null bytes, absolute paths, drive-letter paths, UNC paths,
    directory traversal (`..`), and symlinks escaping the sandbox directory.
    """
    if not isinstance(requested_path, str):
        raise ValueError("Requested path must be a string.")
    if "\x00" in requested_path:
        raise ValueError("Requested path must not contain null bytes.")

    stripped = requested_path.strip()
    if stripped == "":
        return Path(sandbox_root).resolve()

    # Reject UNC paths, root-anchored paths, or Windows drive-letter paths (e.g. C:\ or C:foo)
    if stripped.startswith(("/", "\\")) or (len(stripped) >= 2 and stripped[1] == ":"):
        raise ValueError(f"Absolute or drive-qualified path is forbidden: {requested_path!r}")

    root = Path(sandbox_root).resolve()
    candidate = Path(stripped)
    if candidate.is_absolute():
        raise ValueError(f"Absolute path is forbidden: {requested_path!r}")

    joined = root / candidate
    resolved = joined.resolve()

    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"Path escapes configured sandbox directory: {requested_path!r}"
        ) from exc

    # Also verify no intermediate symlink component points outside the sandbox
    current = root
    for part in candidate.parts:
        if part in ("", "."):
            continue
        current = current / part
        if current.is_symlink():
            target = current.resolve()
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise ValueError(
                    f"Symlink escapes configured sandbox directory: {requested_path!r}"
                ) from exc

    return resolved


class UpstreamServerConfig(BaseModel):
    """Validated configuration for a single explicitly configured upstream MCP server."""

    model_config = ConfigDict(extra="forbid")

    description: str = Field(default="", max_length=500)
    transport: Literal["stdio"] = "stdio"
    command: str = Field(..., min_length=1, max_length=512)
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = Field(default=None, max_length=512)
    sandbox_dir: str | None = Field(default=None, max_length=512)
    enabled: bool = True

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Upstream server command cannot be empty.")
        if _FORBIDDEN_COMMAND_CHARS.search(cleaned):
            raise ValueError(
                "Upstream server command contains forbidden shell metacharacters."
            )
        exe_name = Path(cleaned).name.lower()
        if exe_name in _DISALLOWED_SHELL_EXECUTABLES:
            raise ValueError(
                f"Direct shell executable {exe_name!r} is disallowed as an upstream MCP command."
            )
        return cleaned

    @field_validator("args")
    @classmethod
    def validate_args(cls, value: list[str]) -> list[str]:
        for arg in value:
            if not isinstance(arg, str):
                raise ValueError("All command arguments must be strings.")
            if "\x00" in arg:
                raise ValueError("Command arguments must not contain null bytes.")
        return value

    @field_validator("env")
    @classmethod
    def validate_env(cls, value: dict[str, str]) -> dict[str, str]:
        for key, env_val in value.items():
            if not _VALID_ENV_KEY.match(key):
                raise ValueError(f"Invalid environment variable name: {key!r}")
            if "\x00" in env_val:
                raise ValueError(f"Environment variable {key!r} must not contain null bytes.")
        return value

    @field_validator("cwd", "sandbox_dir")
    @classmethod
    def validate_optional_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("Configured directory path contains illegal control characters.")
        return value


class GuardConfig(BaseModel):
    """Top-level configuration for Walled AI MCP Guard."""

    model_config = ConfigDict(extra="forbid")

    default_server: str = Field(..., min_length=1)
    approval_timeout_seconds: float = Field(default=120.0, gt=0.0, le=3600.0)
    audit_log_path: str = Field(default="logs/audit.jsonl", min_length=1)
    servers: dict[str, UpstreamServerConfig] = Field(..., min_length=1)

    @field_validator("servers")
    @classmethod
    def validate_server_names(
        cls, value: dict[str, UpstreamServerConfig]
    ) -> dict[str, UpstreamServerConfig]:
        for name in value:
            if not _VALID_SERVER_NAME.match(name):
                raise ValueError(
                    f"Invalid server name {name!r}; use only alphanumerics, '.', '_', '-'."
                )
        return value

    @model_validator(mode="after")
    def validate_default_server_exists(self) -> GuardConfig:
        if self.default_server not in self.servers:
            raise ValueError(
                f"default_server {self.default_server!r} is not defined in 'servers'."
            )
        if not self.servers[self.default_server].enabled:
            raise ValueError(
                f"default_server {self.default_server!r} is disabled."
            )
        return self

    def get_server(self, server_name: str | None = None) -> tuple[str, UpstreamServerConfig]:
        """Return (name, config) for an explicitly configured and enabled upstream server."""
        target = server_name or self.default_server
        if target not in self.servers:
            raise ConfigError(
                f"Upstream server {target!r} is not explicitly configured."
            )
        server_cfg = self.servers[target]
        if not server_cfg.enabled:
            raise ConfigError(f"Upstream server {target!r} is disabled.")
        return target, server_cfg


def load_config(config_path: str | Path) -> GuardConfig:
    """Load and validate a GuardConfig JSON file.

    Raises:
        ConfigError: If the file cannot be read, parsed, or fails security validation.
    """
    path = Path(config_path)
    if not path.is_file():
        raise ConfigError(f"Configuration file not found: {path}")

    try:
        raw_text = path.read_text(encoding="utf-8")
        raw_data = json.loads(raw_text)
    except OSError as exc:
        raise ConfigError(f"Failed to read configuration file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Invalid JSON in configuration file {path}: {exc}") from exc

    if not isinstance(raw_data, dict):
        raise ConfigError("Top-level configuration must be a JSON object.")

    try:
        return GuardConfig.model_validate(raw_data)
    except ValidationError as exc:
        raise ConfigError(f"Configuration validation failed: {exc}") from exc


def build_sanitized_env(extra_env: dict[str, str] | None = None) -> dict[str, str]:
    """Build a strict allowlisted environment dictionary for spawning an upstream MCP server.

    Strips arbitrary host environment variables (such as API keys or cloud tokens)
    while preserving essential OS/Python runtime variables including `PYTHONPATH`
    so proxies launched by Claude Desktop from external working directories work reliably.
    """
    inherited_keys = (
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "PROCESSOR_ARCHITECTURE",
        "COMSPEC",
        "TEMP",
        "TMP",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "USERNAME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PYTHONUTF8",
        "PYTHONPATH",
    )
    env: dict[str, str] = {}
    for key in inherited_keys:
        val = os.environ.get(key)
        if val is not None and not val.startswith("()"):
            env[key] = val
    if extra_env:
        env.update(extra_env)
    return env
