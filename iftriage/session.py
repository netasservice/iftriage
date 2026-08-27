"""ReadOnlySession — the single egress point to devices.

Safety layers implemented here:
  Layer 1: the raw driver connection is a private attribute; the only public
           way to run a command is get(). No other module may call the
           driver's send methods (code-review rule: any send_command /
           send_config outside this file is an automatic rejection).
  Layer 2: closed allow-list, fail closed. get() refuses any command that is
           not an exact member of the allow-list frozen at construction.
  Layer 3: prompt verification before and after every command. A config-mode
           prompt disconnects immediately and aborts the entire run.
  Layer 4: audit trail — every exact command sent to every IP, timestamped.
           Credentials and the enable secret never appear in the log; the
           enable step is logged as '<enable elevation>'.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .models import Credentials


class SafetyViolation(Exception):
    """Base class for read-only guarantee violations. Aborts the run."""


class CommandNotAllowed(SafetyViolation):
    """A command outside the closed allow-list was requested."""


class ConfigModeDetected(SafetyViolation):
    """A config-mode prompt was observed. The run must abort loudly."""


class SessionError(Exception):
    """Non-safety connection/session failure (timeout, auth, bad prompt)."""


class EnableRequired(SessionError):
    """The device landed in user exec and no enable secret was supplied.

    The enable secret is optional, so this is a per-device skip (the case ends
    up UNVERIFIED), never a run-level failure. The message deliberately avoids
    the substring 'auth': collectors._is_auth_error matches on it and would
    count this towards the AAA circuit breaker.
    """


class AuditLog:
    """Append-only, thread-safe session log. Never receives secrets."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, host: str, message: str) -> None:
        stamp = datetime.now(UTC).isoformat(timespec="seconds")
        line = f"{stamp} | {host} | {message}\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)


def _default_connect(
    host: str, device_type: str, credentials: Credentials, timeout: int
):
    """Create a Netmiko connection. Only ReadOnlySession may call this."""
    from netmiko import ConnectHandler  # imported lazily; tests never need it

    return ConnectHandler(
        host=host,
        device_type=device_type,
        username=credentials.username,
        password=credentials.password,
        secret=credentials.enable_secret or "",
        conn_timeout=timeout,
        read_timeout_override=timeout,
        fast_cli=False,
    )


class ReadOnlySession:
    """Wraps a device connection so that configuration change is structurally
    impossible. The only public command method is get()."""

    def __init__(
        self,
        host: str,
        device_type: str,
        credentials: Credentials,
        allowed_commands: frozenset[str] | set[str],
        audit: AuditLog,
        connect_fn: Callable | None = None,
        read_timeout: int = 30,
    ):
        self._host = host
        self._device_type = device_type
        self._credentials = credentials
        self._allowed = frozenset(allowed_commands)
        self._audit = audit
        self._connect_fn = connect_fn or _default_connect
        self._read_timeout = read_timeout
        self.__conn = None  # private: the raw driver connection

    # -- lifecycle -----------------------------------------------------------

    def connect(self) -> None:
        conn = self._connect_fn(
            self._host, self._device_type, self._credentials, self._read_timeout
        )
        self.__conn = conn
        self._audit.record(self._host, "<connected>")
        prompt = self._prompt()
        self._guard_config_mode(prompt)
        if prompt.rstrip().endswith(">"):
            # User exec: elevate read-only via the driver's native enable().
            # This is the only sanctioned exception to the allow-list.
            if not self._credentials.enable_secret:
                self.disconnect()
                raise EnableRequired(
                    f"{self._host}: device requires enable but no enable secret "
                    "was provided"
                )
            conn.enable()
            self._audit.record(self._host, "<enable elevation>")
            prompt = self._prompt()
            self._guard_config_mode(prompt)
        if not prompt.rstrip().endswith("#"):
            self.disconnect()
            raise SessionError(
                f"{self._host}: unexpected prompt after connect: {prompt!r}"
            )

    def disconnect(self) -> None:
        conn, self.__conn = self.__conn, None
        if conn is not None:
            try:
                conn.disconnect()
            except Exception:
                pass
            self._audit.record(self._host, "<disconnected>")

    def __enter__(self) -> ReadOnlySession:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.disconnect()

    # -- the single egress point --------------------------------------------

    def get(self, command: str) -> str:
        """Run one allow-listed show command and return its raw output."""
        if command not in self._allowed:
            raise CommandNotAllowed(
                f"{self._host}: command not in allow-list, refusing: {command!r}"
            )
        if self.__conn is None:
            raise SessionError(f"{self._host}: not connected")
        self._assert_privileged_exec()
        output = self.__conn.send_command(command, read_timeout=self._read_timeout)
        self._assert_privileged_exec()
        self._audit.record(self._host, command)
        return output

    # -- prompt guards (layer 3) --------------------------------------------

    def _prompt(self) -> str:
        if self.__conn is None:
            raise SessionError(f"{self._host}: not connected")
        return self.__conn.find_prompt()

    def _guard_config_mode(self, prompt: str) -> None:
        if "(config" in prompt:
            self.disconnect()
            raise ConfigModeDetected(
                f"{self._host}: CONFIG-MODE PROMPT DETECTED ({prompt!r}). "
                "Read-only guarantee violated — aborting entire run."
            )

    def _assert_privileged_exec(self) -> None:
        prompt = self._prompt()
        self._guard_config_mode(prompt)
        if not prompt.rstrip().endswith("#"):
            self.disconnect()
            raise SessionError(
                f"{self._host}: prompt is not privileged exec: {prompt!r}"
            )
