"""Safety-layer tests: allow-list rejection, config-mode abort, audit trail.

Zero device access: a fake connection object stands in for Netmiko.
"""

import pytest

from iftriage.models import Credentials
from iftriage.session import (
    AuditLog,
    CommandNotAllowed,
    ConfigModeDetected,
    EnableRequired,
    ReadOnlySession,
    SessionError,
)

CREDS = Credentials(username="ops", password="pw", enable_secret="S3cr3t-Enable")
ALLOWED = frozenset({"show version", "show interfaces GigabitEthernet3/0/20"})


class FakeConn:
    def __init__(self, prompts):
        self.prompts = list(prompts)
        self.sent: list[str] = []
        self.enabled = False
        self.disconnected = False

    def find_prompt(self):
        if len(self.prompts) > 1:
            return self.prompts.pop(0)
        return self.prompts[0]

    def send_command(self, command, read_timeout=None):
        self.sent.append(command)
        return f"output of {command}"

    def enable(self):
        self.enabled = True

    def disconnect(self):
        self.disconnected = True


def make_session(tmp_path, fake):
    audit = AuditLog(tmp_path / "audit.log")
    session = ReadOnlySession(
        host="10.0.0.1",
        device_type="cisco_xe",
        credentials=CREDS,
        allowed_commands=ALLOWED,
        audit=audit,
        connect_fn=lambda host, dt, creds, timeout: fake,
    )
    return session, audit


def test_allowed_command_is_sent_and_audited(tmp_path):
    fake = FakeConn(["switch#"])
    session, audit = make_session(tmp_path, fake)
    session.connect()
    out = session.get("show version")
    assert out == "output of show version"
    assert fake.sent == ["show version"]
    log = audit.path.read_text()
    assert "show version" in log
    assert "10.0.0.1" in log


def test_non_allowlisted_command_is_rejected_before_sending(tmp_path):
    fake = FakeConn(["switch#"])
    session, _ = make_session(tmp_path, fake)
    session.connect()
    for bad in (
        "show running-config",
        "configure terminal",
        "clear counters",
        "debug all",
        "show tech-support",
        "reload",
    ):
        with pytest.raises(CommandNotAllowed):
            session.get(bad)
    assert fake.sent == []  # nothing ever reached the device


def test_config_mode_prompt_on_connect_aborts_and_disconnects(tmp_path):
    fake = FakeConn(["switch(config)#"])
    session, _ = make_session(tmp_path, fake)
    with pytest.raises(ConfigModeDetected):
        session.connect()
    assert fake.disconnected


def test_config_mode_prompt_after_command_aborts(tmp_path):
    # connect check -> ok, pre-command check -> ok, post-command -> config mode
    fake = FakeConn(["switch#", "switch#", "switch(config-if)#"])
    session, _ = make_session(tmp_path, fake)
    session.connect()
    with pytest.raises(ConfigModeDetected):
        session.get("show version")
    assert fake.disconnected


def test_enable_elevation_from_user_exec_is_audited_without_secret(tmp_path):
    fake = FakeConn(["switch>", "switch#"])
    session, audit = make_session(tmp_path, fake)
    session.connect()
    assert fake.enabled
    log = audit.path.read_text()
    assert "<enable elevation>" in log
    assert "S3cr3t-Enable" not in log
    assert "pw" not in log.split()  # password never logged


def test_user_exec_without_enable_secret_fails(tmp_path):
    fake = FakeConn(["switch>"])
    audit = AuditLog(tmp_path / "audit.log")
    session = ReadOnlySession(
        host="10.0.0.1",
        device_type="cisco_xe",
        credentials=Credentials(username="ops", password="pw"),
        allowed_commands=ALLOWED,
        audit=audit,
        connect_fn=lambda host, dt, creds, timeout: fake,
    )
    with pytest.raises(EnableRequired) as excinfo:
        session.connect()
    assert fake.disconnected
    assert "requires enable" in str(excinfo.value)
    # collectors._is_auth_error matches the substring 'auth': a missing optional
    # enable secret must never be counted towards the AAA circuit breaker.
    assert "auth" not in str(excinfo.value).lower()
    assert issubclass(EnableRequired, SessionError)


def test_credentials_repr_never_exposes_secrets():
    text = repr(CREDS)
    assert "pw" not in text
    assert "S3cr3t-Enable" not in text


def test_oversized_output_is_truncated_to_the_tail(tmp_path):
    """`show logging` on a noisy port can return megabytes. get() bounds it,
    keeps the newest (trailing) lines, and says so in the output itself."""

    class HugeConn(FakeConn):
        def send_command(self, command, read_timeout=None):
            self.sent.append(command)
            return "\n".join(f"line {i}" for i in range(20000))

    fake = HugeConn(["switch#"])
    audit = AuditLog(tmp_path / "audit.log")
    session = ReadOnlySession(
        host="10.0.0.1",
        device_type="cisco_xe",
        credentials=CREDS,
        allowed_commands=ALLOWED,
        audit=audit,
        connect_fn=lambda host, dt, creds, timeout: fake,
        max_output_bytes=500,
    )
    session.connect()
    out = session.get("show version")

    assert "output truncated" in out.splitlines()[0]
    assert len(out) < 700  # ceiling plus the one-line marker
    assert out.endswith("line 19999")
    assert "show version" in audit.path.read_text()


def test_output_within_the_ceiling_is_returned_verbatim(tmp_path):
    fake = FakeConn(["switch#"])
    audit = AuditLog(tmp_path / "audit.log")
    session = ReadOnlySession(
        host="10.0.0.1",
        device_type="cisco_xe",
        credentials=CREDS,
        allowed_commands=ALLOWED,
        audit=audit,
        connect_fn=lambda host, dt, creds, timeout: fake,
        max_output_bytes=500,
    )
    session.connect()
    assert session.get("show version") == "output of show version"


def test_member_allow_list_is_scoped_to_member_keys(tmp_path):
    """A session built for the port-channel member pass allows exactly the
    per-interface commands for the validated members — nothing device-level,
    nothing for other interfaces."""
    from iftriage.models import Platform
    from iftriage.platforms import get_profile
    from iftriage.platforms.base import MEMBER_KEYS

    profile = get_profile(Platform.IOS_XE)
    allowed = profile.allowed_commands(["GigabitEthernet3/0/23"], keys=MEMBER_KEYS)

    fake = FakeConn(["switch#"])
    audit = AuditLog(tmp_path / "audit.log")
    session = ReadOnlySession(
        host="10.0.0.1",
        device_type="cisco_xe",
        credentials=CREDS,
        allowed_commands=allowed,
        audit=audit,
        connect_fn=lambda host, dt, creds, timeout: fake,
    )
    session.connect()

    session.get("show interfaces GigabitEthernet3/0/23")  # member command: allowed
    for bad in (
        "show version",
        "show etherchannel summary",
        "show interfaces GigabitEthernet3/0/24",
    ):
        with pytest.raises(CommandNotAllowed):
            session.get(bad)
