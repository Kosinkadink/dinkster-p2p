from __future__ import annotations

import errno
import socket
import time
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from dinkster_p2p import LanInterface, LanNetworkPolicy, default_p2p_settings, listeners
from dinkster_p2p import runtime as runtime_module
from dinkster_p2p.listeners import ListenerBindings, select_listen_port
from dinkster_p2p.runtime import SidecarRuntime


@pytest.mark.parametrize("exhausted", [False, True])
def test_port_selection_avoids_sequential_udp_exclusion(
    monkeypatch: pytest.MonkeyPatch, exhausted: bool
) -> None:
    candidates = list(range(52665, 52697)) if exhausted else [52665, 49152]
    sampler = MagicMock(return_value=candidates)
    monkeypatch.setattr("dinkster_p2p.listeners.random.SystemRandom.sample", sampler)
    probes: list[tuple[int, int]] = []
    opened: list[MagicMock] = []

    def make_socket(_family: int, kind: int) -> MagicMock:
        probe = MagicMock()
        probe.__enter__.return_value = probe

        def bind(endpoint: tuple[str, int]) -> None:
            address, port = endpoint
            assert address == "127.0.0.1" and port != 0
            probes.append((kind, port))
            if kind == socket.SOCK_DGRAM and 52664 <= port <= 52763:
                raise OSError(10013, "UDP excluded")

        probe.bind.side_effect = bind
        opened.append(probe)
        return probe

    monkeypatch.setattr("dinkster_p2p.listeners.socket.socket", make_socket)
    if exhausted:
        with pytest.raises(OSError, match="no dual TCP/UDP listener"):
            select_listen_port("127.0.0.1")
        assert len(probes) == 64
    else:
        assert select_listen_port("127.0.0.1") == 49152
        assert probes[-2:] == [(socket.SOCK_STREAM, 49152), (socket.SOCK_DGRAM, 49152)]
    sampler.assert_called_once_with(range(49152, 65536), 32)
    assert all(probe.__exit__.call_count == 1 for probe in opened)


def test_selected_port_is_dual_bindable() -> None:
    port = select_listen_port("127.0.0.1")
    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
        tcp.bind(("127.0.0.1", port))
        udp.bind(("127.0.0.1", port))
        tcp.listen()
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            connection, _address = tcp.accept()
            connection.close()


def test_listener_bindings_bound_recovery_and_ignore_stale_alerts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = MagicMock(side_effect=range(49152, 49200))
    monkeypatch.setattr(listeners, "select_listen_port", selected)
    bindings = ListenerBindings()
    assert bindings.configure("") == ""
    selected.assert_not_called()
    template = "192.168.1.2:0l,192.168.2.2:0l"
    assert bindings.configure(template) == "192.168.1.2:49152l,192.168.2.2:49153l"
    assert bindings.configure(template) == bindings.interfaces
    assert selected.call_count == 2
    assert not bindings.failed("192.168.1.2", 49151, 10013)
    for old, new in ((49152, 49154), (49154, 49155), (49155, 49156)):
        assert bindings.failed("192.168.1.2", old, 10013)
        assert f"192.168.1.2:{new}l" in bindings.interfaces
    assert bindings.failed("192.168.1.2", 49156, 10013)
    assert bindings.configure(template) == "192.168.2.2:49153l"
    assert selected.call_count == 5
    assert bindings.configure("") == ""
    assert not bindings.failed("192.168.2.2", 49153, 10013)
    assert bindings.configure(template) == "192.168.1.2:49157l,192.168.2.2:49158l"


@pytest.mark.parametrize("wildcard", [False, True])
def test_tcp_readiness_requires_current_binding_on_every_advertised_address(
    monkeypatch: pytest.MonkeyPatch, wildcard: bool
) -> None:
    monkeypatch.setattr(listeners, "select_listen_port", MagicMock(side_effect=range(49152, 49160)))
    bindings = ListenerBindings()
    addresses = ("192.168.1.2", "192.168.2.2")
    second_port = 49152 if wildcard else 49153
    template = "0.0.0.0:0" if wildcard else ",".join(f"{address}:0l" for address in addresses)
    bindings.configure(template)
    assert not bindings.tcp_ready(())
    assert not bindings.tcp_ready(addresses)
    assert bindings.tcp_endpoints == ()
    bindings.tcp_succeeded(addresses[0], 49152)
    assert bindings.tcp_endpoints == ((addresses[0], 49152),)
    bindings.tcp_succeeded(addresses[1], 49151)
    assert not bindings.tcp_ready(addresses)
    bindings.tcp_succeeded(addresses[1], second_port)
    assert bindings.tcp_ready(addresses)
    assert bindings.tcp_endpoints == (
        (addresses[0], 49152),
        (addresses[1], second_port),
    )
    bindings.configure(template)
    assert bindings.tcp_ready(addresses)
    assert not bindings.failed(addresses[1], 49151, errno.EADDRINUSE)
    assert bindings.tcp_ready(addresses)
    if wildcard:
        assert not bindings.failed(addresses[1], 49152, errno.EADDRINUSE, tcp=False)
        assert bindings.tcp_ready(addresses)
    bindings.failed(addresses[1], second_port, errno.EACCES)
    assert not bindings.tcp_ready(addresses)
    assert bindings.tcp_ready(addresses[:1])
    bindings.tcp_succeeded(addresses[1], 49152 if wildcard else 49154)
    assert bindings.tcp_ready(addresses)
    bindings.configure("")
    bindings.tcp_succeeded(addresses[1], 49152)
    assert not bindings.tcp_ready(addresses)
    bindings.configure(template)
    assert not bindings.tcp_ready(addresses)


@pytest.mark.parametrize(
    ("initial", "replacement"),
    [
        ("192.168.1.2:0l", "192.168.1.2:0l"),
        ("0.0.0.0:0", "192.168.1.2:0l"),
        ("192.168.1.2:0l,192.168.2.2:0l", "0.0.0.0:0"),
    ],
)
def test_listener_reconfiguration_cannot_reuse_stale_native_alert_ports(
    monkeypatch: pytest.MonkeyPatch, initial: str, replacement: str
) -> None:
    selected: list[int] = []

    def select(_address: str, excluded: frozenset[int]) -> int:
        assert set(selected) <= excluded
        port = 49152 + len(selected)
        selected.append(port)
        return port

    monkeypatch.setattr(listeners, "select_listen_port", select)
    bindings = ListenerBindings()
    bindings.configure(initial)
    old_ports = tuple(selected)
    bindings.configure("")
    bindings.configure(replacement)
    for port in old_ports:
        bindings.tcp_succeeded("192.168.1.2", port)
    assert not bindings.tcp_ready(("192.168.1.2",))
    bindings.tcp_succeeded("192.168.1.2", selected[-1])
    assert bindings.tcp_ready(("192.168.1.2",))
    for port in old_ports:
        assert not bindings.failed("192.168.1.2", port, errno.EACCES)
    assert bindings.tcp_ready(("192.168.1.2",))


def test_tcp_confirmation_retires_old_templates_but_keeps_current_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = MagicMock(side_effect=range(49152, 49160))
    monkeypatch.setattr(listeners, "select_listen_port", selected)
    bindings = ListenerBindings()
    bindings.configure("192.168.1.2:0l")
    bindings.configure("")
    bindings.configure("192.168.1.2:0l,192.168.2.2:0l")
    selected.assert_called_with("192.168.2.2", frozenset({49152, 49153}))
    assert bindings.failed("192.168.2.2", 49154, errno.EACCES, tcp=False)
    bindings.tcp_succeeded("192.168.1.2", 49153)
    bindings.configure("")
    bindings.configure("0.0.0.0:0")
    selected.assert_called_with("0.0.0.0", frozenset({49153, 49154, 49155}))
    bindings.tcp_succeeded("192.168.2.2", 49154)
    assert not bindings.tcp_ready(("192.168.2.2",))
    bindings.tcp_succeeded("192.168.2.2", 49156)
    assert bindings.tcp_ready(("192.168.2.2",))
    bindings.configure("")
    bindings.configure("192.168.2.2:0l")
    selected.assert_called_with("192.168.2.2", frozenset({49156}))


def test_udp_reselection_invalidates_previously_confirmed_tcp_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(listeners, "select_listen_port", MagicMock(side_effect=[49152, 49153]))
    bindings = ListenerBindings()
    bindings.configure("192.168.1.2:0l")
    bindings.tcp_succeeded("192.168.1.2", 49152)
    assert bindings.tcp_ready(("192.168.1.2",))
    assert bindings.failed("192.168.1.2", 49152, errno.EADDRINUSE, tcp=False)
    assert not bindings.tcp_ready(("192.168.1.2",))
    bindings.tcp_succeeded("192.168.1.2", 49152)
    assert not bindings.tcp_ready(("192.168.1.2",))
    bindings.tcp_succeeded("192.168.1.2", 49153)
    assert bindings.tcp_ready(("192.168.1.2",))


def test_listener_probe_exhaustion_closes_without_reopening_on_same_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = MagicMock(side_effect=OSError(errno.EACCES, "denied"))
    monkeypatch.setattr(listeners, "select_listen_port", selected)
    bindings = ListenerBindings()
    assert bindings.configure("127.0.0.1:0l") == ""
    assert bindings.configure("127.0.0.1:0l") == ""
    selected.assert_called_once()


def test_runtime_recovers_native_udp_handoff_collision_in_same_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    policy = LanNetworkPolicy(
        (LanInterface("test", IPv4Address("127.0.0.1"), IPv4Network("127.0.0.0/8")),)
    )
    monkeypatch.setattr(runtime_module, "current_lan_policy", lambda: policy)
    occupied = socket.socket(type=socket.SOCK_DGRAM)
    exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
    if isinstance(exclusive, int):
        occupied.setsockopt(socket.SOL_SOCKET, exclusive, 1)
    selected: list[int] = []

    def select(address: str, excluded: frozenset[int]) -> int:
        port = select_listen_port(address, excluded)
        if not selected:
            occupied.bind((address, port))
        selected.append(port)
        return port

    monkeypatch.setattr(listeners, "select_listen_port", select)
    settings = {**default_p2p_settings(), "downloadsEnabled": True}
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
        network_paused=True,
    )
    try:
        assert not selected
        session = runtime._session
        runtime.set_network_paused({"paused": False})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            runtime.poll_alerts()
            if (
                len(selected) == 2
                and session.is_listening()
                and session.listen_port() == selected[1]
            ):
                break
            time.sleep(0.01)
        assert len(selected) == 2 and selected[0] != selected[1]
        assert runtime._session is session
        assert session.listen_port() == selected[1]
        assert capsys.readouterr().err == ""
        assert not (tmp_path / "state" / "listener-error.txt").exists()
        diagnostic = cast(dict[str, Any], runtime.status()["diagnostics"])
        assert any(
            event["kind"] == "listener_failed"
            and event["address"] == "127.0.0.1"
            and event["port"] == selected[0]
            and event["errorCode"] != 0
            for event in diagnostic["events"]
        )
        with socket.create_connection(("127.0.0.1", selected[1]), timeout=1):
            pass
        runtime.configure(settings)
        assert len(selected) == 2
        runtime.set_network_paused({"paused": True})
        assert session.get_settings()["listen_interfaces"] == ""
    finally:
        runtime.close()
        occupied.close()


def test_legacy_listener_resume_preserves_counters_without_opening_sockets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = LanNetworkPolicy(
        (LanInterface("test", IPv4Address("127.0.0.1"), IPv4Network("127.0.0.0/8")),)
    )
    monkeypatch.setattr(runtime_module, "current_lan_policy", lambda: policy)
    selected = MagicMock(side_effect=AssertionError("paused restore must not probe"))
    monkeypatch.setattr(listeners, "select_listen_port", selected)
    settings = {**default_p2p_settings(), "downloadsEnabled": True}
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
        network_paused=True,
    )
    digest = "blake3:" + "1" * 64
    try:
        runtime._activity[digest] = runtime_module._ActivityRecord(
            digest, 100, downloaded_bytes=50, uploaded_bytes=20
        )
        runtime.save_state()
        libtorrent = runtime._lt
    finally:
        runtime.close()
    resume_path = tmp_path / "state" / "session.resume"
    resume = libtorrent.bdecode(resume_path.read_bytes())
    resume[b"settings"][b"listen_interfaces"] = b"127.0.0.1:0l"
    resume_path.write_bytes(libtorrent.bencode(resume))
    restored = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
        network_paused=True,
    )
    try:
        assert restored._recovery is None
        assert restored._activity[digest].downloaded_bytes == 50
        assert restored._activity[digest].uploaded_bytes == 20
        assert restored._session.get_settings()["listen_interfaces"] == ""
        assert not restored._session.is_listening()
        selected.assert_not_called()
    finally:
        restored.close()
