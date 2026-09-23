"""Native smoke gate for every declared P2P runtime matrix entry."""

from __future__ import annotations

import errno
import os
import secrets
import socket
import time
import tomllib
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

from dinkster_p2p import (
    LIBTORRENT_ARTIFACTS,
    LanInterface,
    LanNetworkPolicy,
    default_p2p_settings,
    select_libtorrent_artifact,
)
from dinkster_p2p import runtime as runtime_module
from dinkster_p2p.runtime import SidecarError, SidecarRuntime


def _available_loopback_port() -> int:
    last_error: OSError | None = None
    for _ in range(32):
        # TCP port-zero allocation can stay within a UDP-excluded range on Windows.
        port = 49152 + secrets.randbelow(16384)
        with (
            socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
        ):
            if os.name == "nt":
                tcp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                udp.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                tcp.bind(("127.0.0.1", port))
                udp.bind(("127.0.0.1", port))
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EADDRINUSE, 10013, 10048):
                    raise
                last_error = error
                continue
            return port
    raise RuntimeError("No loopback port available for both TCP and UDP") from last_error


@pytest.mark.parametrize("error_code", [errno.EACCES, errno.EADDRINUSE, 10013, 10048])
def test_smoke_port_rejects_udp_excluded_or_occupied_tcp_candidate(
    monkeypatch: pytest.MonkeyPatch, error_code: int
) -> None:
    denied_port: int | None = None
    sockets: list[socket.socket] = []

    class RestrictedUdpSocket(socket.socket):
        def bind(self, address: Any) -> None:
            nonlocal denied_port
            sockets.append(self)
            if self.type == socket.SOCK_DGRAM:
                if denied_port is None:
                    denied_port = address[1]
                if address[1] == denied_port:
                    raise OSError(error_code, "UDP port unavailable")
            super().bind(address)

    monkeypatch.setattr(socket, "socket", RestrictedUdpSocket)
    port = _available_loopback_port()
    assert denied_port is not None and port != denied_port
    assert all(probe.fileno() == -1 for probe in sockets)


def test_smoke_port_probes_explicit_candidates_and_rejects_tcp_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    occupied_port = _available_loopback_port()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
        if os.name == "nt":
            occupied.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        occupied.bind(("127.0.0.1", occupied_port))
        available_port = _available_loopback_port()
        candidates = iter((occupied_port, available_port))

        def candidate_offset(limit: int) -> int:
            assert limit == 16384
            return next(candidates) - 49152

        monkeypatch.setattr(secrets, "randbelow", candidate_offset)
        assert _available_loopback_port() == available_port
        assert next(candidates, None) is None


@pytest.mark.parametrize("error_code", [10013, errno.EINVAL])
def test_smoke_port_selection_is_bounded_and_preserves_unexpected_errors(
    monkeypatch: pytest.MonkeyPatch, error_code: int
) -> None:
    candidate = _available_loopback_port()
    monkeypatch.setattr(secrets, "randbelow", lambda limit: candidate - 49152)
    attempts = 0
    sockets: list[socket.socket] = []

    class UnavailableUdpSocket(socket.socket):
        def bind(self, address: Any) -> None:
            nonlocal attempts
            sockets.append(self)
            if self.type == socket.SOCK_DGRAM:
                attempts += 1
                raise OSError(error_code, "UDP bind refused")
            super().bind(address)

    monkeypatch.setattr(socket, "socket", UnavailableUdpSocket)
    if error_code == errno.EINVAL:
        with pytest.raises(OSError) as failure:
            _available_loopback_port()
        assert failure.value.errno == error_code
        assert attempts == 1
    else:
        with pytest.raises(RuntimeError, match="both TCP and UDP") as failure:
            _available_loopback_port()
        assert isinstance(failure.value.__cause__, OSError)
        assert failure.value.__cause__.errno == error_code
        assert attempts == 32
    assert all(probe.fileno() == -1 for probe in sockets)


def test_approved_artifact_records_match_the_lockfile() -> None:
    root = Path(__file__).parent.parent
    lock_path = root / "uv.lock"
    if not lock_path.is_file():
        lock_path = root / ".dinkster" / "uv.lock"
    lock = tomllib.loads(lock_path.read_text("utf-8"))
    package = next(item for item in lock["package"] if item["name"] == "libtorrent")
    locked = {Path(urlparse(item["url"]).path).name: item for item in package["wheels"]}
    for artifact in LIBTORRENT_ARTIFACTS.values():
        record = locked[artifact.filename]
        assert record["hash"] == f"sha256:{artifact.sha256}"
        assert record["size"] == artifact.size


def test_pinned_libtorrent_respects_disabled_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_root = tmp_path / "vault" / ".p2p"
    with pytest.raises(SidecarError, match="enabled P2P capability"):
        SidecarRuntime(
            state_root=state_root,
            vault_root=tmp_path / "vault",
            installation_root=tmp_path / "install",
            settings={
                **default_p2p_settings(),
                "downloadsEnabled": False,
                "seedingEnabled": False,
            },
        )
    assert not state_root.exists()

    # Artifact startup must not depend on discovery of a bindable host LAN interface.
    policy = LanNetworkPolicy(
        (LanInterface("loopback", IPv4Address("127.0.0.1"), IPv4Network("127.0.0.0/8")),)
    )
    monkeypatch.setattr(runtime_module, "current_lan_policy", lambda: policy)
    selected_ports: list[int] = []

    def isolated_port(address: str, excluded: frozenset[int]) -> int:
        assert address == "127.0.0.1"
        port = _available_loopback_port()
        while port in excluded:
            port = _available_loopback_port()
        selected_ports.append(port)
        return port

    monkeypatch.setattr("dinkster_p2p.listeners.select_listen_port", isolated_port)
    session_settings = runtime_module.session_settings

    def isolated_session_settings(*args: Any, **kwargs: Any) -> dict[str, object]:
        applied = session_settings(*args, **kwargs)
        applied["enable_lsd"] = False
        return applied

    monkeypatch.setattr(runtime_module, "session_settings", isolated_session_settings)
    listen_failures: list[str] = []
    handle_alert = SidecarRuntime._handle_alert

    def record_listen_failure(runtime: SidecarRuntime, alert: Any) -> None:
        if isinstance(alert, runtime._lt.listen_failed_alert):
            listen_failures.append(alert.message())
        handle_alert(runtime, alert)

    monkeypatch.setattr(SidecarRuntime, "_handle_alert", record_listen_failure)
    settings = {**default_p2p_settings(), "downloadsEnabled": True}
    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=tmp_path / "install",
        settings=settings,
    )
    try:
        status = runtime.status()
        deadline = time.monotonic() + 20.0
        while status["listenPort"] in (None, 0) and time.monotonic() < deadline:
            time.sleep(0.025)
            status = runtime.status()
        assert select_libtorrent_artifact().filename.endswith(".whl")
        assert status["libtorrentVersion"] == "2.1.1"
        assert status["listenInterfaces"] == ["127.0.0.1"]
        listen_port = status["listenPort"]
        assert isinstance(listen_port, int) and listen_port in selected_ports, (
            f"{status!r}\nNative listen failures: {listen_failures!r}"
        )
        with socket.create_connection(("127.0.0.1", listen_port), timeout=5):
            pass
        assert status["networkFeatures"] == {
            "dht": False,
            "trackers": False,
            "pex": False,
            "lsd": False,
            "upnp": False,
            "natMappings": False,
            "tcp": False,
            "utp": False,
            "natPmp": False,
            "pcp": False,
        }
        runtime.save_state()
        assert (state_root / "state.json").is_file()
        assert (state_root / "session.resume").is_file()
        if os.name != "nt":
            assert state_root.stat().st_mode & 0o777 == 0o700
            assert (state_root / "state.json").stat().st_mode & 0o777 == 0o600
            assert (state_root / "session.resume").stat().st_mode & 0o777 == 0o600
    finally:
        runtime.close()
