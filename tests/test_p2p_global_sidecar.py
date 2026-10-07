"""Global sidecar scope, closure, tracker, and budget behavior."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import psutil
import pytest
from dinkster_assets import (
    P2P_PIECE_LENGTH,
    AssetVault,
    P2PGrantSnapshot,
    P2PLocalFileMapping,
    derive_p2p_descriptor,
)
from dinkster_assets.p2p_global import GlobalP2PCounterStore

from dinkster_p2p import (
    MAX_GLOBAL_LEASE_SECONDS,
    DownloadLease,
    P2PLeaseError,
    P2PManagerError,
    P2PSidecarManager,
    SeedLease,
    authorized_global_leases,
    default_p2p_settings,
    seed_lease_from_wire,
)
from dinkster_p2p.global_transfers import GlobalTransferController
from dinkster_p2p.runtime import SidecarError, SidecarRuntime
from tests.p2p_global_fixtures import TRUSTED_PROVIDER_IDS, build_provider_fixture

_GRANT_ID = "a" * 64


def _seed_lease(
    tmp_path: Path,
    *,
    grant_ids: list[str] | None = None,
    expires_at: float | None = None,
) -> SeedLease:
    source = tmp_path / "fixture.safetensors"
    payload_size = 1024
    header = json.dumps(
        {
            "weight": {
                "data_offsets": [0, payload_size],
                "dtype": "U8",
                "shape": [payload_size],
            }
        },
        separators=(",", ":"),
    ).encode("utf-8")
    header += b" " * (-len(header) % 8)
    source.write_bytes(len(header).to_bytes(8, "little") + header + bytes(payload_size))
    descriptor = derive_p2p_descriptor(source)
    return seed_lease_from_wire(
        {
            "version": 1,
            "kind": "seed",
            "leaseId": "global-fixture",
            "digest": descriptor.asset_digest,
            "sizeBytes": descriptor.size,
            "descriptor": descriptor.descriptor.to_wire(),
            "grantIds": [_GRANT_ID] if grant_ids is None else grant_ids,
            "localPath": str(source.resolve()),
            "scope": "lan-and-internet",
            "expiresAt": time.time() + 60 if expires_at is None else expires_at,
        }
    )


def _grant_global(
    runtime: SidecarRuntime,
    lease: DownloadLease | SeedLease,
    trackers: tuple[str, ...] = (),
) -> dict[str, object]:
    return runtime.grant_global({"lease": lease.to_wire(), "trackers": list(trackers)})


def _peer(
    address: str,
    *,
    port: int = 6881,
    peer_id: str = "peer",
    downloaded: int = 0,
    uploaded: int = 0,
    download_rate: int = 0,
    upload_rate: int = 0,
) -> SimpleNamespace:
    return SimpleNamespace(
        ip=(address, port),
        pid=peer_id,
        total_download=downloaded,
        total_upload=uploaded,
        payload_down_speed=download_rate,
        payload_up_speed=upload_rate,
    )


def _global_settings(**changes: object) -> dict[str, object]:
    return {
        **default_p2p_settings(),
        "downloadsEnabled": True,
        "seedingEnabled": True,
        "scope": "lan-and-internet",
        **changes,
    }


class _AccountingHandle:
    def __init__(
        self,
        peers: list[SimpleNamespace],
        *,
        downloaded: int = 0,
        uploaded: int = 0,
    ) -> None:
        self.peers = peers
        self.downloaded = downloaded
        self.uploaded = uploaded
        self.calls: list[str] = []

    def get_peer_info(self) -> list[SimpleNamespace]:
        self.calls.append("get_peer_info")
        return self.peers

    def status(self) -> SimpleNamespace:
        self.calls.append("status")
        return SimpleNamespace(
            state="seeding",
            is_finished=True,
            is_seeding=True,
            paused=False,
            all_time_download=self.downloaded,
            all_time_upload=self.uploaded,
        )

    @staticmethod
    def replace_trackers(_trackers: object) -> None:
        pass

    @staticmethod
    def set_flags(_flags: object, _mask: object) -> None:
        pass


def _accounting_controller(
    tmp_path: Path,
    lease: SeedLease,
    handle: _AccountingHandle,
    *,
    allows_lan_peer: Callable[[str], bool],
) -> GlobalTransferController:
    controller = GlobalTransferController(
        cast(Any, object()),
        SimpleNamespace(remove_torrent=lambda _: None),
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        torrent_flags=lambda _: 0,
        shared_handle_for=lambda _: None,
        release_shared_handle=lambda _lease, _handle: None,
        allows_lan_peer=allows_lan_peer,
    )
    internal = cast(Any, controller)
    internal._leases = {lease.lease_id: lease}
    internal._handles = {lease.lease_id: handle}
    internal._last_totals = {lease.lease_id: (0, 0)}
    internal._last_peer_totals = {lease.lease_id: {}}
    return controller


def _global_tcp_listener_open(port: int) -> bool:
    return any(
        connection.laddr
        and connection.laddr.port == port
        and connection.status == psutil.CONN_LISTEN
        for connection in psutil.Process().net_connections(kind="tcp")
    )


def _assert_tcp_listener_closed(port: int) -> None:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if not _global_tcp_listener_open(port):
            return
        time.sleep(0.01)
    pytest.fail(f"global TCP listener {port} remained open")


def _assert_tcp_listener_open(port: int) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if _global_tcp_listener_open(port):
            return
        time.sleep(0.01)
    pytest.fail(f"global TCP listener {port} did not open")


def test_global_session_closes_on_scope_network_pause_and_revocation_while_lan_survives(
    tmp_path: Path,
) -> None:
    lease = _seed_lease(tmp_path)
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(
            internetUploadBytesPerSecond=1234,
            internetDownloadBytesPerSecond=5678,
        ),
    )
    try:
        with pytest.raises(SidecarError, match="trusted provider authority"):
            runtime.grant(lease.to_wire(), "seed")
        _grant_global(runtime, lease)
        active = runtime.status()
        assert active["listenPort"] is not None
        assert active["global"]["active"] is True  # type: ignore[index]
        assert active["networkFeatures"] == {
            "dht": True,
            "pex": True,
            "tcp": True,
            "utp": True,
            "trackers": False,
            "upnp": True,
            "natMappings": True,
            "natPmp": True,
            "pcp": True,
            "lsd": True,
        }
        shared_session = cast(Any, runtime)._session
        assert cast(Any, runtime)._global._session is shared_session
        assert shared_session.get_settings()["upload_rate_limit"] == 1234
        assert shared_session.get_settings()["download_rate_limit"] == 5678
        assert shared_session.get_settings()["dht_bootstrap_nodes"] == "dht.libtorrent.org:25401"
        global_port = active["global"]["listenPort"]  # type: ignore[index]
        assert isinstance(global_port, int)
        _assert_tcp_listener_open(global_port)

        paused = runtime.pause()
        assert cast(Any, runtime)._session is shared_session
        assert paused["global"]["active"] is False  # type: ignore[index]
        assert paused["global"]["closureReason"] == "paused"  # type: ignore[index]
        resumed = runtime.resume()
        assert cast(Any, runtime)._session is shared_session
        assert resumed["global"]["active"] is True  # type: ignore[index]

        lan_only = runtime.configure(_global_settings(scope="lan-only"))
        assert cast(Any, runtime)._session is shared_session
        assert lan_only["listenPort"] is not None
        assert lan_only["global"]["active"] is False  # type: ignore[index]
        assert lan_only["global"]["closureReason"] == "scope-disabled"  # type: ignore[index]
        assert lan_only["leases"][0]["state"] == "disabled"  # type: ignore[index]
        _assert_tcp_listener_closed(global_port)

        restored = runtime.configure(_global_settings())
        assert restored["global"]["active"] is True  # type: ignore[index]
        paused = runtime.set_global_network_policy({"cost": "metered", "paused": True})
        assert paused["global"]["active"] is False  # type: ignore[index]
        assert paused["global"]["closureReason"] == "metered-network"  # type: ignore[index]
        assert paused["state"] == "running"
        assert paused["networkPaused"] is False
        assert paused["networkFeatures"]["lsd"] is True  # type: ignore[index]
        assert not cast(Any, runtime)._session.is_paused()

        unpaused = runtime.set_global_network_policy({"cost": "unmetered", "paused": False})
        assert unpaused["global"]["active"] is False  # type: ignore[index]
        assert unpaused["global"]["closureReason"] == "resume-required"  # type: ignore[index]
        runtime.resume_transfer({"digest": lease.digest})
        assert runtime.status()["global"]["active"] is True  # type: ignore[index]
        lease.local_path.write_bytes(lease.local_path.read_bytes()[:-1] + b"x")
        runtime.maintain()
        stale = runtime.status()
        assert stale["global"]["active"] is False  # type: ignore[index]
        assert stale["global"]["closureReason"] == "seed-mapping-stale"  # type: ignore[index]

        lease.local_path.write_bytes(lease.local_path.read_bytes()[:-1] + b"\0")
        runtime.revoke({"leaseId": lease.lease_id})
        revoked = runtime.status()
        assert revoked["global"]["active"] is False  # type: ignore[index]
        assert revoked["global"]["closureReason"] == "no-authority"  # type: ignore[index]
        assert revoked["listenPort"] is not None
    finally:
        runtime.close()


def test_only_approved_trackers_reach_the_global_session(tmp_path: Path) -> None:
    tracker = "https://tracker.example/announce"
    lease = _seed_lease(tmp_path)
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        _grant_global(runtime, lease, (tracker,))
        assert runtime.status()["networkFeatures"]["trackers"] is True  # type: ignore[index]
        controller = cast(Any, runtime)._global
        handle = next(iter(controller._handles.values()))
        assert [entry["url"] for entry in handle.trackers()] == [tracker]
        with pytest.raises(SidecarError, match="HTTPS or UDP"):
            _grant_global(runtime, lease, ("http://tracker.example/announce",))
        with pytest.raises(SidecarError, match="internet scope"):
            _grant_global(runtime, replace(lease, scope="lan-only"), (tracker,))
    finally:
        runtime.close()

    with pytest.raises(P2PLeaseError, match="fields must be exactly"):
        seed_lease_from_wire({**lease.to_wire(), "trackers": [tracker]})


def test_global_seed_requires_a_current_safe_format_mapping(tmp_path: Path) -> None:
    source = tmp_path / "unsafe.bin"
    source.write_bytes(b"not a safe model format")
    descriptor = derive_p2p_descriptor(source)
    lease = seed_lease_from_wire(
        {
            "version": 1,
            "kind": "seed",
            "leaseId": "unsafe-global-fixture",
            "digest": descriptor.asset_digest,
            "sizeBytes": descriptor.size,
            "descriptor": descriptor.descriptor.to_wire(),
            "grantIds": [_GRANT_ID],
            "localPath": str(source.resolve()),
            "scope": "lan-and-internet",
            "expiresAt": time.time() + 60,
        }
    )
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        with pytest.raises(SidecarError, match="localPath verification failed"):
            _grant_global(runtime, lease)
        assert runtime.status()["global"]["active"] is False  # type: ignore[index]
    finally:
        runtime.close()


def test_global_seed_rechecks_mapping_at_final_session_admission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _seed_lease(tmp_path)
    original_require_current = P2PLocalFileMapping.require_current
    calls = 0

    def mutate_before_final_check(mapping: P2PLocalFileMapping) -> Path:
        nonlocal calls
        calls += 1
        if calls == 3:
            payload = mapping.path.read_bytes()
            mapping.path.write_bytes(payload[:-1] + bytes([payload[-1] ^ 1]))
        return original_require_current(mapping)

    monkeypatch.setattr(P2PLocalFileMapping, "require_current", mutate_before_final_check)
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        with pytest.raises(SidecarError, match="seed mapping is not safe and current"):
            _grant_global(runtime, lease)
        assert calls == 3
        assert runtime.status()["global"]["active"] is False  # type: ignore[index]
    finally:
        runtime.close()


def test_global_seed_surfaces_unavailable_change_token_at_final_admission(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _seed_lease(tmp_path)
    calls = 0
    original_require_current = P2PLocalFileMapping.require_current

    def unavailable_at_final_admission(mapping: P2PLocalFileMapping) -> Path:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("USN change token unavailable")
        return original_require_current(mapping)

    monkeypatch.setattr(P2PLocalFileMapping, "require_current", unavailable_at_final_admission)
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        with pytest.raises(
            SidecarError,
            match="seed mapping is not safe and current: USN change token unavailable",
        ):
            _grant_global(runtime, lease)
        recovery = cast(dict[str, object], runtime.status()["recovery"])
        assert recovery["state"] == "global-session-closed"
        assert recovery["error"] == (
            "seed mapping is not safe and current: USN change token unavailable"
        )
    finally:
        runtime.close()


def test_global_seed_manager_surfaces_unavailable_change_token(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    lease = _seed_lease(tmp_path)
    manager = P2PSidecarManager(vault_root=tmp_path / "vault")

    def fail_mapping(*_args: object, **_kwargs: object) -> P2PLocalFileMapping:
        raise OSError("USN change token unavailable")

    monkeypatch.setattr(AssetVault, "verify_p2p_local_file", fail_mapping)
    with pytest.raises(
        P2PManagerError,
        match="global seed mapping is not safe and current: USN change token unavailable",
    ):
        cast(Any, manager)._verify_global_seed(lease)


def test_six_hour_limit_and_durable_ratio_budget_stop_global_announcement(tmp_path: Path) -> None:
    overlong = _seed_lease(tmp_path, expires_at=time.time() + MAX_GLOBAL_LEASE_SECONDS + 60)
    rejecting = SidecarRuntime(
        state_root=tmp_path / "rejecting-state",
        vault_root=tmp_path / "rejecting-vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        with pytest.raises(SidecarError, match="six-hour maximum"):
            _grant_global(rejecting, overlong)
    finally:
        rejecting.close()

    lease = _seed_lease(tmp_path, grant_ids=["b" * 64, "c" * 64])
    state_root = tmp_path / "state"
    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(internetSeedRatio=1.0),
    )
    try:
        _grant_global(runtime, lease)
        assert runtime.status()["global"]["active"] is True  # type: ignore[index]
        with GlobalP2PCounterStore(state_root / "global-counters.sqlite") as counters:
            assert counters.get(lease.digest).ratio_equivalent_bytes == lease.size_bytes
            counters.record_transfer(lease.digest, uploaded_bytes=lease.size_bytes)
        runtime.maintain()
        stopped = runtime.status()
        assert stopped["global"]["active"] is False  # type: ignore[index]
        assert stopped["global"]["closureReason"] == "budget-exhausted"  # type: ignore[index]
    finally:
        runtime.close()

    state = json.loads((state_root / "state.json").read_text("utf-8"))
    assert state["leases"] == []

    restarted = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(internetSeedRatio=1.0),
    )
    try:
        assert restarted.status()["global"]["active"] is False  # type: ignore[index]
    finally:
        restarted.close()


def test_durable_seed_time_budget_stops_global_announcement(tmp_path: Path) -> None:
    lease = _seed_lease(tmp_path)
    state_root = tmp_path / "state"
    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(internetSeedTimeSeconds=10),
    )
    try:
        _grant_global(runtime, lease)
        assert runtime.status()["global"]["active"] is True  # type: ignore[index]
        with GlobalP2PCounterStore(state_root / "global-counters.sqlite") as counters:
            counters.record_transfer(lease.digest, active_seed_seconds=10)
        runtime.maintain()
        assert runtime.status()["global"]["active"] is False  # type: ignore[index]
    finally:
        runtime.close()


def test_transfer_actions_control_global_session_and_preserve_counters(
    tmp_path: Path,
) -> None:
    lease = _seed_lease(tmp_path)
    state_root = tmp_path / "state"
    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(internetSeedRatio=1.0),
    )
    try:
        _grant_global(runtime, lease)
        assert runtime.status()["global"]["active"] is True  # type: ignore[index]

        runtime.pause_transfer({"digest": lease.digest})
        paused = runtime.status()
        assert paused["global"]["active"] is False  # type: ignore[index]
        assert paused["transfers"][0]["state"] == "paused"  # type: ignore[index]
        runtime.resume_transfer({"digest": lease.digest})
        assert runtime.status()["global"]["active"] is True  # type: ignore[index]

        with GlobalP2PCounterStore(state_root / "global-counters.sqlite") as counters:
            counters.record_transfer(lease.digest, uploaded_bytes=lease.size_bytes)
        runtime.maintain()
        assert runtime.status()["global"]["active"] is False  # type: ignore[index]
        with pytest.raises(SidecarError, match="seed budget is exhausted"):
            runtime.resume_transfer({"digest": lease.digest})

        runtime.reset_transfer_budget({"digest": lease.digest})
        reset = runtime.status()
        assert reset["global"]["active"] is False  # type: ignore[index]
        assert reset["totals"]["uploadedBytes"] == lease.size_bytes  # type: ignore[index]
        assert reset["transfers"][0]["remainingSeedRatio"] == 1.0  # type: ignore[index]
        runtime.resume_transfer({"digest": lease.digest})
        assert runtime.status()["global"]["active"] is True  # type: ignore[index]

        with GlobalP2PCounterStore(state_root / "global-counters.sqlite") as counters:
            counters.record_transfer(lease.digest, uploaded_bytes=lease.size_bytes)
        runtime.maintain()
        assert runtime.status()["global"]["active"] is False  # type: ignore[index]
        with pytest.raises(SidecarError, match="seed budget is exhausted"):
            runtime.resume_transfer({"digest": lease.digest})
        runtime.make_transfer_continuous({"digest": lease.digest})
        assert runtime.status()["global"]["active"] is False  # type: ignore[index]
        runtime.resume_transfer({"digest": lease.digest})
        assert runtime.status()["global"]["active"] is True  # type: ignore[index]
        runtime.stop_transfer({"digest": lease.digest})
        assert runtime.status()["global"]["active"] is False  # type: ignore[index]
    finally:
        runtime.close()

    restarted = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(internetSeedRatio=1.0),
    )
    try:
        status = restarted.status()
        assert status["global"]["active"] is False  # type: ignore[index]
        assert status["transfers"][0]["state"] == "stopped"  # type: ignore[index]
        assert status["totals"]["uploadedBytes"] == 2 * lease.size_bytes  # type: ignore[index]
    finally:
        restarted.close()


def test_lan_and_global_activity_counters_remain_independent_across_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("dinkster_p2p.global_transfers.time.monotonic", lambda: 100.0)
    lease = _seed_lease(tmp_path)
    state_root = tmp_path / "state"
    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        _grant_global(runtime, lease)
        record = cast(Any, runtime)._activity[lease.digest]
        record.downloaded_bytes = 5
        record.uploaded_bytes = 7
        with GlobalP2PCounterStore(state_root / "global-counters.sqlite") as counters:
            counters.record_transfer(
                lease.digest,
                downloaded_bytes=11,
                uploaded_bytes=13,
                active_seed_seconds=17,
            )
        status = runtime.status()
        assert status["totals"] == {"downloadedBytes": 16, "uploadedBytes": 20}
        runtime.reset_transfer_budget({"digest": lease.digest})
        assert record.seed_uploaded_baseline == 7
        assert record.global_uploaded_baseline == 13
        assert record.global_seed_seconds_baseline == 17
    finally:
        runtime.close()

    restored = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        status = restored.status()
        assert status["totals"] == {"downloadedBytes": 16, "uploadedBytes": 20}
        record = cast(Any, restored)._activity[lease.digest]
        assert record.seed_uploaded_baseline == 7
        assert record.global_uploaded_baseline == 13
        assert record.global_seed_seconds_baseline == 17
    finally:
        restored.close()


def test_frequent_status_polling_does_not_erase_seed_time(monkeypatch, tmp_path: Path) -> None:
    now = [100.0]
    monkeypatch.setattr("dinkster_p2p.global_transfers.time.monotonic", lambda: now[0])
    lease = _seed_lease(tmp_path)
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        _grant_global(runtime, lease)
        for _ in range(100):
            if runtime.status()["global"]["transfers"][0]["state"] == "seeding":  # type: ignore[index]
                break
            time.sleep(0.01)
        else:
            pytest.fail("fixture did not enter seeding state")
        now[0] += 0.6
        runtime.status()
        now[0] += 0.6
        status = runtime.status()
        assert status["global"]["transfers"][0]["activeSeedSeconds"] == 1  # type: ignore[index]
    finally:
        runtime.close()


def test_global_session_close_persists_final_transfer_counters(monkeypatch, tmp_path: Path) -> None:
    now = [100.0]
    monkeypatch.setattr("dinkster_p2p.global_transfers.time.monotonic", lambda: now[0])
    lease = _seed_lease(tmp_path)
    controller = GlobalTransferController(
        cast(Any, object()),
        SimpleNamespace(remove_torrent=lambda _: None),
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        torrent_flags=lambda _: 0,
        shared_handle_for=lambda _: None,
        release_shared_handle=lambda _lease, _handle: None,
        allows_lan_peer=lambda _: False,
    )

    class FakeHandle:
        @staticmethod
        def status():
            return SimpleNamespace(
                total_done=lease.size_bytes,
                all_time_download=11,
                all_time_upload=29,
                is_seeding=True,
                paused=False,
            )

        @staticmethod
        def get_peer_info():
            return [_peer("198.51.100.1", downloaded=11, uploaded=29)]

    class FakeSession:
        @staticmethod
        def remove_torrent(_: object) -> None:
            pass

    internal = cast(Any, controller)
    internal._session = FakeSession()
    internal._leases = {lease.lease_id: lease}
    internal._handles = {lease.lease_id: FakeHandle()}
    internal._last_totals = {lease.lease_id: (0, 0)}
    internal._last_peer_totals = {lease.lease_id: {}}
    internal._last_tick = 99.0
    controller.close_transfers()

    counters = controller.counters(lease.digest)
    assert counters.downloaded_bytes == 11
    assert counters.uploaded_bytes == 29
    assert counters.active_seed_seconds == 1
    controller.close()


def test_global_accounting_excludes_lan_peers_on_a_shared_handle(tmp_path: Path) -> None:
    lease = _seed_lease(tmp_path)
    released: list[object] = []
    removed: list[object] = []
    network_plans: list[tuple[bool, bool]] = []
    totals = {"downloaded": 0, "uploaded": lease.size_bytes * 2 + 10}
    peers = [
        _peer("192.168.1.20", peer_id="lan", uploaded=lease.size_bytes * 2, upload_rate=50),
        _peer("198.51.100.20", peer_id="global", uploaded=10, upload_rate=7),
    ]

    class FakeHandle:
        @staticmethod
        def status():
            return SimpleNamespace(
                state="seeding",
                is_finished=True,
                is_seeding=True,
                paused=False,
                all_time_download=totals["downloaded"],
                all_time_upload=totals["uploaded"],
            )

        @staticmethod
        def get_peer_info():
            return peers

        @staticmethod
        def replace_trackers(_trackers: object) -> None:
            pass

    class FakeSession:
        @staticmethod
        def remove_torrent(handle: object) -> None:
            removed.append(handle)

        @staticmethod
        def get_settings() -> dict[str, bool]:
            return {
                "enable_dht": True,
                "enable_incoming_tcp": True,
                "enable_outgoing_tcp": True,
                "enable_incoming_utp": True,
                "enable_outgoing_utp": True,
                "enable_upnp": True,
                "enable_natpmp": True,
            }

        @staticmethod
        def is_dht_running() -> bool:
            return True

        @staticmethod
        def is_listening() -> bool:
            return False

    handle = FakeHandle()
    controller = GlobalTransferController(
        cast(Any, object()),
        FakeSession(),
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        torrent_flags=lambda _: 0,
        shared_handle_for=lambda _: handle,
        release_shared_handle=lambda _lease, value: released.append(value),
        allows_lan_peer=lambda address: address == "192.168.1.20",
    )
    internal = cast(Any, controller)
    internal._leases = {lease.lease_id: lease}
    internal._handles = {lease.lease_id: handle}
    internal._borrowed_handles = {lease.lease_id}
    internal._trackers = {lease.lease_id: ()}
    internal._last_totals = {lease.lease_id: (0, 0)}
    internal._last_peer_totals = {lease.lease_id: {}}
    controller.credit_seed(lease)

    controller.maintain()
    counters = controller.counters(lease.digest)
    assert counters.uploaded_bytes == 10
    status = controller.status()
    assert status["transfers"][0]["peers"] == 1  # type: ignore[index]
    assert status["transfers"][0]["uploadRateBytesPerSecond"] == 7  # type: ignore[index]

    peers[0].total_upload += lease.size_bytes * 2
    totals["uploaded"] += lease.size_bytes * 2
    controller.reconcile(
        (lease,),
        _global_settings(internetSeedRatio=1.0),
        trackers={},
        closure_reason=None,
        apply_network_plan=lambda active, trackers: network_plans.append((active, trackers)),
    )
    assert controller.active is True
    assert controller.counters(lease.digest).uploaded_bytes == 10

    peers[1].total_upload = lease.size_bytes
    totals["uploaded"] += lease.size_bytes - 10
    controller.reconcile(
        (lease,),
        _global_settings(internetSeedRatio=1.0),
        trackers={},
        closure_reason=None,
        apply_network_plan=lambda active, trackers: network_plans.append((active, trackers)),
    )
    assert controller.active is False
    assert controller.status()["closureReason"] == "budget-exhausted"
    assert released == [handle]
    assert removed == []
    controller.close()


def test_global_accounting_charges_unattributed_upload_to_internet_budget(
    tmp_path: Path,
) -> None:
    lease = _seed_lease(tmp_path)
    peers = [_peer("198.51.100.20", uploaded=10)]
    handle = _AccountingHandle(peers, uploaded=10)
    controller = _accounting_controller(tmp_path, lease, handle, allows_lan_peer=lambda _: False)

    controller.maintain()
    peers.clear()
    handle.uploaded = 40
    controller.maintain()

    assert controller.counters(lease.digest).uploaded_bytes == 40
    controller.close()


def test_global_accounting_charges_only_lan_disconnect_residual_to_internet(
    tmp_path: Path,
) -> None:
    lease = _seed_lease(tmp_path)
    peers = [_peer("192.168.1.20", uploaded=100)]
    handle = _AccountingHandle(peers, uploaded=100)
    controller = _accounting_controller(
        tmp_path,
        lease,
        handle,
        allows_lan_peer=lambda address: address == "192.168.1.20",
    )

    controller.maintain()
    assert controller.counters(lease.digest).uploaded_bytes == 0
    peers[0].total_upload = 140
    handle.uploaded = 140
    peers.clear()
    controller.maintain()

    assert controller.counters(lease.digest).uploaded_bytes == 40
    controller.close()


@pytest.mark.parametrize(
    ("address", "expected_uploaded"),
    (("192.168.1.20", 0), ("198.51.100.20", 20)),
)
def test_global_accounting_treats_peer_total_drop_as_reconnect(
    tmp_path: Path,
    address: str,
    expected_uploaded: int,
) -> None:
    lease = _seed_lease(tmp_path)
    peer = _peer(address, uploaded=20)
    handle = _AccountingHandle([peer], uploaded=520)
    controller = _accounting_controller(
        tmp_path,
        lease,
        handle,
        allows_lan_peer=lambda value: value == "192.168.1.20",
    )
    internal = cast(Any, controller)
    key = (address, 6881, "peer")
    internal._last_totals[lease.lease_id] = (0, 500)
    internal._last_peer_totals[lease.lease_id] = {key: (address == "192.168.1.20", 0, 500)}

    controller.maintain()

    assert controller.counters(lease.digest).uploaded_bytes == expected_uploaded
    controller.close()


def test_global_accounting_treats_aggregate_total_drop_as_reset(tmp_path: Path) -> None:
    lease = _seed_lease(tmp_path)
    handle = _AccountingHandle([], uploaded=20)
    controller = _accounting_controller(tmp_path, lease, handle, allows_lan_peer=lambda _: False)
    cast(Any, controller)._last_totals[lease.lease_id] = (0, 500)

    controller.maintain()

    assert controller.counters(lease.digest).uploaded_bytes == 20
    controller.close()


def test_global_accounting_baselines_borrowed_handle_totals(tmp_path: Path) -> None:
    lease = _seed_lease(tmp_path)
    peer = _peer("192.168.1.20", uploaded=5000)
    handle = _AccountingHandle([peer], uploaded=5000)
    flags = SimpleNamespace(
        apply_ip_filter=1,
        disable_dht=2,
        disable_pex=4,
        override_trackers=8,
        override_web_seeds=16,
        seed_mode=32,
        upload_mode=64,
    )
    libtorrent = SimpleNamespace(
        add_torrent_params=SimpleNamespace,
        bdecode=lambda value: value,
        torrent_info=lambda value: value,
        torrent_flags=flags,
    )
    controller = GlobalTransferController(
        libtorrent,
        SimpleNamespace(remove_torrent=lambda _: None),
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        torrent_flags=lambda _: 0,
        shared_handle_for=lambda _: handle,
        release_shared_handle=lambda _lease, _handle: None,
        allows_lan_peer=lambda address: address == "192.168.1.20",
    )
    internal = cast(Any, controller)
    internal._handles = {lease.lease_id: internal._add(lease, ())}
    internal._leases = {lease.lease_id: lease}

    controller.maintain()

    assert controller.counters(lease.digest).uploaded_bytes == 0
    controller.close()


def test_global_accounting_brackets_aggregate_status_with_peer_samples(tmp_path: Path) -> None:
    lease = _seed_lease(tmp_path)
    handle = _AccountingHandle([])
    controller = _accounting_controller(tmp_path, lease, handle, allows_lan_peer=lambda _: False)

    controller.maintain()

    assert handle.calls[:3] == ["get_peer_info", "status", "get_peer_info"]
    controller.close()


def test_global_accounting_does_not_offset_post_reset_internet_bytes_with_lan_race(
    tmp_path: Path,
) -> None:
    lease = _seed_lease(tmp_path)
    lan_peer = _peer("192.168.1.20")

    class RacingHandle(_AccountingHandle):
        status_calls = 0

        def status(self) -> SimpleNamespace:
            self.status_calls += 1
            if self.status_calls == 1:
                lan_peer.total_upload = 100
                self.uploaded = 100
            else:
                self.uploaded = 200
            return super().status()

    handle = RacingHandle([lan_peer])
    controller = _accounting_controller(
        tmp_path,
        lease,
        handle,
        allows_lan_peer=lambda address: address == "192.168.1.20",
    )

    controller.maintain()
    baseline = controller.counters(lease.digest).uploaded_bytes
    controller.set_transfer_policy(
        lease.digest,
        enabled=True,
        continuous=False,
        uploaded_baseline=baseline,
        active_seed_seconds_baseline=0,
        resume_required=False,
    )
    controller.maintain()

    assert controller.counters(lease.digest).uploaded_bytes - baseline == 100
    controller.close()


def test_global_lease_status_keeps_native_verified_progress_distinct_from_durable_bytes(
    tmp_path: Path,
) -> None:
    fixture = build_provider_fixture(tmp_path, payload_size=2 * P2P_PIECE_LENGTH)
    lease = cast(
        DownloadLease,
        fixture.authorizations(local_seed=False, request_download=True)[0].lease,
    )
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        _grant_global(runtime, lease)
        controller = cast(Any, runtime)._global
        native = controller._handles[lease.lease_id]
        snapshot = SimpleNamespace(
            errc=native.status().errc,
            total_wanted_done=P2P_PIECE_LENGTH + 1024,
            pieces=[True, False, False],
            is_finished=False,
        )
        controller._handles[lease.lease_id] = SimpleNamespace(status=lambda: snapshot)
        try:
            progress = controller.lease_status(lease.lease_id)
            assert progress == {"state": "downloading", "verifiedBytes": P2P_PIECE_LENGTH}
            snapshot.pieces = [False, False, True]
            assert (
                controller.lease_status(lease.lease_id)["verifiedBytes"]
                == lease.size_bytes - 2 * P2P_PIECE_LENGTH
            )
            snapshot.pieces = [True, True, True]
            assert controller.lease_status(lease.lease_id)["verifiedBytes"] == lease.size_bytes
            snapshot.is_finished = True
            assert controller.lease_status(lease.lease_id)["state"] == "publishing"
            assert "path" not in controller.lease_status(lease.lease_id)
        finally:
            controller._handles[lease.lease_id] = native
    finally:
        runtime.close()


def test_global_lease_status_reports_adoption_error_and_policy_pause(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)
    lease = cast(
        DownloadLease,
        fixture.authorizations(local_seed=False, request_download=True)[0].lease,
    )
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        _grant_global(runtime, lease)
        runtime.pause_transfer({"digest": lease.digest})
        assert runtime.operate("lease-status", {"leaseId": lease.lease_id})["state"] == "paused"
        runtime.resume_transfer({"digest": lease.digest})
        assert (
            runtime.operate("lease-status", {"leaseId": lease.lease_id})["state"] == "downloading"
        )
        cast(Any, runtime)._global._publish_download(lease.lease_id)
        failed = runtime.operate("lease-status", {"leaseId": lease.lease_id})
        assert failed["state"] == "failed"
        assert failed["error"]
        assert failed["durableBytes"] == 0
        assert "path" not in failed
        assert not AssetVault(tmp_path / "vault").has(lease.digest)
    finally:
        runtime.close()


def test_global_download_stops_on_completion_without_seed_authority(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)
    lease = cast(
        DownloadLease,
        fixture.authorizations(local_seed=False, request_download=True)[0].lease,
    )
    controller = GlobalTransferController(
        cast(Any, object()),
        SimpleNamespace(remove_torrent=lambda _: None),
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        torrent_flags=lambda _: 0,
        shared_handle_for=lambda _: None,
        release_shared_handle=lambda _lease, _handle: None,
        allows_lan_peer=lambda _: False,
    )

    class FakeHandle:
        @staticmethod
        def status():
            return SimpleNamespace(
                all_time_download=lease.size_bytes,
                all_time_upload=0,
                is_finished=True,
                is_seeding=True,
            )

        @staticmethod
        def get_peer_info():
            return [_peer("198.51.100.1", downloaded=lease.size_bytes)]

    class FakeSession:
        removed: list[object] = []

        @classmethod
        def remove_torrent(cls, handle: object) -> None:
            cls.removed.append(handle)

    handle = FakeHandle()
    internal = cast(Any, controller)
    internal._session = FakeSession()
    internal._leases = {lease.lease_id: lease}
    internal._handles = {lease.lease_id: handle}
    internal._last_totals = {lease.lease_id: (0, 0)}
    internal._last_peer_totals = {lease.lease_id: {}}
    controller.maintain()

    assert FakeSession.removed == [handle]
    assert internal._handles == {}
    assert internal._completed_downloads == {lease.lease_id}
    assert controller.counters(lease.digest).downloaded_bytes == lease.size_bytes
    controller.close()


def test_completed_global_download_closes_shared_session_features(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)
    lease = cast(
        DownloadLease,
        fixture.authorizations(local_seed=False, request_download=True)[0].lease,
    )
    network_plans: list[tuple[bool, bool]] = []
    controller = GlobalTransferController(
        cast(Any, SimpleNamespace()),
        SimpleNamespace(remove_torrent=lambda _: None),
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        torrent_flags=lambda _: 0,
        shared_handle_for=lambda _: None,
        release_shared_handle=lambda _lease, _handle: None,
        allows_lan_peer=lambda _: False,
    )

    class FakeHandle:
        @staticmethod
        def status():
            return SimpleNamespace(
                all_time_download=lease.size_bytes,
                all_time_upload=0,
                is_finished=True,
                is_seeding=True,
            )

        @staticmethod
        def get_peer_info():
            return [_peer("198.51.100.1", downloaded=lease.size_bytes)]

    internal = cast(Any, controller)
    internal._leases = {lease.lease_id: lease}
    internal._handles = {lease.lease_id: FakeHandle()}
    internal._trackers = {lease.lease_id: ()}
    internal._last_totals = {lease.lease_id: (0, 0)}
    internal._last_peer_totals = {lease.lease_id: {}}
    internal._add = lambda *_args: pytest.fail("existing handle should be reused")

    controller.reconcile(
        (lease,),
        _global_settings(downloadsEnabled=True),
        trackers={},
        closure_reason=None,
        apply_network_plan=lambda active, trackers: network_plans.append((active, trackers)),
    )

    assert network_plans == [(True, False), (False, False)]
    assert controller.active is False
    controller.close()


def test_download_authority_can_transition_to_seed_authority(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)
    download = cast(
        DownloadLease,
        fixture.authorizations(local_seed=False, request_download=True)[0].lease,
    )
    seed = cast(SeedLease, fixture.authorizations()[0].lease)
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(downloadsEnabled=True),
    )
    try:
        _grant_global(runtime, download)
        runtime.revoke({"leaseId": download.lease_id})
        _grant_global(runtime, seed)

        status = runtime.status()
        assert status["global"]["active"] is True  # type: ignore[index]
        assert status["global"]["transfers"][0]["kind"] == "seed"  # type: ignore[index]
    finally:
        runtime.close()


def test_global_seed_borrows_and_returns_matching_lan_torrent(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)
    authorization = fixture.authorizations()[0]
    global_seed = cast(SeedLease, authorization.lease)
    lan_seed = replace(
        global_seed,
        lease_id="lan-seed-" + global_seed.digest.removeprefix("blake3:"),
        scope="lan-only",
    )
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        runtime.grant(lan_seed.to_wire(), "seed")
        lan_handle = cast(Any, runtime)._torrents[lan_seed.lease_id].handle
        _grant_global(runtime, global_seed, ("https://tracker.example/announce",))
        global_handle = cast(Any, runtime)._global._handles[global_seed.lease_id]

        assert global_handle == lan_handle
        assert [tracker["url"] for tracker in lan_handle.trackers()] == [
            "https://tracker.example/announce"
        ]
        assert len(cast(Any, runtime)._session.get_torrents()) == 1
        assert not (lan_handle.status().flags & cast(Any, runtime)._lt.torrent_flags.disable_dht)
        runtime.revoke({"leaseId": global_seed.lease_id})

        deadline = time.monotonic() + 5.0
        while True:
            runtime.poll_alerts()
            status = runtime.status()
            leases = cast("list[dict[str, object]]", status["leases"])
            lan_status = next(row for row in leases if row["leaseId"] == lan_seed.lease_id)
            if lan_status["state"] == "ready" or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        assert len(cast(Any, runtime)._session.get_torrents()) == 1
        assert lan_handle.is_valid()
        assert lan_handle.trackers() == []
        assert status["global"]["active"] is False  # type: ignore[index]
        assert status["networkFeatures"]["dht"] is False  # type: ignore[index]
        assert status["networkFeatures"]["lsd"] is True  # type: ignore[index]
        assert lan_status["state"] == "ready"
    finally:
        runtime.close()


def test_lan_seed_borrows_matching_global_torrent_and_survives_global_closure(
    tmp_path: Path,
) -> None:
    fixture = build_provider_fixture(tmp_path)
    authorization = fixture.authorizations()[0]
    global_seed = cast(SeedLease, authorization.lease)
    lan_seed = replace(
        global_seed,
        lease_id="lan-seed-" + global_seed.digest.removeprefix("blake3:"),
        scope="lan-only",
    )
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        _grant_global(runtime, global_seed)
        global_controller = cast(Any, runtime)._global
        handle = global_controller._handles[global_seed.lease_id]

        runtime.grant(lan_seed.to_wire(), "seed")

        assert cast(Any, runtime)._torrents[lan_seed.lease_id].handle == handle
        assert len(cast(Any, runtime)._session.get_torrents()) == 1
        runtime.configure(_global_settings(scope="lan-only"))

        assert handle.is_valid()
        assert not (handle.status().flags & cast(Any, runtime)._lt.torrent_flags.paused)
        assert handle.status().flags & cast(Any, runtime)._lt.torrent_flags.disable_dht
        assert handle.trackers() == []
    finally:
        runtime.close()


def test_network_pause_latches_until_resume_and_preserves_shared_handle(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)
    authorization = fixture.authorizations()[0]
    global_seed = cast(SeedLease, authorization.lease)
    lan_seed = replace(
        global_seed,
        lease_id="lan-seed-" + global_seed.digest.removeprefix("blake3:"),
        scope="lan-only",
    )
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        runtime.grant(lan_seed.to_wire(), "seed")
        _grant_global(runtime, global_seed)
        handle = cast(Any, runtime)._torrents[lan_seed.lease_id].handle

        paused = runtime.set_network_paused({"paused": True})

        assert handle.is_valid()
        assert handle.status().flags & cast(Any, runtime)._lt.torrent_flags.paused
        assert handle.status().flags & cast(Any, runtime)._lt.torrent_flags.disable_dht
        assert paused["global"]["active"] is False  # type: ignore[index]
        assert paused["networkFeatures"]["lsd"] is False  # type: ignore[index]

        unpaused = runtime.set_network_paused({"paused": False})
        assert unpaused["global"]["active"] is False  # type: ignore[index]
        assert unpaused["global"]["closureReason"] == "resume-required"  # type: ignore[index]
        assert handle.is_valid()

        resumed = runtime.resume_transfer({"digest": global_seed.digest})
        assert resumed["resumed"] is True
        assert runtime.status()["global"]["active"] is True  # type: ignore[index]
        assert not (handle.status().flags & cast(Any, runtime)._lt.torrent_flags.disable_dht)

        with GlobalP2PCounterStore(tmp_path / "state" / "global-counters.sqlite") as counters:
            counters.record_transfer(global_seed.digest, uploaded_bytes=global_seed.size_bytes)
        runtime.maintain()
        budget_closed = runtime.status()
        assert budget_closed["global"]["active"] is False  # type: ignore[index]
        assert budget_closed["global"]["closureReason"] == "budget-exhausted"  # type: ignore[index]
        assert budget_closed["networkFeatures"]["lsd"] is True  # type: ignore[index]
        assert handle.is_valid()
        assert not (handle.status().flags & cast(Any, runtime)._lt.torrent_flags.paused)
    finally:
        runtime.close()


def test_network_pause_latch_survives_sidecar_restart(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)
    lease = cast(SeedLease, fixture.authorizations()[0].lease)
    state_root = tmp_path / "state"
    settings = _global_settings()
    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    _grant_global(runtime, lease)
    runtime.set_network_paused({"paused": True})
    runtime.close()

    restored = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    try:
        _grant_global(restored, lease)

        status = restored.status()
        assert status["global"]["active"] is False  # type: ignore[index]
        assert status["global"]["closureReason"] == "resume-required"  # type: ignore[index]

        restored.resume_transfer({"digest": lease.digest})
        assert restored.status()["global"]["active"] is True  # type: ignore[index]
    finally:
        restored.close()


def test_shared_torrent_closes_when_all_enabled_authority_is_removed(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)
    authorization = fixture.authorizations()[0]
    global_seed = cast(SeedLease, authorization.lease)
    lan_seed = replace(
        global_seed,
        lease_id="lan-seed-" + global_seed.digest.removeprefix("blake3:"),
        scope="lan-only",
    )
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        runtime.grant(lan_seed.to_wire(), "seed")
        _grant_global(runtime, global_seed)
        handle = cast(Any, runtime)._torrents[lan_seed.lease_id].handle

        runtime.revoke({"leaseId": lan_seed.lease_id})
        runtime.configure(_global_settings(scope="lan-only"))

        assert not handle.is_valid()
        assert cast(Any, runtime)._session.get_torrents() == []
        assert runtime.status()["global"]["active"] is False  # type: ignore[index]
    finally:
        runtime.close()


def test_global_revocation_closes_before_completed_bytes_are_published(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)
    lease = cast(
        DownloadLease,
        fixture.authorizations(local_seed=False, request_download=True)[0].lease,
    )
    controller = GlobalTransferController(
        cast(Any, object()),
        SimpleNamespace(remove_torrent=lambda _: None),
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        torrent_flags=lambda _: 0,
        shared_handle_for=lambda _: None,
        release_shared_handle=lambda _lease, _handle: None,
        allows_lan_peer=lambda _: False,
    )

    class FakeHandle:
        @staticmethod
        def status():
            return SimpleNamespace(
                all_time_download=lease.size_bytes,
                all_time_upload=0,
                is_finished=True,
                is_seeding=True,
            )

        @staticmethod
        def get_peer_info():
            return [_peer("198.51.100.1", downloaded=lease.size_bytes)]

    class FakeSession:
        @staticmethod
        def remove_torrent(_: object) -> None:
            pass

        @staticmethod
        def pause() -> None:
            pass

        @staticmethod
        def apply_settings(_: object) -> None:
            pass

        @staticmethod
        def get_torrents() -> list[object]:
            return []

    internal = cast(Any, controller)
    internal._session = FakeSession()
    internal._leases = {lease.lease_id: lease}
    internal._handles = {lease.lease_id: FakeHandle()}
    internal._last_totals = {lease.lease_id: (0, 0)}
    internal._last_peer_totals = {lease.lease_id: {}}
    internal._publish_download = lambda _: pytest.fail("revocation attempted publication")

    controller.reconcile(
        (),
        _global_settings(downloadsEnabled=True),
        trackers={},
        closure_reason=None,
        apply_network_plan=lambda _active, _trackers: None,
    )

    assert controller.active is False
    assert controller.counters(lease.digest).downloaded_bytes == lease.size_bytes
    controller.close()


def test_manager_applies_network_pause_over_private_ipc(tmp_path: Path) -> None:
    async def scenario() -> None:
        fixture = build_provider_fixture(tmp_path)
        authorization = fixture.authorizations()[0]
        lease = cast(SeedLease, authorization.lease)
        manager = P2PSidecarManager(vault_root=tmp_path / "vault")
        await manager.start(_global_settings())
        try:
            with pytest.raises(P2PManagerError, match="trusted provider authority"):
                await manager.grant_seed(lease)
            with pytest.raises(P2PManagerError, match="lacks trusted provider authority"):
                await manager.grant_global(cast(Any, SimpleNamespace(lease=lease)))
            await manager.grant_global(authorization)
            running = await manager.status()
            assert running["sidecar"]["global"]["active"] is True  # type: ignore[index]
            await manager.set_network_paused(True)
            paused = await manager.status()
            assert paused["sidecar"]["global"]["active"] is False  # type: ignore[index]
            assert paused["sidecar"]["state"] == "paused"  # type: ignore[index]
        finally:
            await manager.close()

    asyncio.run(scenario())


def test_global_network_policy_commands_are_closed_and_validated(tmp_path: Path) -> None:
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=_global_settings(),
    )
    try:
        invalid = (
            ({"cost": "metered"}, "exactly cost and paused"),
            ({"cost": "wifi", "paused": False}, "network cost is invalid"),
            ({"cost": "metered", "paused": 1}, "pause must be a boolean"),
            ({"cost": "unmetered", "paused": True}, "cannot be paused"),
        )
        for body, message in invalid:
            with pytest.raises(SidecarError, match=message):
                runtime.set_global_network_policy(body)
    finally:
        runtime.close()

    async def manager_scenario() -> None:
        manager = P2PSidecarManager(vault_root=tmp_path / "manager-vault")
        with pytest.raises(P2PManagerError, match="network cost is invalid"):
            await manager.set_global_network_policy("wifi", False)
        with pytest.raises(P2PManagerError, match="cannot be paused"):
            await manager.set_global_network_policy("unmetered", True)

        internal = cast(Any, manager)
        internal._process = object()
        discarded: list[bool] = []
        failures: list[str] = []

        async def reject_policy(_operation: str, _body: object) -> dict[str, object]:
            raise ConnectionError("policy response was lost")

        async def discard() -> None:
            discarded.append(True)
            internal._process = None

        internal._request_locked = reject_policy
        internal._discard_process_locked = discard
        internal._record_failure_locked = failures.append
        with pytest.raises(P2PManagerError, match="response was lost"):
            await manager.set_global_network_policy("metered", True)
        assert manager.global_network_policy == ("unknown", False)
        assert discarded == [True]
        assert failures == ["policy response was lost"]

    asyncio.run(manager_scenario())


def test_only_an_exact_seed_grant_can_mint_a_global_seed_lease(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)
    mismatched = replace(fixture.grants.seed_grants[0], evidence_id="other-enumeration")
    grants = P2PGrantSnapshot(True, fixture.grants.public_grants, (mismatched,))

    authorizations = authorized_global_leases(
        fixture.snapshot,
        grants,
        trusted_provider_ids=TRUSTED_PROVIDER_IDS,
        requested_download_digests=frozenset({fixture.descriptor.asset_digest}),
        now=fixture.observed_at,
        local_path_for=lambda _: fixture.source,
    )

    assert len(authorizations) == 1
    assert isinstance(authorizations[0].lease, DownloadLease)


def test_provider_catalog_does_not_mint_unrequested_download_leases(tmp_path: Path) -> None:
    fixture = build_provider_fixture(tmp_path)

    assert fixture.authorizations(local_seed=False) == ()
    requested = fixture.authorizations(local_seed=False, request_download=True)
    assert len(requested) == 1
    assert isinstance(requested[0].lease, DownloadLease)


def test_ambiguous_global_authority_failures_discard_the_sidecar(tmp_path: Path) -> None:
    async def scenario() -> None:
        fixture = build_provider_fixture(tmp_path)
        authorization = fixture.authorizations()[0]
        manager = P2PSidecarManager(vault_root=tmp_path / "vault")
        internal = cast(Any, manager)
        discarded: list[bool] = []
        failures: list[str] = []

        async def ambiguous_request(_: str, __: object) -> dict[str, Any]:
            raise ConnectionError("global grant response was lost")

        async def discard() -> None:
            discarded.append(True)
            internal._process = None
            internal._global_authorizations.clear()

        internal._request_locked = ambiguous_request
        internal._discard_process_locked = discard
        internal._record_failure_locked = failures.append
        internal._process = object()

        with pytest.raises(P2PManagerError, match="response was lost"):
            await manager.grant_global(authorization)

        internal._process = object()
        internal._global_authorizations = {authorization.lease.lease_id: authorization}
        with pytest.raises(P2PManagerError, match="response was lost"):
            await manager.reconcile_global(())

        assert discarded == [True, True]
        assert failures == ["global grant response was lost"] * 2
        assert internal._global_authorizations == {}

    asyncio.run(scenario())


def test_provider_trackers_and_tombstone_control_the_live_global_lease(tmp_path: Path) -> None:
    async def scenario() -> None:
        tracker = "https://tracker.example/announce"
        fixture = build_provider_fixture(tmp_path, trackers=(tracker,))
        authorizations = fixture.authorizations()
        assert len(authorizations) == 1
        authorization = authorizations[0]
        lease = cast(SeedLease, authorization.lease)
        assert authorization.trackers == (tracker,)
        assert "trackers" not in lease.to_wire()
        assert lease.expires_at <= fixture.observed_at + MAX_GLOBAL_LEASE_SECONDS

        manager = P2PSidecarManager(vault_root=tmp_path / "vault")
        await manager.start(_global_settings())
        try:
            granted = await manager.reconcile_global(authorizations)
            assert granted == {"granted": (lease.lease_id,), "revoked": ()}
            active = await manager.status()
            assert active["sidecar"]["global"]["active"] is True  # type: ignore[index]
            assert active["sidecar"]["networkFeatures"]["trackers"] is True  # type: ignore[index]

            tombstoned = fixture.tombstoned()
            current = authorized_global_leases(
                tombstoned,
                fixture.grants,
                trusted_provider_ids=TRUSTED_PROVIDER_IDS,
                requested_download_digests=frozenset(),
                now=fixture.observed_at,
                local_path_for=lambda _: fixture.source,
            )
            assert current == ()
            revoked = await manager.reconcile_global(current)
            assert revoked == {"granted": (), "revoked": (lease.lease_id,)}
            closed = await manager.status()
            assert closed["sidecar"]["global"]["active"] is False  # type: ignore[index]
            assert closed["state"] == "running"
        finally:
            await manager.close()

    asyncio.run(scenario())
