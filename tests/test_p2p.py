"""Host-managed libtorrent sidecar contracts and lifecycle."""

from __future__ import annotations

import asyncio
import json
import socket
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import replace
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast

import pytest
from dinkster_assets import AssetVault, derive_p2p_descriptor
from dinkster_workers.boundary import read_frame as read_boundary_frame

from dinkster_p2p import (
    LIBTORRENT_ARTIFACTS,
    DownloadLease,
    LanInterface,
    LanNetworkPolicy,
    P2PLeaseError,
    P2PManagerConflict,
    P2PManagerError,
    P2PSidecarManager,
    SeedLease,
    UnsupportedLibtorrentRuntime,
    default_p2p_settings,
    download_lease_from_wire,
    normalize_p2p_settings,
    seed_lease_from_wire,
    select_libtorrent_artifact,
)
from dinkster_p2p import manager as p2p_manager
from dinkster_p2p import runtime as p2p_runtime
from dinkster_p2p.global_leases import _AUTHORITY, AuthorizedGlobalLease
from dinkster_p2p.runtime import (
    SidecarError,
    SidecarRuntime,
    StateLock,
    StateLockError,
)
from tests.p2p_global_fixtures import build_provider_fixture

SEED_GRANT_ID = "a" * 64
INTERNET_SEED_GRANT_ID = "b" * 64


def test_sidecar_startup_and_operations_use_four_hour_bounds() -> None:
    assert p2p_manager._CONNECT_TIMEOUT_SECONDS == 4 * 60 * 60
    assert p2p_manager._REQUEST_TIMEOUT_SECONDS == 4 * 60 * 60


def test_global_seed_expiry_renewal_does_not_revoke(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        fixture = build_provider_fixture(tmp_path / "fixture")
        current = fixture.authorizations()[0]
        later = fixture.observed_at + 60
        monkeypatch.setattr("dinkster_p2p.global_leases.time.time", lambda: later)
        renewed = AuthorizedGlobalLease(
            replace(current.lease, expires_at=current.lease.expires_at + 60),
            current.trackers,
            _AUTHORITY,
        )
        manager = P2PSidecarManager(vault_root=tmp_path / "vault")
        internal = cast(Any, manager)
        operations: list[str] = []

        async def request(operation: str, _body: object) -> dict[str, Any]:
            operations.append(operation)
            return {}

        internal._process = object()
        internal._request_with_recovery_locked = request
        await manager.reconcile_global((current,))
        operations.clear()

        result = await manager.reconcile_global((renewed,))

        assert result == {"granted": (renewed.lease.lease_id,), "revoked": ()}
        assert operations == ["grant-global"]
        assert internal._global_authorizations == {renewed.lease.lease_id: renewed}

    asyncio.run(scenario())


def enabled_settings(*, downloads: bool = False, seeding: bool = False) -> dict[str, object]:
    return {
        **default_p2p_settings(),
        "downloadsEnabled": downloads,
        "seedingEnabled": seeding,
    }


async def wait_for(
    sample: Callable[[], Awaitable[Any]],
    predicate: Callable[[Any], bool],
    *,
    timeout: float = 5.0,
) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = await sample()
        if predicate(value):
            return value
        await asyncio.sleep(0.025)
    raise AssertionError("condition did not become true before timeout")


def test_p2p_defaults_disable_transport_with_budgets() -> None:
    assert default_p2p_settings() == {
        "downloadsEnabled": False,
        "seedingEnabled": False,
        "scope": "lan-and-internet",
        "internetUploadBytesPerSecond": 5_242_880,
        "internetDownloadBytesPerSecond": 0,
        "lanUploadBytesPerSecond": 0,
        "lanDownloadBytesPerSecond": 0,
        "pauseOnMetered": True,
        "networkCostOverride": "auto",
        "seedMode": "budgeted",
        "internetSeedRatio": 1.0,
        "internetSeedTimeSeconds": 86_400,
        "stagingBudgetBytes": 64 * 1024**3,
        "maxActiveSeeds": 64,
        "listenPort": 0,
    }
    assert len(LIBTORRENT_ARTIFACTS) == 8
    assert {key[0] for key in LIBTORRENT_ARTIFACTS} == {"linux", "win32", "darwin"}
    assert {key[2] for key in LIBTORRENT_ARTIFACTS} == {(3, 12), (3, 13)}
    with pytest.raises(UnsupportedLibtorrentRuntime, match="no approved artifact"):
        select_libtorrent_artifact(sys_platform="win32", machine="arm64", python_version=(3, 13))
    with pytest.raises(ValueError, match="exactly"):
        normalize_p2p_settings({**default_p2p_settings(), "dhtEnabled": True})
    with pytest.raises(ValueError, match="0 through 2147483647"):
        normalize_p2p_settings({**default_p2p_settings(), "internetUploadBytesPerSecond": 2**31})


@pytest.mark.parametrize("budget", [-1, True, 1.5, 2**53])
def test_p2p_staging_budget_requires_nonnegative_safe_integer(budget: object) -> None:
    with pytest.raises(ValueError, match="safe integer"):
        normalize_p2p_settings({**default_p2p_settings(), "stagingBudgetBytes": budget})


def test_legacy_p2p_settings_preserve_opt_out_and_add_disk_budget() -> None:
    legacy = {**enabled_settings(), "scope": "lan-only"}
    legacy.pop("stagingBudgetBytes")
    normalized = normalize_p2p_settings(legacy)
    assert normalized == {**legacy, "stagingBudgetBytes": 64 * 1024**3}
    assert (
        normalize_p2p_settings({**normalized, "stagingBudgetBytes": 0})["stagingBudgetBytes"] == 0
    )


def lease_fixtures(tmp_path: Path) -> tuple[DownloadLease, SeedLease]:
    download_source = tmp_path / "download.bin"
    download_source.write_bytes(b"download fixture")
    download_derived = derive_p2p_descriptor(download_source)
    seed_source = download_source
    seed_derived = download_derived
    expires_at = time.time() + 60
    common = {
        "version": 1,
        "scope": "lan-only",
        "expiresAt": expires_at,
    }
    download = download_lease_from_wire(
        {
            **common,
            "kind": "download",
            "leaseId": "download-fixture",
            "digest": download_derived.asset_digest,
            "sizeBytes": download_derived.size,
            "descriptor": download_derived.descriptor.to_wire(),
            "stagingPath": (
                f"{download_derived.descriptor.info_hash}/"
                f"{download_derived.asset_digest.removeprefix('blake3:')}"
            ),
        }
    )
    seed = seed_lease_from_wire(
        {
            **common,
            "kind": "seed",
            "leaseId": "seed-fixture",
            "digest": seed_derived.asset_digest,
            "sizeBytes": seed_derived.size,
            "descriptor": seed_derived.descriptor.to_wire(),
            "grantIds": [SEED_GRANT_ID],
            "localPath": str(seed_source.resolve()),
        }
    )
    return download, seed


@pytest.mark.parametrize("pending_state", ["flush", "read"])
def test_delayed_sparse_hash_failure_does_not_fail_a_pending_piece(
    tmp_path: Path, pending_state: str
) -> None:
    download, _seed = lease_fixtures(tmp_path)

    class Handle:
        def __init__(self) -> None:
            self.flushes = 0
            self.reads: list[int] = []

        def status(self) -> Any:
            return SimpleNamespace(total_failed_bytes=0)

        def flush_cache(self) -> None:
            self.flushes += 1

        def read_piece(self, piece: int) -> None:
            self.reads.append(piece)

        def is_valid(self) -> bool:
            return True

    handle = Handle()
    partial = AssetVault(tmp_path / "vault").open_p2p_partial(
        download.descriptor, download.digest, download.size_bytes
    )
    torrent = p2p_runtime._TorrentRuntime(download, handle, partial, state="downloading")

    class IgnoredAlert:
        pass

    class PieceFinishedAlert:
        def __init__(self) -> None:
            self.handle = handle
            self.piece_index = 0

    class HashFailedAlert:
        def __init__(self) -> None:
            self.handle = handle
            self.piece_index = 0

        def message(self) -> str:
            return "hash for piece 0 failed"

    class CacheFlushedAlert:
        def __init__(self) -> None:
            self.handle = handle

    class FakeLibtorrent:
        listen_succeeded_alert = IgnoredAlert
        listen_failed_alert = IgnoredAlert
        metadata_failed_alert = IgnoredAlert
        torrent_error_alert = IgnoredAlert
        file_error_alert = IgnoredAlert
        hash_failed_alert = HashFailedAlert
        metadata_received_alert = IgnoredAlert
        torrent_checked_alert = IgnoredAlert
        piece_finished_alert = PieceFinishedAlert
        cache_flushed_alert = CacheFlushedAlert
        read_piece_alert = IgnoredAlert

    removed: list[object] = []
    runtime = object.__new__(SidecarRuntime)
    runtime._diagnostics = p2p_runtime.NativeDiagnostics()
    runtime._lt = FakeLibtorrent()
    runtime._session = SimpleNamespace(remove_torrent=removed.append)
    runtime._torrents = {download.lease_id: torrent}

    runtime._handle_alert(PieceFinishedAlert())
    assert torrent.pending_flush == {0}
    assert handle.flushes == 1
    if pending_state == "read":
        runtime._handle_alert(CacheFlushedAlert())
        assert torrent.pending_flush == set()
        assert torrent.pending_reads == {0}
        assert handle.reads == [0]

    runtime._handle_alert(HashFailedAlert())

    assert torrent.state == "downloading"
    assert torrent.error is None
    assert not torrent.stopped
    assert removed == []

    partial.write_piece(0, (tmp_path / "download.bin").read_bytes())
    runtime._handle_alert(HashFailedAlert())

    assert torrent.state == "failed"
    assert torrent.error == "hash for piece 0 failed"
    assert torrent.stopped
    assert removed == [handle]


def test_restored_seed_renews_authority_without_rebinding_bytes(tmp_path: Path) -> None:
    _download, seed = lease_fixtures(tmp_path)
    arguments = {
        "state_root": tmp_path / "vault" / ".p2p",
        "vault_root": tmp_path / "vault",
        "installation_root": None,
        "settings": enabled_settings(seeding=True),
    }
    original = SidecarRuntime(**arguments)
    try:
        original.grant(seed.to_wire(), "seed")
    finally:
        original.close()

    restored = SidecarRuntime(**arguments)
    renewed = replace(
        seed,
        grant_ids=(INTERNET_SEED_GRANT_ID,),
        expires_at=seed.expires_at + 60,
    )
    try:
        restored.grant(renewed.to_wire(), "seed")
        assert restored._leases[seed.lease_id] == renewed  # noqa: SLF001
        runtime = restored._torrent_for_digest(seed.digest)  # noqa: SLF001
        assert runtime is not None and runtime.lease == renewed
        with pytest.raises(SidecarError, match="different lease"):
            restored.grant(replace(renewed, local_path=tmp_path / "other").to_wire(), "seed")
    finally:
        restored.close()


def test_lease_contracts_are_closed_and_confine_download_staging(tmp_path: Path) -> None:
    download, seed = lease_fixtures(tmp_path)
    assert download_lease_from_wire(download.to_wire()) == download
    assert seed_lease_from_wire(seed.to_wire()) == seed
    hinted = replace(
        download,
        version=2,
        peer_address="192.168.70.44",
        peer_port=51413,
    )
    assert download_lease_from_wire(hinted.to_wire()) == hinted
    assert hinted.to_wire()["peerEndpoint"] == {
        "address": "192.168.70.44",
        "port": 51413,
    }
    with pytest.raises(P2PLeaseError, match="version 1.*peer hint"):
        replace(download, peer_address="192.168.70.44", peer_port=51413)
    with pytest.raises(P2PLeaseError, match="version 2.*peer hint"):
        replace(download, version=2)
    with pytest.raises(P2PLeaseError, match="canonical IPv4"):
        replace(download, version=2, peer_address="192.168.070.44", peer_port=51413)
    with pytest.raises(P2PLeaseError, match="LAN-only"):
        replace(
            download,
            version=2,
            peer_address="192.168.70.44",
            peer_port=51413,
            scope="lan-and-internet",
        )
    with pytest.raises(P2PLeaseError, match="fields must be exactly"):
        download_lease_from_wire({**download.to_wire(), "tracker": "unexpected"})
    with pytest.raises(P2PLeaseError, match="confined relative"):
        download_lease_from_wire({**download.to_wire(), "stagingPath": "../outside"})
    with pytest.raises(P2PLeaseError, match="confined relative"):
        download_lease_from_wire({**download.to_wire(), "stagingPath": "part\\outside"})
    with pytest.raises(P2PLeaseError, match="descriptor"):
        download_lease_from_wire(
            {
                **download.to_wire(),
                "descriptor": {**download.descriptor.to_wire(), "infoHash": "0" * 64},
            }
        )


def test_sidecar_samples_live_transport_activity_and_restores_counters(tmp_path: Path) -> None:
    download, seed = lease_fixtures(tmp_path)
    settings = enabled_settings(downloads=True, seeding=True)
    state_root = tmp_path / "vault" / ".p2p"
    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    runtime.grant(download.to_wire(), "download")
    runtime.grant(seed.to_wire(), "seed")
    sample = SimpleNamespace(
        info_hashes=SimpleNamespace(
            v2=download.descriptor.info_hash,
            has_v2=lambda: True,
        ),
        all_time_download=5,
        all_time_upload=1,
        is_seeding=False,
        is_finished=False,
        flags=runtime._lt.torrent_flags.auto_managed,  # noqa: SLF001
        state=runtime._lt.torrent_status.downloading,  # noqa: SLF001
        num_peers=2,
        download_payload_rate=4,
        upload_payload_rate=3,
    )
    real_session = runtime._session  # noqa: SLF001
    handle_actions: list[str] = []
    handle = SimpleNamespace(
        status=lambda: sample,
        info_hashes=lambda: sample.info_hashes,
        unset_flags=lambda _flags: None,
        pause=lambda: handle_actions.append("pause"),
        resume=lambda: handle_actions.append("resume"),
    )
    session = SimpleNamespace(
        get_torrents=lambda: [handle],
        save_state=real_session.save_state,
        apply_settings=real_session.apply_settings,
        set_ip_filter=real_session.set_ip_filter,
        pause=real_session.pause,
        resume=real_session.resume,
    )
    runtime._session = session  # noqa: SLF001
    try:
        assert runtime._sync_activity(now=10.0) is True  # noqa: SLF001
        record = runtime._activity[download.digest]  # noqa: SLF001
        transfer = runtime._transfer_status(record)  # noqa: SLF001
        assert transfer["state"] == "downloading"
        assert transfer["peers"] == 2
        assert transfer["downloadRateBytesPerSecond"] == 4
        assert transfer["uploadRateBytesPerSecond"] == 3
        assert transfer["downloadedBytes"] == 5
        assert transfer["uploadedBytes"] == 1

        runtime.pause_transfer({"digest": download.digest})
        transfer = runtime._transfer_status(record)  # noqa: SLF001
        assert handle_actions == ["pause"]
        assert transfer["state"] == "paused"
        assert transfer["peers"] == 0
        assert transfer["downloadRateBytesPerSecond"] == 0
        assert transfer["uploadRateBytesPerSecond"] == 0
        runtime.resume_transfer({"digest": download.digest})
        assert handle_actions == ["pause", "resume"]
        assert runtime._transfer_status(record)["state"] == "downloading"  # noqa: SLF001
        runtime.stop_transfer({"digest": download.digest})
        assert handle_actions == ["pause", "resume", "pause"]
        assert runtime._transfer_status(record)["state"] == "stopped"  # noqa: SLF001
        runtime.resume_transfer({"digest": download.digest})
        assert handle_actions == ["pause", "resume", "pause", "resume"]

        runtime.settings = enabled_settings(downloads=True)
        assert runtime._transfer_status(record)["uploadRateBytesPerSecond"] == 3  # noqa: SLF001
        runtime.settings = settings

        sample.all_time_download = 7
        sample.all_time_upload = 2
        sample.is_seeding = True
        sample.state = runtime._lt.torrent_status.seeding  # noqa: SLF001
        assert runtime._sync_activity(now=11.0) is True  # noqa: SLF001
        assert runtime._sync_activity(now=14.0) is False  # noqa: SLF001
        transfer = runtime._transfer_status(record)  # noqa: SLF001
        assert transfer["state"] == "seeding"
        assert transfer["downloadedBytes"] == 7
        assert transfer["uploadedBytes"] == 2
        assert transfer["remainingSeedTimeSeconds"] is None

        runtime.settings = enabled_settings(downloads=True)
        assert runtime._transfer_status(record)["uploadRateBytesPerSecond"] == 0  # noqa: SLF001
        runtime.settings = settings

        sample.all_time_download = 2
        assert runtime._sync_activity(now=15.0) is True  # noqa: SLF001
        assert record.downloaded_bytes == 7
    finally:
        runtime._session = real_session  # noqa: SLF001
        runtime.save_state()
        runtime.close()

    restored = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    try:
        status = restored.status()
        assert status["totals"] == {"downloadedBytes": 7, "uploadedBytes": 2}
        assert status["transfers"][0]["remainingSeedTimeSeconds"] is None  # type: ignore[index]
    finally:
        restored.close()


def test_sidecar_enforces_authorization_without_applying_internet_budgets_to_lan_handles(
    tmp_path: Path,
) -> None:
    download, seed = lease_fixtures(tmp_path)
    settings = enabled_settings(downloads=True, seeding=True)
    runtime = SidecarRuntime(
        state_root=tmp_path / "vault" / ".p2p",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    runtime.grant(download.to_wire(), "download")
    runtime.grant(seed.to_wire(), "seed")
    sample = SimpleNamespace(
        info_hashes=SimpleNamespace(
            v2=download.descriptor.info_hash,
            has_v2=lambda: True,
        ),
        all_time_download=0,
        all_time_upload=1,
        is_seeding=True,
        is_finished=True,
        flags=runtime._lt.torrent_flags.auto_managed,  # noqa: SLF001
        state=runtime._lt.torrent_status.seeding,  # noqa: SLF001
        num_peers=1,
        download_payload_rate=0,
        upload_payload_rate=3,
    )
    pause_calls = 0
    auto_managed_unsets = 0

    class Handle:
        def status(self) -> Any:
            return sample

        def info_hashes(self) -> Any:
            return sample.info_hashes

        def pause(self) -> None:
            nonlocal pause_calls
            pause_calls += 1
            sample.flags |= runtime._lt.torrent_flags.paused  # noqa: SLF001

        def resume(self) -> None:
            sample.flags &= ~runtime._lt.torrent_flags.paused  # noqa: SLF001

        def unset_flags(self, flags: int) -> None:
            nonlocal auto_managed_unsets
            assert flags == runtime._lt.torrent_flags.auto_managed  # noqa: SLF001
            auto_managed_unsets += 1
            sample.flags &= ~flags

        def trackers(self) -> list[object]:
            return []

        def is_valid(self) -> bool:
            return True

        def flags(self) -> int:
            return sample.flags

    handle = Handle()
    real_session = runtime._session  # noqa: SLF001

    class SessionProxy:
        def get_torrents(self) -> list[Handle]:
            return [handle]

        def __getattr__(self, name: str) -> Any:
            return getattr(real_session, name)

    runtime._session = SessionProxy()  # noqa: SLF001
    try:
        runtime.settings = {**settings, "internetSeedRatio": 0.05}
        assert runtime._sync_activity(now=1.0) is True  # noqa: SLF001
        transfer = runtime._transfer_status(runtime._activity[download.digest])  # noqa: SLF001
        assert pause_calls == 0
        assert transfer["state"] == "seeding"
        assert transfer["uploadRateBytesPerSecond"] == 3
        assert transfer["remainingSeedRatio"] is None
        assert auto_managed_unsets == 0
        runtime._sync_activity(now=2.0)  # noqa: SLF001
        assert pause_calls == 0
        assert (
            runtime._transfer_status(runtime._activity[download.digest])[  # noqa: SLF001
                "state"
            ]
            == "seeding"
        )

        runtime.settings = {
            **settings,
            "internetSeedRatio": 100.0,
            "internetSeedTimeSeconds": 2,
        }
        runtime._sync_activity(now=10.0)  # noqa: SLF001
        runtime._sync_activity(now=12.0)  # noqa: SLF001
        transfer = runtime._transfer_status(runtime._activity[download.digest])  # noqa: SLF001
        assert pause_calls == 0
        assert transfer["state"] == "seeding"
        assert transfer["remainingSeedTimeSeconds"] is None
        runtime._sync_activity(now=13.0)  # noqa: SLF001
        runtime.resume_transfer({"digest": download.digest})
        runtime._sync_activity(now=100.0)  # noqa: SLF001
        assert pause_calls == 0

        runtime.configure(enabled_settings(downloads=True))
        transfer = runtime._transfer_status(runtime._activity[download.digest])  # noqa: SLF001
        assert pause_calls == 1
        assert transfer["state"] == "complete"
        assert transfer["uploadRateBytesPerSecond"] == 0
        runtime._sync_activity()  # noqa: SLF001
        assert (
            runtime._transfer_status(runtime._activity[download.digest])[  # noqa: SLF001
                "state"
            ]
            == "complete"
        )

        sample.is_seeding = False
        sample.is_finished = False
        sample.state = runtime._lt.torrent_status.downloading  # noqa: SLF001
        runtime.resume_transfer({"digest": download.digest})
        runtime._leases[download.lease_id] = replace(  # noqa: SLF001
            download,
            expires_at=time.time() - 1,
        )
        runtime._sync_activity()  # noqa: SLF001
        assert pause_calls == 2
        runtime._sync_activity()  # noqa: SLF001
        assert (
            runtime._transfer_status(runtime._activity[download.digest])[  # noqa: SLF001
                "state"
            ]
            == "stopped"
        )

        runtime._leases[download.lease_id] = replace(  # noqa: SLF001
            download,
            expires_at=time.time() + 60,
        )
        runtime.settings = settings
        sample.is_seeding = True
        sample.is_finished = True
        sample.state = runtime._lt.torrent_status.seeding  # noqa: SLF001
        runtime.resume_transfer({"digest": download.digest})
        runtime.revoke({"leaseId": seed.lease_id})
        assert pause_calls == 3
        assert (
            runtime._transfer_status(runtime._activity[download.digest])[  # noqa: SLF001
                "state"
            ]
            == "complete"
        )
        runtime.revoke({"leaseId": download.lease_id})
        assert pause_calls == 3
        assert auto_managed_unsets == 1
    finally:
        runtime._session = real_session  # noqa: SLF001
        runtime.close()


def test_sidecar_activity_sampler_wakes_for_libtorrent_alerts() -> None:
    async def scenario() -> None:
        sampled = asyncio.Event()

        class Session:
            notify_fd = -1
            popped = 0

            def set_alert_fd(self, notify_fd: int) -> None:
                self.notify_fd = notify_fd

            def notify(self) -> None:
                sender = socket.socket(fileno=self.notify_fd)
                try:
                    sender.send(b"\0")
                finally:
                    sender.detach()

            def pop_alerts(self) -> list[object]:
                self.popped += 1
                return []

        class Runtime:
            def __init__(self) -> None:
                self._session = Session()

            def sample_activity(self) -> None:
                sampled.set()

        runtime = Runtime()
        task = asyncio.create_task(SidecarRuntime.sample_activity_loop(cast(Any, runtime)))
        try:
            await asyncio.sleep(0)
            assert runtime._session.notify_fd >= 0
            runtime._session.notify()
            await asyncio.wait_for(sampled.wait(), timeout=0.1)
            assert runtime._session.popped == 1
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert runtime._session.notify_fd == -1

    asyncio.run(scenario())


@pytest.mark.parametrize("state_version", [1, 2, 3])
def test_legacy_activity_state_migrates_without_quarantine(
    tmp_path: Path, state_version: int
) -> None:
    download, seed = lease_fixtures(tmp_path)
    settings = enabled_settings(downloads=True, seeding=True)
    state_root = tmp_path / "vault" / ".p2p"
    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    try:
        runtime.grant(download.to_wire(), "download")
        runtime.grant(seed.to_wire(), "seed")
        record = runtime._activity[download.digest]  # noqa: SLF001
        record.downloaded_bytes = 6
        record.uploaded_bytes = 4
        record.transport_download_sample = 6
        record.transport_upload_sample = 4
        record.seed_uploaded_baseline = 1
        record.seed_active_seconds = 12
        record.seed_seconds_baseline = 2
        runtime.pause_transfer({"digest": download.digest})
        runtime.save_state()
    finally:
        runtime.close()

    state = json.loads((state_root / "state.json").read_text("utf-8"))
    state["version"] = state_version
    for lease in state["leases"]:
        if lease["kind"] == "seed":
            lease["grantIds"] = ["public-fixture-grant"]
    if state_version == 1:
        state.pop("activity")
    else:
        for activity in state["activity"]:
            if state_version == 2:
                activity.pop("transportDownloadSample")
                activity.pop("transportUploadSample")
            activity.pop("seedGrantIds")
            activity.pop("globalUploadedBaseline")
            activity.pop("globalSeedSecondsBaseline")
            activity.pop("globalResumeRequired")
    (state_root / "state.json").write_text(json.dumps(state), "utf-8")

    restored = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    try:
        status = restored.status()
        assert status["recovery"] is None
        expected_totals = (
            {"downloadedBytes": 0, "uploadedBytes": 0}
            if state_version == 1
            else {"downloadedBytes": 6, "uploadedBytes": 4}
        )
        assert status["totals"] == expected_totals
        assert status["transfers"][0]["state"] == (  # type: ignore[index]
            "queued" if state_version == 1 else "paused"
        )
        assert status["transfers"][0]["seedGrantIds"] == []  # type: ignore[index]
        assert all(isinstance(lease, DownloadLease) for lease in restored._leases.values())  # noqa: SLF001
        record = restored._activity[download.digest]  # noqa: SLF001
        assert record.transport_download_sample == expected_totals["downloadedBytes"]
        assert record.transport_upload_sample == expected_totals["uploadedBytes"]
        if state_version == 1:
            assert not list(state_root.glob("*.corrupt-*"))
            return
        assert status["transfers"][0]["remainingSeedTimeSeconds"] is None  # type: ignore[index]
        restored.grant(seed.to_wire(), "seed")
        reauthorized = restored.status()["transfers"][0]  # type: ignore[index]
        assert reauthorized["seedGrantIds"] == [SEED_GRANT_ID]
        assert reauthorized["remainingSeedTimeSeconds"] is None
        sample = SimpleNamespace(
            info_hashes=SimpleNamespace(v2=download.descriptor.info_hash, has_v2=lambda: True),
            all_time_download=record.transport_download_sample,
            all_time_upload=record.transport_upload_sample,
            is_seeding=False,
            is_finished=False,
            flags=restored._lt.torrent_flags.paused,  # noqa: SLF001
            state=restored._lt.torrent_status.downloading,  # noqa: SLF001
            num_peers=1,
            download_payload_rate=1,
            upload_payload_rate=1,
        )
        real_session = restored._session  # noqa: SLF001
        restored._session = SimpleNamespace(  # noqa: SLF001
            get_torrents=lambda: [SimpleNamespace(status=lambda: sample, pause=lambda: None)]
        )
        try:
            assert restored._sync_activity(now=1.0) is False  # noqa: SLF001
            assert record.downloaded_bytes == 6
            assert record.uploaded_bytes == 4
        finally:
            restored._session = real_session  # noqa: SLF001
        assert not list(state_root.glob("*.corrupt-*"))
    finally:
        restored.close()


@pytest.mark.parametrize("state_version", [4, 5])
def test_prior_activity_state_restores_global_policy_defaults(
    tmp_path: Path, state_version: int
) -> None:
    download, seed = lease_fixtures(tmp_path)
    settings = enabled_settings(downloads=True, seeding=True)
    state_root = tmp_path / "vault" / ".p2p"
    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    try:
        runtime.grant(download.to_wire(), "download")
        runtime.grant(seed.to_wire(), "seed")
        runtime.save_state()
    finally:
        runtime.close()

    state = json.loads((state_root / "state.json").read_text("utf-8"))
    state["version"] = state_version
    for activity in state["activity"]:
        if state_version == 4:
            activity.pop("globalUploadedBaseline")
            activity.pop("globalSeedSecondsBaseline")
        activity.pop("globalResumeRequired")
    (state_root / "state.json").write_text(json.dumps(state), "utf-8")

    restored = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    try:
        assert restored.status()["recovery"] is None
        record = restored._activity[download.digest]  # noqa: SLF001
        assert record.seed_grant_ids == (SEED_GRANT_ID,)
        assert record.global_uploaded_baseline == 0
        assert record.global_seed_seconds_baseline == 0
        assert record.global_resume_required is False
        assert not list(state_root.glob("*.corrupt-*"))
    finally:
        restored.close()


@pytest.mark.parametrize(
    ("manually_paused", "unsafe_resume"),
    [(False, False), (True, False), (False, True)],
    ids=("running", "manual-pause", "unsafe-setting"),
)
def test_resume_uses_current_outgoing_interfaces_across_policy_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    manually_paused: bool,
    unsafe_resume: bool,
) -> None:
    populated = LanNetworkPolicy(
        (
            LanInterface(
                "loopback",
                IPv4Address("127.0.0.1"),
                IPv4Network("127.0.0.0/8"),
            ),
        )
    )
    empty = LanNetworkPolicy(())
    current_policy = [populated]
    monkeypatch.setattr(p2p_runtime, "current_lan_policy", lambda: current_policy[0])
    download, _ = lease_fixtures(tmp_path)
    settings = {**enabled_settings(downloads=True), "scope": "lan-only"}
    vault = tmp_path / "vault"
    state_root = vault / ".p2p"

    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=vault,
        installation_root=None,
        settings=settings,
    )
    try:
        runtime.grant(download.to_wire(), "download")
        if manually_paused:
            runtime.pause()
        else:
            runtime.save_state()
        if unsafe_resume:
            resume_state = runtime._lt.bdecode(  # noqa: SLF001
                (state_root / "session.resume").read_bytes()
            )
            resume_state[b"settings"][b"enable_dht"] = 1
            (state_root / "session.resume").write_bytes(
                bytes(runtime._lt.bencode(resume_state))  # noqa: SLF001
            )
    finally:
        runtime.close()

    for policy in (empty,) if unsafe_resume else (empty, populated):
        current_policy[0] = policy
        restored = SidecarRuntime(
            state_root=state_root,
            vault_root=vault,
            installation_root=None,
            settings=settings,
        )
        try:
            status = restored.status()
            if unsafe_resume:
                assert status["state"] == "paused"
                assert status["leases"] == []
                assert status["recovery"]["state"] == "corrupt-state-quarantined"  # type: ignore[index]
                assert list(state_root.glob("session.resume.corrupt-*"))
            else:
                assert status["state"] == ("paused" if manually_paused else "running")
                assert status["recovery"] is None
                assert [lease["leaseId"] for lease in status["leases"]] == [download.lease_id]  # type: ignore[index]
                assert not list(state_root.glob("*.corrupt-*"))
                restored.save_state()
        finally:
            restored.close()


def test_legacy_grant_migration_still_quarantines_duplicate_lease_ids(tmp_path: Path) -> None:
    download, seed = lease_fixtures(tmp_path)
    settings = enabled_settings(downloads=True, seeding=True)
    state_root = tmp_path / "vault" / ".p2p"
    runtime = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    try:
        runtime.grant(download.to_wire(), "download")
        runtime.grant(seed.to_wire(), "seed")
        runtime.save_state()
    finally:
        runtime.close()

    state = json.loads((state_root / "state.json").read_text("utf-8"))
    state["version"] = 3
    for lease in state["leases"]:
        if lease["kind"] == "seed":
            lease["leaseId"] = download.lease_id
            lease["grantIds"] = ["public-fixture-grant"]
    for activity in state["activity"]:
        activity.pop("seedGrantIds")
        activity.pop("globalUploadedBaseline")
        activity.pop("globalSeedSecondsBaseline")
        activity.pop("globalResumeRequired")
    (state_root / "state.json").write_text(json.dumps(state), "utf-8")

    restored = SidecarRuntime(
        state_root=state_root,
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings=settings,
    )
    try:
        assert restored.status()["recovery"]["state"] == "corrupt-state-quarantined"  # type: ignore[index]
        assert list(state_root.glob("state.json.corrupt-*"))
    finally:
        restored.close()


def test_state_lock_denies_a_second_owner(tmp_path: Path) -> None:
    first = StateLock(tmp_path / "session.lock")
    try:
        with pytest.raises(StateLockError, match="another sidecar owns"):
            StateLock(tmp_path / "session.lock")
    finally:
        first.close()
    replacement = StateLock(tmp_path / "session.lock")
    replacement.close()


def test_default_manager_creates_no_p2p_state_or_child(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        manager = P2PSidecarManager(vault_root=tmp_path / "vault")
        assert not manager.state_root.exists()
        await manager.start(default_p2p_settings())
        try:
            status = await manager.status()
            assert manager.process is None
            assert status["state"] == "disabled"
            assert status["settings"] == default_p2p_settings()
            assert status["sidecar"] is None
            assert not manager.state_root.exists()
        finally:
            await manager.close()

    asyncio.run(scenario())


def test_manager_discards_and_restarts_after_a_control_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        download, _seed = lease_fixtures(tmp_path)
        manager = P2PSidecarManager(vault_root=tmp_path / "vault")
        await manager.start(enabled_settings(downloads=True))
        try:
            await manager.grant_download(download)
            process = manager.process
            assert process is not None
            original_pid = process.pid
            block_next = True

            async def blocked_read(reader: asyncio.StreamReader) -> Any:
                nonlocal block_next
                if block_next:
                    block_next = False
                    await asyncio.sleep(1)
                return await read_boundary_frame(reader)

            monkeypatch.setattr("dinkster_p2p.manager.read_frame", blocked_read)
            monkeypatch.setattr("dinkster_p2p.manager._REQUEST_TIMEOUT_SECONDS", 0.01)
            with pytest.raises(
                P2PManagerError,
                match=r"P2P sidecar lease-status timed out after 0\.01 seconds",
            ):
                await manager.lease_status(download.lease_id)

            failed = await manager.status()
            assert failed["state"] == "restarting"
            assert failed["sidecar"] is None
            assert failed["lastError"] == ("P2P sidecar lease-status timed out after 0.01 seconds")
            assert manager.process is None

            monkeypatch.setattr("dinkster_p2p.manager.read_frame", read_boundary_frame)
            monkeypatch.setattr("dinkster_p2p.manager._REQUEST_TIMEOUT_SECONDS", 15.0)
            restarted = await wait_for(
                manager.status,
                lambda value: value["state"] == "running",
            )
            assert restarted["restartCount"] == 1
            assert restarted["lastError"] is None
            assert manager.process is not None and manager.process.pid != original_pid
        finally:
            await manager.close()

    asyncio.run(scenario())


def test_manager_discards_and_restarts_after_a_cancelled_control_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        download, _seed = lease_fixtures(tmp_path)
        manager = P2PSidecarManager(vault_root=tmp_path / "vault")
        await manager.start(enabled_settings(downloads=True))
        try:
            await manager.grant_download(download)
            process = manager.process
            assert process is not None
            original_pid = process.pid
            reading = asyncio.Event()

            async def blocked_read(reader: asyncio.StreamReader) -> Any:
                reading.set()
                await asyncio.Event().wait()
                return await read_boundary_frame(reader)

            monkeypatch.setattr("dinkster_p2p.manager.read_frame", blocked_read)
            request = asyncio.create_task(manager.lease_status(download.lease_id))
            await asyncio.wait_for(reading.wait(), timeout=1)
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request

            failed = await manager.status()
            assert failed["state"] == "restarting"
            assert failed["sidecar"] is None
            assert failed["lastError"] == ("P2P sidecar lease-status was cancelled before response")
            assert manager.process is None

            monkeypatch.setattr("dinkster_p2p.manager.read_frame", read_boundary_frame)
            restarted = await wait_for(
                manager.status,
                lambda value: value["state"] == "running",
            )
            assert restarted["restartCount"] == 1
            assert restarted["lastError"] is None
            assert manager.process is not None and manager.process.pid != original_pid
        finally:
            await manager.close()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "transport",
    [
        pytest.param(
            "unix",
            marks=pytest.mark.skipif(
                sys.platform == "win32", reason="asyncio has no Unix endpoints on Windows"
            ),
        ),
        "tcp",
    ],
)
def test_sidecar_capabilities_operations_and_persistence(
    tmp_path: Path, transport: Literal["unix", "tcp"]
) -> None:
    async def scenario() -> None:
        download, seed = lease_fixtures(tmp_path)
        manager = P2PSidecarManager(vault_root=tmp_path / "vault", transport=transport)
        await manager.start(enabled_settings(downloads=True))
        try:
            status = await manager.status()
            assert status["state"] == "running"
            assert status["sidecar"]["capabilities"] == {  # type: ignore[index]
                "downloads": True,
                "seeding": False,
            }
            await manager.grant_download(download)
            await manager.pause_transfer(download.digest)
            await manager.grant_download(download)
            assert (await manager.status())["sidecar"]["transfers"][0]["state"] == "paused"  # type: ignore[index]
            await manager.stop_transfer(download.digest)
            await manager.grant_download(download)
            assert (await manager.status())["sidecar"]["transfers"][0]["state"] == "stopped"  # type: ignore[index]
            await manager.resume_transfer(download.digest)
            with pytest.raises(P2PManagerError, match="one active torrent per digest"):
                await manager.grant_download(replace(download, lease_id="duplicate-writer"))
            with pytest.raises(P2PManagerError, match="expired"):
                await manager.grant_download(
                    replace(download, lease_id="expired", expires_at=time.time() - 1)
                )
            with pytest.raises(P2PManagerError, match="trusted provider authority"):
                await manager.grant_download(
                    replace(download, lease_id="global", scope="lan-and-internet")
                )
            with pytest.raises(P2PManagerError, match="seed capability is disabled"):
                await manager.grant_seed(seed)

            await manager.update(enabled_settings(downloads=True, seeding=True))
            wrong_seed = tmp_path / "wrong-seed.bin"
            wrong_seed.write_bytes(b"x" * seed.size_bytes)
            with pytest.raises(P2PManagerError, match="verification failed"):
                await manager.grant_seed(
                    replace(seed, lease_id="wrong-seed", local_path=wrong_seed.resolve())
                )
            await manager.grant_seed(seed)
            await wait_for(
                lambda: manager.lease_status(seed.lease_id),
                lambda value: value["state"] == "ready",
            )
            await manager.update(enabled_settings(seeding=True))
            lease_states = {
                lease["leaseId"]: lease["state"]
                for lease in (await manager.status())["sidecar"]["leases"]  # type: ignore[index]
            }
            assert lease_states == {"download-fixture": "disabled", "seed-fixture": "ready"}
            paused = await manager.pause()
            assert paused["state"] == "paused"
            assert paused["networkFeatures"] == {
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
            assert (await manager.resume())["state"] == "running"

            partial = manager.vault_root / ".p2p" / "staging" / download.staging_path
            partial.parent.mkdir(parents=True, exist_ok=True)
            partial.write_bytes(b"partial")
            assert (await manager.remove_partial(download.lease_id))["removed"] is True
            assert not partial.exists()
            await manager.save_state()
        finally:
            await manager.close()

        assert (manager.state_root / "state.json").is_file()
        assert (manager.state_root / "session.resume").is_file()
        restored = P2PSidecarManager(vault_root=manager.vault_root, transport=transport)
        await restored.start(enabled_settings(downloads=True, seeding=True))
        try:
            sidecar = (await restored.status())["sidecar"]
            assert [lease["leaseId"] for lease in sidecar["leases"]] == ["seed-fixture"]  # type: ignore[index]
            assert sidecar["leases"][0]["state"] == "inactive"  # type: ignore[index]
            await restored.grant_seed(seed)
            await wait_for(
                lambda: restored.lease_status(seed.lease_id),
                lambda value: value["state"] == "ready",
            )
            assert (await restored.revoke(seed.lease_id))["revoked"] is True
        finally:
            await restored.close()

    asyncio.run(scenario())


def test_activity_rejects_untrusted_global_seed_and_gates_resume(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        download, seed = lease_fixtures(tmp_path)
        internet_seed = replace(
            seed,
            lease_id="internet-seed",
            grant_ids=(INTERNET_SEED_GRANT_ID,),
            scope="lan-and-internet",
        )
        internet_policy = {
            **enabled_settings(downloads=True, seeding=True),
            "scope": "lan-and-internet",
        }
        manager = P2PSidecarManager(vault_root=tmp_path / "vault")
        await manager.start(internet_policy)
        try:
            with pytest.raises(P2PManagerError, match="trusted provider authority"):
                await manager.grant_seed(internet_seed)
            await manager.grant_download(download)
            await manager.grant_seed(seed)
            await manager.update(enabled_settings(downloads=True, seeding=True))

            transfer = (await manager.status())["sidecar"]["transfers"][0]  # type: ignore[index]
            assert transfer["seedGrantIds"] == [SEED_GRANT_ID]
            assert transfer["authorizedSeedGrantIds"] == [SEED_GRANT_ID]

            await manager.pause_transfer(download.digest)
            await manager.revoke(download.lease_id)
            await manager.revoke(seed.lease_id)
            with pytest.raises(P2PManagerConflict, match="active authorization"):
                await manager.resume_transfer(download.digest)
            with pytest.raises(P2PManagerConflict, match="seed authorization"):
                await manager.reset_transfer_budget(download.digest)
            with pytest.raises(P2PManagerConflict, match="seed authorization"):
                await manager.make_transfer_continuous(download.digest)
        finally:
            await manager.close()

    asyncio.run(scenario())


def test_second_manager_is_denied_and_corrupt_state_recovers_paused(tmp_path: Path) -> None:
    async def scenario() -> None:
        vault = tmp_path / "vault"
        first = P2PSidecarManager(vault_root=vault)
        second = P2PSidecarManager(vault_root=vault)
        await first.start(enabled_settings(downloads=True))
        try:
            await second.start(enabled_settings(seeding=True))
            denied = await second.status()
            assert denied["state"] == "restarting"
            assert denied["sidecar"] is None
        finally:
            await second.close()
            await first.close()

        state_root = vault / ".p2p"
        (state_root / "state.json").write_text("{not json", "utf-8")
        recovering = P2PSidecarManager(vault_root=vault)
        await recovering.start(enabled_settings(downloads=True))
        try:
            sidecar = (await recovering.status())["sidecar"]
            assert sidecar["state"] == "paused"  # type: ignore[index]
            assert sidecar["recovery"]["state"] == "corrupt-state-quarantined"  # type: ignore[index]
            assert list(state_root.glob("state.json.corrupt-*"))
            assert list(state_root.glob("session.resume.corrupt-*"))
        finally:
            await recovering.close()

        recovered = P2PSidecarManager(vault_root=vault)
        await recovered.start(enabled_settings(downloads=True))
        try:
            sidecar = (await recovered.status())["sidecar"]
            assert sidecar["state"] == "paused"  # type: ignore[index]
            assert sidecar["recovery"] is None  # type: ignore[index]
        finally:
            await recovered.close()

        (state_root / "session.resume").write_bytes(b"not bencoded")
        resume_recovery = P2PSidecarManager(vault_root=vault)
        await resume_recovery.start(enabled_settings(downloads=True))
        try:
            sidecar = (await resume_recovery.status())["sidecar"]
            assert sidecar["state"] == "paused"  # type: ignore[index]
            assert sidecar["recovery"]["state"] == "corrupt-state-quarantined"  # type: ignore[index]
        finally:
            await resume_recovery.close()

        (state_root / "session.resume").write_bytes(b"d8:settingsd10:enable_dhti1eee")
        unsafe_recovery = P2PSidecarManager(vault_root=vault)
        await unsafe_recovery.start(enabled_settings(downloads=True))
        try:
            sidecar = (await unsafe_recovery.status())["sidecar"]
            assert sidecar["state"] == "paused"  # type: ignore[index]
            assert sidecar["recovery"]["state"] == "corrupt-state-quarantined"  # type: ignore[index]
        finally:
            await unsafe_recovery.close()

    asyncio.run(scenario())


def test_changed_seed_fails_closed_during_restore(tmp_path: Path) -> None:
    async def scenario() -> None:
        _, seed = lease_fixtures(tmp_path)
        vault = tmp_path / "vault"
        manager = P2PSidecarManager(vault_root=vault)
        await manager.start(enabled_settings(seeding=True))
        try:
            await manager.grant_seed(seed)
        finally:
            await manager.close()

        seed.local_path.write_bytes(b"changed fixture")
        recovering = P2PSidecarManager(vault_root=vault)
        await recovering.start(enabled_settings(seeding=True))
        try:
            sidecar = (await recovering.status())["sidecar"]
            assert sidecar["state"] == "paused"  # type: ignore[index]
            assert sidecar["leases"] == []  # type: ignore[index]
            assert sidecar["recovery"]["state"] == "corrupt-state-quarantined"  # type: ignore[index]
        finally:
            await recovering.close()

    asyncio.run(scenario())


def test_restart_budget_stops_relaunching(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        monkeypatch.setattr("dinkster_p2p.manager._RESTART_BACKOFF_SECONDS", (0.01, 0.01, 0.01))
        manager = P2PSidecarManager(vault_root=tmp_path / "vault")
        monkeypatch.setattr(
            manager,
            "_sidecar_command",
            lambda endpoint: [sys.executable, "-c", "raise SystemExit(9)"],
        )
        await manager.start(enabled_settings(downloads=True))
        try:
            failed = await wait_for(manager.status, lambda value: value["state"] == "failed")
            assert failed["restartCount"] == 3
            assert manager.process is None
        finally:
            await manager.close()

    asyncio.run(scenario())
