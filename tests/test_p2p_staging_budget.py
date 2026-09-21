"""Shared LAN/global disk admission with real libtorrent and confined staging."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from dinkster_assets import AssetVault, canonical_p2p_info, derive_p2p_descriptor

from dinkster_p2p import DownloadLease, SeedLease, default_p2p_settings
from dinkster_p2p.global_transfers import GlobalTransferController, GlobalTransferError
from dinkster_p2p.runtime import SidecarError, SidecarRuntime


def _download(tmp_path: Path, name: str, scope: str = "lan-only") -> DownloadLease:
    source = tmp_path / f"{name}.safetensors"
    size = 256 * 1024
    header = json.dumps(
        {"weight": {"dtype": "U8", "shape": [size], "data_offsets": [0, size]}},
        separators=(",", ":"),
    ).encode()
    header += b" " * (-len(header) % 8)
    source.write_bytes(len(header).to_bytes(8, "little") + header + name.encode()[:1] * size)
    derived = derive_p2p_descriptor(source)
    return DownloadLease(
        version=1,
        kind="download",
        lease_id=name,
        digest=derived.asset_digest,
        size_bytes=derived.size,
        descriptor=derived.descriptor,
        staging_path=f"{derived.descriptor.info_hash}/{derived.asset_digest[7:]}",
        scope=scope,
        expires_at=time.time() + 60,
    )


@contextmanager
def _runtime(tmp_path: Path, budget: int) -> Iterator[SidecarRuntime]:
    runtime = SidecarRuntime(
        state_root=tmp_path / "state",
        vault_root=tmp_path / "vault",
        installation_root=None,
        settings={
            **default_p2p_settings(),
            "downloadsEnabled": True,
            "seedingEnabled": True,
            "scope": "lan-and-internet",
            "stagingBudgetBytes": budget,
        },
    )
    try:
        yield runtime
    finally:
        runtime.close()


def _grant(runtime: SidecarRuntime, lease: DownloadLease | SeedLease) -> None:
    if lease.scope == "lan-only":
        runtime.grant(lease.to_wire(), lease.kind)
    else:
        runtime.grant_global({"lease": lease.to_wire(), "trackers": []})


def _state(runtime: SidecarRuntime, lease: DownloadLease | SeedLease) -> str:
    status = cast(Any, runtime.status())
    return next(row["state"] for row in status["transfers"] if row["digest"] == lease.digest)


@pytest.mark.parametrize(
    ("first_scope", "second_scope"),
    [
        ("lan-only", "lan-only"),
        ("lan-only", "lan-and-internet"),
        ("lan-and-internet", "lan-only"),
        ("lan-and-internet", "lan-and-internet"),
    ],
)
def test_concurrent_downloads_reserve_missing_bytes_across_scopes(
    tmp_path: Path, first_scope: str, second_scope: str
) -> None:
    first = _download(tmp_path, "a", first_scope)
    second = _download(tmp_path, "b", second_scope)
    third = _download(tmp_path, "c", second_scope)
    with _runtime(tmp_path, first.size_bytes + second.size_bytes + 32 * 1024) as runtime:
        _grant(runtime, first)
        _grant(runtime, second)
        with pytest.raises(SidecarError, match="staging budget"):
            _grant(runtime, third)
        assert len(cast(Any, runtime)._session.get_torrents()) == 2
        assert third.lease_id not in cast(Any, runtime)._leases
        assert not (tmp_path / "vault" / ".p2p" / "staging" / third.descriptor.info_hash).exists()
        assert _state(runtime, first) != "paused"
        assert _state(runtime, second) != "paused"


@pytest.mark.parametrize("scope", ["lan-only", "lan-and-internet"])
def test_partial_resume_counts_allocated_bytes_once_and_reserves_sparse_holes(
    tmp_path: Path, scope: str
) -> None:
    lease = _download(tmp_path, "a", scope)
    other = _download(tmp_path, "b")
    vault = AssetVault(tmp_path / "vault")
    partial = vault.open_p2p_partial(lease.descriptor, lease.digest, lease.size_bytes)
    partial.write_piece(0, (tmp_path / "a.safetensors").read_bytes()[: 128 * 1024])
    before = partial.completed_ranges
    with _runtime(tmp_path, lease.size_bytes + 32 * 1024) as runtime:
        _grant(runtime, lease)
        runtime.pause_transfer({"digest": lease.digest})
        assert _state(runtime, lease) == "paused"
        runtime.resume_transfer({"digest": lease.digest})
        assert _state(runtime, lease) != "paused"
        with pytest.raises(SidecarError, match="staging budget"):
            _grant(runtime, other)
        runtime.configure({**runtime.settings, "stagingBudgetBytes": lease.size_bytes // 2})
        assert _state(runtime, lease) == "paused"
        with pytest.raises(SidecarError, match="staging budget"):
            runtime.resume_transfer({"digest": lease.digest})
        assert partial.completed_ranges == before


def test_unleased_staging_counts_and_pausing_releases_only_unallocated_reservation(
    tmp_path: Path,
) -> None:
    first = _download(tmp_path, "a")
    second = _download(tmp_path, "b", "lan-and-internet")
    orphan = _download(tmp_path, "c")
    vault = AssetVault(tmp_path / "vault")
    partial = vault.open_p2p_partial(orphan.descriptor, orphan.digest, orphan.size_bytes)
    partial.write_piece(0, (tmp_path / "c.safetensors").read_bytes()[: 128 * 1024])
    vault.open_p2p_partial(first.descriptor, first.digest, first.size_bytes)
    allocated_usage = vault.p2p_staging_usage().actual_bytes
    first_growth = vault.p2p_partial_growth(first.descriptor, first.digest, first.size_bytes)
    admission_budget = allocated_usage + first_growth
    with _runtime(tmp_path, admission_budget - 1) as runtime:
        with pytest.raises(SidecarError, match="staging budget"):
            _grant(runtime, first)
        runtime.configure({**runtime.settings, "stagingBudgetBytes": admission_budget})
        _grant(runtime, first)
        with pytest.raises(SidecarError, match="staging budget"):
            _grant(runtime, second)
        runtime.pause_transfer({"digest": first.digest})
        _grant(runtime, second)
        with pytest.raises(SidecarError, match="staging budget"):
            runtime.resume_transfer({"digest": first.digest})
        assert partial.path.exists()


def test_lowered_budget_pauses_only_downloads_that_do_not_fit_and_survives_restart(
    tmp_path: Path,
) -> None:
    lan = _download(tmp_path, "a")
    internet = _download(tmp_path, "b", "lan-and-internet")
    high = 2 * lan.size_bytes + 32 * 1024
    low = lan.size_bytes + 32 * 1024
    with _runtime(tmp_path, high) as runtime:
        _grant(runtime, lan)
        _grant(runtime, internet)
        runtime.configure({**runtime.settings, "stagingBudgetBytes": low})
        assert _state(runtime, lan) != "paused"
        assert _state(runtime, internet) == "paused"
        with pytest.raises(SidecarError, match="staging budget"):
            runtime.resume_transfer({"digest": internet.digest})
        runtime.configure({**runtime.settings, "stagingBudgetBytes": high})
        assert _state(runtime, internet) == "paused"
    state = json.loads((tmp_path / "state" / "state.json").read_text())
    assert (
        next(row for row in state["activity"] if row["digest"] == internet.digest)["stateOverride"]
        == "paused"
    )
    with _runtime(tmp_path, high) as runtime:
        _grant(runtime, internet)
        assert _state(runtime, internet) == "paused"
        runtime.resume_transfer({"digest": internet.digest})
        assert _state(runtime, internet) != "paused"


def test_lower_budget_at_startup_latches_lan_resume_without_deleting_partial(
    tmp_path: Path,
) -> None:
    lease = _download(tmp_path, "a")
    high = lease.size_bytes + 32 * 1024
    with _runtime(tmp_path, high) as runtime:
        _grant(runtime, lease)
    partial_path = tmp_path / "vault" / ".p2p" / "staging" / lease.staging_path
    with _runtime(tmp_path, 0) as runtime:
        assert _state(runtime, lease) == "paused"
        with pytest.raises(SidecarError, match="staging budget"):
            runtime.resume_transfer({"digest": lease.digest})
        assert partial_path.exists()
    with _runtime(tmp_path, high) as runtime:
        assert _state(runtime, lease) == "paused"
        runtime.resume_transfer({"digest": lease.digest})
        assert len(cast(Any, runtime)._session.get_torrents()) == 1
        assert _state(runtime, lease) != "paused"


@pytest.mark.parametrize("scope", ["lan-only", "lan-and-internet"])
def test_zero_denies_new_growth_but_preserves_seeds_and_lan_mapping(
    tmp_path: Path, scope: str
) -> None:
    download = _download(tmp_path, "a", scope)
    source = _download(tmp_path, "b", scope)
    seed = SeedLease(
        version=1,
        kind="seed",
        lease_id="seed",
        digest=source.digest,
        size_bytes=source.size_bytes,
        descriptor=source.descriptor,
        grant_ids=("a" * 64,),
        local_path=(tmp_path / "b.safetensors").resolve(),
        scope=scope,
        expires_at=source.expires_at,
    )
    with _runtime(tmp_path, download.size_bytes + 32 * 1024) as runtime:
        _grant(runtime, seed)
        _grant(runtime, download)
        seed_handle = cast(Any, runtime)._torrent_handles(seed.digest)[0]
        plan = cast(Any, runtime)._session_plan
        runtime.configure({**runtime.settings, "stagingBudgetBytes": 0})
        assert _state(runtime, download) == "paused"
        assert _state(runtime, seed) != "paused"
        download_handles = cast(Any, runtime)._torrent_handles(download.digest)
        if scope == "lan-only":
            assert download_handles[0].status().paused
        else:
            assert not download_handles
        assert cast(Any, runtime)._session_plan == plan
        assert cast(Any, runtime)._torrent_handles(seed.digest) == [seed_handle]
        other = _download(tmp_path, "c", scope)
        with pytest.raises(SidecarError, match="staging budget"):
            _grant(runtime, other)
        assert not (tmp_path / "vault" / ".p2p" / "staging" / other.staging_path).exists()


@pytest.mark.parametrize("scope", ["lan-only", "lan-and-internet"])
def test_publishing_releases_reservation_for_next_download(tmp_path: Path, scope: str) -> None:
    first = _download(tmp_path, "a", scope)
    second = _download(tmp_path, "b", scope)
    with _runtime(tmp_path, first.size_bytes + 32 * 1024) as runtime:
        _grant(runtime, first)
        with pytest.raises(SidecarError, match="staging budget"):
            _grant(runtime, second)
        internal = cast(Any, runtime)
        partial = internal._vault.open_p2p_partial(first.descriptor, first.digest, first.size_bytes)
        partial.write_piece(0, (tmp_path / "a.safetensors").read_bytes())
        if scope == "lan-only":
            torrent = internal._torrents[first.lease_id]
            internal._stop_torrent(torrent)
            torrent.state = "publishing"
            internal._publish_downloads()
        else:
            internal._global._publish_download(first.lease_id)
        assert internal._vault.has(first.digest)
        assert not partial.path.exists()
        _grant(runtime, second)
        assert _state(runtime, second) != "paused"
    with _runtime(tmp_path, first.size_bytes + 32 * 1024) as runtime:
        _grant(runtime, second)
        assert _state(runtime, second) != "paused"


@pytest.mark.parametrize("scope", ["lan-only", "lan-and-internet"])
def test_oversized_descriptor_cannot_allocate_before_admission(tmp_path: Path, scope: str) -> None:
    lease = _download(tmp_path, "a", scope)
    size = 65 * 1024**3
    info = canonical_p2p_info(
        asset_digest=lease.digest, size=size, file_root=lease.descriptor.file_root
    )
    descriptor = replace(lease.descriptor, info_hash=hashlib.sha256(info).hexdigest())
    lease = replace(
        lease,
        descriptor=descriptor,
        size_bytes=size,
        staging_path=f"{descriptor.info_hash}/{lease.digest[7:]}",
    )
    with _runtime(tmp_path, 64 * 1024**3) as runtime:
        with pytest.raises(SidecarError, match="staging budget"):
            _grant(runtime, lease)
        assert not cast(Any, runtime)._session.get_torrents()
        assert AssetVault(tmp_path / "vault").p2p_staging_usage().logical_bytes == 0


def test_global_add_requires_shared_admission_even_when_called_directly(tmp_path: Path) -> None:
    lease = _download(tmp_path, "a", "lan-and-internet")
    with _runtime(tmp_path, 0) as runtime:
        with pytest.raises(SidecarError, match="staging budget"):
            cast(Any, runtime)._global._add(lease, ())
        controller = GlobalTransferController(
            cast(Any, object()),
            cast(Any, object()),
            state_root=tmp_path / "unused-state",
            vault_root=tmp_path / "vault",
            torrent_flags=lambda _: 0,
            shared_handle_for=lambda _: None,
            release_shared_handle=lambda _lease, _handle: None,
            allows_lan_peer=lambda _: False,
        )
        with pytest.raises(GlobalTransferError, match="shared staging budget"):
            cast(Any, controller)._add(lease, ())
