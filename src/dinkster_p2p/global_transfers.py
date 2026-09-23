"""Scope-gated global transfer policy and durable accounting."""

# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import contextlib
import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from dinkster_assets import (
    P2P_FORMAT_POLICY_VERSION,
    P2P_PIECE_LENGTH,
    AssetError,
    AssetVault,
    P2PLocalFileMapping,
)
from dinkster_assets.p2p_global import GlobalP2PCounters, GlobalP2PCounterStore
from dinkster_assets.p2p_storage import verified_p2p_seed_descriptor

from .contracts import DownloadLease, P2PLease, SeedLease

_TRANSFER_STATES = {
    "checking_files": "queued",
    "downloading_metadata": "queued",
    "downloading": "downloading",
    "finished": "complete",
    "seeding": "seeding",
    "allocating": "queued",
    "checking_resume_data": "queued",
}


class GlobalTransferError(RuntimeError):
    """A global transfer cannot safely apply an authorized lease."""


@dataclass(frozen=True, slots=True)
class _TerminalDownload:
    lease: DownloadLease
    state: str
    path: str | None = None
    error: str | None = None


class GlobalTransferController:
    """Own global handles and accounting within the sidecar's shared session."""

    def __init__(
        self,
        libtorrent: Any,
        session: Any,
        *,
        state_root: Path,
        vault_root: Path,
        torrent_flags: Callable[[P2PLease], int],
        shared_handle_for: Callable[[P2PLease], Any | None],
        release_shared_handle: Callable[[P2PLease, Any], None],
        allows_lan_peer: Callable[[str], bool],
        admit_download: Callable[[DownloadLease], None] | None = None,
    ) -> None:
        self._lt = libtorrent
        self._session = session
        self._state_root = state_root
        self._vault_root = vault_root
        self._torrent_flags = torrent_flags
        self._shared_handle_for = shared_handle_for
        self._release_shared_handle = release_shared_handle
        self._allows_lan_peer = allows_lan_peer
        self._admit_download = admit_download
        self._handles: dict[str, Any] = {}
        self._borrowed_handles: set[str] = set()
        self._leases: dict[str, P2PLease] = {}
        self._trackers: dict[str, tuple[str, ...]] = {}
        self._mappings: dict[str, P2PLocalFileMapping] = {}
        self._counter_store: GlobalP2PCounterStore | None = None
        self._last_totals: dict[str, tuple[int, int]] = {}
        self._last_peer_totals: dict[str, dict[tuple[str, int, str], tuple[bool, int, int]]] = {}
        self._transfer_policies: dict[str, tuple[bool, bool, int, int, bool]] = {}
        self._completed_downloads: set[str] = set()
        self._terminal_downloads: dict[str, _TerminalDownload] = {}
        self._budget_exhausted_digests: set[str] = set()
        self._last_tick = time.monotonic()
        self._closure_reason: str | None = "no-authority"

    @property
    def active(self) -> bool:
        return bool(self._handles)

    @property
    def budget_exhausted_digests(self) -> frozenset[str]:
        return frozenset(self._budget_exhausted_digests)

    def owns(self, handle: Any) -> bool:
        return any(current == handle for current in self._handles.values())

    def download_finished(self, lease_id: str) -> bool:
        return lease_id in self._completed_downloads

    def lease_status(self, lease_id: str) -> dict[str, object] | None:
        terminal = self._terminal_downloads.get(lease_id)
        if terminal is not None:
            result: dict[str, object] = {
                "state": "failed" if terminal.error is not None else terminal.state,
                "durableBytes": terminal.lease.size_bytes if terminal.path is not None else 0,
            }
            if terminal.path is not None:
                result["path"] = terminal.path
            if terminal.error is not None:
                result["error"] = terminal.error
            return result
        handle = self._handles.get(lease_id)
        if handle is None:
            return None
        lease = self._leases[lease_id]
        status = handle.status()
        if status.errc.value():
            return {"state": "failed", "error": status.errc.message()}
        if isinstance(lease, DownloadLease):
            # Native verified pieces indicate progress, not durable publication.
            # Only the verified vault adoption above can report completion/path.
            return {
                "state": "publishing" if status.is_finished else "downloading",
                "verifiedBytes": sum(
                    min(P2P_PIECE_LENGTH, lease.size_bytes - index * P2P_PIECE_LENGTH)
                    for index, have_piece in enumerate(status.pieces)
                    if have_piece
                ),
            }
        return {"state": "ready" if status.is_seeding else "checking"}

    def share_with_lan(self, lease: P2PLease) -> Any | None:
        for lease_id, current in self._leases.items():
            if current.digest != lease.digest:
                continue
            if not (
                isinstance(current, SeedLease)
                and isinstance(lease, SeedLease)
                and current.size_bytes == lease.size_bytes
                and current.descriptor == lease.descriptor
                and current.local_path == lease.local_path
            ):
                raise GlobalTransferError("LAN lease conflicts with an active global torrent")
            self._borrowed_handles.add(lease_id)
            return self._handles[lease_id]
        return None

    def unshare_with_lan(self, lease: P2PLease, handle: Any) -> None:
        for lease_id, current in self._leases.items():
            if current.digest == lease.digest and self._handles.get(lease_id) == handle:
                self._borrowed_handles.discard(lease_id)
                return

    def _counters(self) -> GlobalP2PCounterStore:
        if self._counter_store is None:
            self._counter_store = GlobalP2PCounterStore(self._state_root / "global-counters.sqlite")
        return self._counter_store

    def credit_seed(self, lease: SeedLease) -> None:
        if lease.scope != "lan-and-internet":
            return
        self._counters().credit_ratio_equivalent(
            f"seed:{lease.digest}", lease.digest, lease.size_bytes
        )

    @staticmethod
    def _capability_enabled(lease: P2PLease, settings: Mapping[str, object]) -> bool:
        field = "downloadsEnabled" if isinstance(lease, DownloadLease) else "seedingEnabled"
        return bool(settings[field])

    def _within_budget(self, lease: P2PLease, settings: Mapping[str, object]) -> bool:
        _, continuous, uploaded_baseline, seconds_baseline, _ = self._transfer_policies.get(
            lease.digest, (True, False, 0, 0, False)
        )
        if not isinstance(lease, SeedLease) or settings["seedMode"] == "continuous" or continuous:
            return True
        counters = self._counters().get(lease.digest)
        scaled_ratio = counters.ratio_equivalent_bytes * cast(float, settings["internetSeedRatio"])
        ratio_limit = (2**63 - 1) if scaled_ratio >= 2**63 - 1 else math.floor(scaled_ratio)
        uploaded = max(0, counters.uploaded_bytes - uploaded_baseline)
        active_seconds = max(0, counters.active_seed_seconds - seconds_baseline)
        return uploaded < ratio_limit and active_seconds < cast(
            int, settings["internetSeedTimeSeconds"]
        )

    def set_transfer_policy(
        self,
        digest: str,
        *,
        enabled: bool,
        continuous: bool,
        uploaded_baseline: int,
        active_seed_seconds_baseline: int,
        resume_required: bool,
    ) -> None:
        self._transfer_policies[digest] = (
            enabled,
            continuous,
            uploaded_baseline,
            active_seed_seconds_baseline,
            resume_required,
        )

    def _resume_required(self, lease: P2PLease) -> bool:
        return self._transfer_policies.get(lease.digest, (True, False, 0, 0, False))[4]

    def _policy_enabled(self, lease: P2PLease) -> bool:
        return self._transfer_policies.get(lease.digest, (True, False, 0, 0, False))[0]

    def _eligible(
        self,
        leases: Sequence[P2PLease],
        settings: Mapping[str, object],
        *,
        closure_reason: str | None,
    ) -> tuple[tuple[P2PLease, ...], str | None]:
        if settings["scope"] != "lan-and-internet":
            return (), "scope-disabled"
        if closure_reason is not None:
            return (), closure_reason
        now = time.time()
        eligible: list[P2PLease] = []
        blocked: set[str] = set()
        for lease in leases:
            if lease.scope != "lan-and-internet":
                continue
            if lease.lease_id in self._completed_downloads:
                blocked.add("download-complete")
            elif lease.expires_at <= now:
                blocked.add("lease-expired")
            elif not self._capability_enabled(lease, settings):
                blocked.add("capability-disabled")
            elif not self._within_budget(lease, settings):
                blocked.add("budget-exhausted")
                self._budget_exhausted_digests.add(lease.digest)
            elif self._resume_required(lease):
                blocked.add("resume-required")
            elif not self._policy_enabled(lease):
                blocked.add("policy-disabled")
            elif (
                isinstance(lease, SeedLease)
                and lease.lease_id in self._mappings
                and not self._mappings[lease.lease_id].is_current()
            ):
                blocked.add("seed-mapping-stale")
            else:
                eligible.append(lease)
        digests = [lease.digest for lease in eligible]
        if len(digests) != len(set(digests)):
            raise GlobalTransferError("global leases must have unique artifact digests")
        if eligible:
            return tuple(eligible), None
        if not blocked:
            return (), "no-authority"
        if len(blocked) == 1:
            return (), blocked.pop()
        return (), "no-eligible-authority"

    def reconcile(
        self,
        leases: Sequence[P2PLease],
        settings: Mapping[str, object],
        *,
        trackers: Mapping[str, tuple[str, ...]],
        closure_reason: str | None,
        apply_network_plan: Callable[[bool, bool], None],
    ) -> None:
        self.maintain(publish_downloads=False)
        self._budget_exhausted_digests.clear()
        current_lease_ids = {lease.lease_id for lease in leases}
        self._completed_downloads.intersection_update(current_lease_ids)
        for lease_id in self._terminal_downloads.keys() - current_lease_ids:
            self._terminal_downloads.pop(lease_id)
        for lease_id in self._mappings.keys() - current_lease_ids:
            self._mappings.pop(lease_id)
        eligible, closure_reason = self._eligible(
            leases,
            settings,
            closure_reason=closure_reason,
        )
        self._closure_reason = closure_reason
        if not eligible:
            self.close_transfers()
            apply_network_plan(False, False)
            return

        desired = {lease.lease_id: lease for lease in eligible}
        desired_trackers = {lease_id: tuple(trackers.get(lease_id, ())) for lease_id in desired}
        for lease_id in tuple(self._handles):
            if desired.get(lease_id) != self._leases.get(lease_id) or desired_trackers.get(
                lease_id
            ) != self._trackers.get(lease_id):
                self._remove(lease_id)
        apply_network_plan(True, any(desired_trackers.values()))
        for lease_id, lease in desired.items():
            if lease_id not in self._handles:
                self._handles[lease_id] = self._add(lease, desired_trackers[lease_id])
        self._leases = desired
        self._trackers = desired_trackers
        self.maintain()
        if not self._handles:
            apply_network_plan(False, False)

    def _staging_path(self, lease: DownloadLease) -> Path:
        return AssetVault(self._vault_root).p2p_staging_path(
            lease.descriptor,
            lease.digest,
            lease.size_bytes,
        )

    def _add(self, lease: P2PLease, trackers: tuple[str, ...]) -> Any:
        if isinstance(lease, DownloadLease):
            if self._admit_download is None:
                raise GlobalTransferError("download requires shared staging budget admission")
            self._admit_download(lease)
        params = self._lt.add_torrent_params()
        mapping: P2PLocalFileMapping | None = None
        params.flags = self._torrent_flags(lease)
        if isinstance(lease, SeedLease):
            try:
                mapping = AssetVault(self._vault_root).verify_p2p_local_file(
                    lease.digest,
                    lease.size_bytes,
                    lease.local_path,
                    P2P_FORMAT_POLICY_VERSION,
                )
                local_path = mapping.require_current()
                derived = verified_p2p_seed_descriptor(
                    self._vault_root, lease.digest, lease.size_bytes, local_path
                )
            except (AssetError, OSError) as error:
                raise GlobalTransferError(
                    f"seed mapping is not safe and current: {error}"
                ) from error
            if (
                derived.asset_digest != lease.digest
                or derived.size != lease.size_bytes
                or derived.descriptor != lease.descriptor
            ):
                raise GlobalTransferError("seed bytes no longer match the authorized descriptor")
            # Failed seed verification must not download repairs into the source file.
            params.flags |= self._lt.torrent_flags.seed_mode | self._lt.torrent_flags.upload_mode
            metainfo: dict[bytes, object] = {b"info": self._lt.bdecode(derived.info)}
            if derived.piece_layer:
                metainfo[b"piece layers"] = {
                    bytes.fromhex(lease.descriptor.file_root): derived.piece_layer
                }
            params.ti = self._lt.torrent_info(cast(Any, metainfo))
            params.save_path = str(local_path.parent)
            params.renamed_files = {0: local_path.name}
        else:
            params.max_uploads = 0
            params.info_hashes = self._lt.info_hash_t(
                self._lt.sha256_hash(bytes.fromhex(lease.descriptor.info_hash))
            )
            expected_staging = (
                f"{lease.descriptor.info_hash}/{lease.digest.removeprefix('blake3:')}"
            )
            if lease.staging_path != expected_staging:
                raise GlobalTransferError("download lease does not use canonical P2P staging")
            staging = self._staging_path(lease)
            params.save_path = str(staging.parent)

        if mapping is not None:
            try:
                mapping.require_current()
            except (AssetError, OSError) as error:
                raise GlobalTransferError(
                    f"seed mapping is not safe and current: {error}"
                ) from error
        handle = self._shared_handle_for(lease)
        borrowed = handle is not None
        if not borrowed:
            handle = self._session.add_torrent(params)
        else:
            mask = int(
                self._lt.torrent_flags.apply_ip_filter
                | self._lt.torrent_flags.disable_dht
                | self._lt.torrent_flags.disable_pex
                | self._lt.torrent_flags.override_trackers
                | self._lt.torrent_flags.override_web_seeds
            )
            handle.set_flags(self._torrent_flags(lease), mask)
            self._borrowed_handles.add(lease.lease_id)
        if trackers:
            handle.replace_trackers([self._lt.announce_entry(url) for url in trackers])
        if isinstance(lease, SeedLease):
            assert mapping is not None
            self._mappings[lease.lease_id] = mapping
        if borrowed:
            status = handle.status()
            peer_totals, _, _, _ = self._peer_snapshot(handle)
            self._last_peer_totals[lease.lease_id] = peer_totals
            self._last_totals[lease.lease_id] = (
                max(0, int(status.all_time_download)),
                max(0, int(status.all_time_upload)),
            )
        else:
            self._last_peer_totals[lease.lease_id] = {}
            self._last_totals[lease.lease_id] = (0, 0)
        return handle

    def _remove(self, lease_id: str) -> None:
        handle = self._handles.pop(lease_id, None)
        lease = self._leases.get(lease_id)
        if handle is not None:
            if lease_id in self._borrowed_handles and lease is not None:
                with contextlib.suppress(Exception):
                    handle.replace_trackers([])
                    self._release_shared_handle(lease, handle)
            else:
                with contextlib.suppress(Exception):
                    self._session.remove_torrent(handle)
        self._borrowed_handles.discard(lease_id)
        self._leases.pop(lease_id, None)
        self._trackers.pop(lease_id, None)
        self._mappings.pop(lease_id, None)
        self._last_totals.pop(lease_id, None)
        self._last_peer_totals.pop(lease_id, None)

    def _publish_download(self, lease_id: str) -> None:
        lease = self._leases.get(lease_id)
        if not isinstance(lease, DownloadLease):
            return
        self._remove(lease_id)
        self._completed_downloads.add(lease_id)
        self._closure_reason = "download-complete"
        try:
            path = AssetVault(self._vault_root).adopt_staged_asset(
                lease.descriptor,
                lease.digest,
                lease.size_bytes,
                self._staging_path(lease),
                P2P_FORMAT_POLICY_VERSION,
            )
        except (AssetError, OSError, RuntimeError) as error:
            result = _TerminalDownload(lease, "error", error=str(error))
        else:
            result = _TerminalDownload(lease, "complete", path=str(path))
        self._terminal_downloads[lease_id] = result

    def _peer_snapshot(
        self, handle: Any
    ) -> tuple[dict[tuple[str, int, str], tuple[bool, int, int]], int, int, int]:
        totals: dict[tuple[str, int, str], tuple[bool, int, int]] = {}
        peers = download_rate = upload_rate = 0
        for peer in handle.get_peer_info():
            address, port = peer.ip
            address = str(address)
            lan = self._allows_lan_peer(address)
            key = (address, int(port), str(peer.pid))
            totals[key] = (
                lan,
                max(0, int(peer.total_download)),
                max(0, int(peer.total_upload)),
            )
            if not lan:
                peers += 1
                download_rate += max(0, int(peer.payload_down_speed))
                upload_rate += max(0, int(peer.payload_up_speed))
        return totals, peers, download_rate, upload_rate

    @staticmethod
    def _counter_delta(current: int, previous: int) -> int:
        return current if current < previous else current - previous

    def _peer_deltas(
        self,
        current: Mapping[tuple[str, int, str], tuple[bool, int, int]],
        previous: Mapping[tuple[str, int, str], tuple[bool, int, int]],
    ) -> tuple[int, int, int, int]:
        lan_downloaded = lan_uploaded = global_downloaded = global_uploaded = 0
        for key, (lan, downloaded, uploaded) in current.items():
            old = previous.get(key)
            old_downloaded = old[1] if old is not None and old[0] == lan else 0
            old_uploaded = old[2] if old is not None and old[0] == lan else 0
            downloaded_delta = self._counter_delta(downloaded, old_downloaded)
            uploaded_delta = self._counter_delta(uploaded, old_uploaded)
            if lan:
                lan_downloaded += downloaded_delta
                lan_uploaded += uploaded_delta
            else:
                global_downloaded += downloaded_delta
                global_uploaded += uploaded_delta
        return lan_downloaded, lan_uploaded, global_downloaded, global_uploaded

    def maintain(self, *, publish_downloads: bool = True) -> None:
        now = time.monotonic()
        elapsed = max(0, math.floor(now - self._last_tick))
        self._last_tick += elapsed
        counters = self._counters()
        for lease_id, handle in tuple(self._handles.items()):
            lease = self._leases[lease_id]
            # Sample peers first so bytes racing the two reads are charged globally.
            peer_totals, _, _, _ = self._peer_snapshot(handle)
            status = handle.status()
            total_download = max(0, int(status.all_time_download))
            total_upload = max(0, int(status.all_time_upload))
            previous_download, previous_upload = self._last_totals.get(lease_id, (0, 0))
            aggregate_downloaded = self._counter_delta(total_download, previous_download)
            aggregate_uploaded = self._counter_delta(total_upload, previous_upload)
            lan_downloaded, lan_uploaded, global_downloaded, global_uploaded = self._peer_deltas(
                peer_totals, self._last_peer_totals.get(lease_id, {})
            )
            downloaded = max(global_downloaded, aggregate_downloaded - lan_downloaded, 0)
            uploaded = max(global_uploaded, aggregate_uploaded - lan_uploaded, 0)
            active = (
                elapsed
                if isinstance(lease, SeedLease) and status.is_seeding and not status.paused
                else 0
            )
            if downloaded or uploaded or active:
                counters.record_transfer(
                    lease.digest,
                    downloaded_bytes=downloaded,
                    uploaded_bytes=uploaded,
                    active_seed_seconds=active,
                )
            self._last_totals[lease_id] = (total_download, total_upload)
            # The next LAN interval starts after this aggregate boundary.
            self._last_peer_totals[lease_id] = self._peer_snapshot(handle)[0]
            if publish_downloads and isinstance(lease, DownloadLease) and status.is_finished:
                self._publish_download(lease_id)

    def counters(self, digest: str) -> GlobalP2PCounters:
        return self._counters().get(digest)

    def status(self) -> dict[str, object]:
        self.maintain()
        if not self._handles:
            return {
                "active": False,
                "listenPort": None,
                "closureReason": self._closure_reason,
                "networkFeatures": {
                    "dht": False,
                    "pex": False,
                    "tcp": False,
                    "utp": False,
                    "trackers": False,
                    "upnp": False,
                    "natMappings": False,
                    "natPmp": False,
                    "pcp": False,
                },
                "transfers": self._terminal_transfer_rows(),
            }
        applied = self._session.get_settings()
        transfers = []
        for lease_id in sorted(self._handles):
            lease = self._leases[lease_id]
            status = self._handles[lease_id].status()
            _, peers, download_rate, upload_rate = self._peer_snapshot(self._handles[lease_id])
            counter = self.counters(lease.digest)
            transfers.append(
                {
                    "leaseId": lease_id,
                    "digest": lease.digest,
                    "kind": lease.kind,
                    "state": _TRANSFER_STATES.get(str(status.state), "error"),
                    "peers": peers,
                    "downloadRateBytesPerSecond": download_rate,
                    "uploadRateBytesPerSecond": upload_rate,
                    "downloadedBytes": counter.downloaded_bytes,
                    "uploadedBytes": counter.uploaded_bytes,
                    "activeSeedSeconds": counter.active_seed_seconds,
                }
            )
        transfers.extend(self._terminal_transfer_rows())
        natpmp_enabled = bool(applied["enable_natpmp"])
        return {
            "active": True,
            "listenPort": self._session.listen_port() if self._session.is_listening() else None,
            "closureReason": None,
            "networkFeatures": {
                "dht": bool(applied["enable_dht"] or self._session.is_dht_running()),
                "pex": bool(self._handles),
                "tcp": bool(applied["enable_incoming_tcp"] or applied["enable_outgoing_tcp"]),
                "utp": bool(applied["enable_incoming_utp"] or applied["enable_outgoing_utp"]),
                "trackers": any(self._trackers.values()),
                "upnp": bool(applied["enable_upnp"]),
                "natMappings": natpmp_enabled,
                # Libtorrent's combined mapper tries PCP before falling back to NAT-PMP.
                "natPmp": natpmp_enabled,
                "pcp": natpmp_enabled,
            },
            "transfers": transfers,
        }

    def _terminal_transfer_rows(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for lease_id in sorted(self._terminal_downloads):
            result = self._terminal_downloads[lease_id]
            counter = self.counters(result.lease.digest)
            row: dict[str, object] = {
                "leaseId": lease_id,
                "digest": result.lease.digest,
                "kind": result.lease.kind,
                "state": result.state,
                "peers": 0,
                "downloadRateBytesPerSecond": 0,
                "uploadRateBytesPerSecond": 0,
                "downloadedBytes": counter.downloaded_bytes,
                "uploadedBytes": counter.uploaded_bytes,
                "activeSeedSeconds": counter.active_seed_seconds,
            }
            if result.path is not None:
                row["path"] = result.path
            if result.error is not None:
                row["error"] = result.error
            rows.append(row)
        return rows

    def close_transfers(self, *, reason: str | None = None) -> None:
        if reason is not None:
            self._closure_reason = reason
        if self._handles:
            with contextlib.suppress(Exception):
                self.maintain(publish_downloads=False)
        for lease_id, handle in self._handles.items():
            lease = self._leases[lease_id]
            with contextlib.suppress(Exception):
                if lease_id in self._borrowed_handles:
                    handle.replace_trackers([])
                    self._release_shared_handle(lease, handle)
                else:
                    self._session.remove_torrent(handle)
        self._borrowed_handles.clear()
        self._handles.clear()
        self._leases.clear()
        self._trackers.clear()
        self._last_totals.clear()
        self._last_peer_totals.clear()
        self._last_tick = time.monotonic()

    def close(self) -> None:
        self.close_transfers()
        self._mappings.clear()
        self._transfer_policies.clear()
        self._completed_downloads.clear()
        self._terminal_downloads.clear()
        self._budget_exhausted_digests.clear()
        if self._counter_store is not None:
            self._counter_store.close()
            self._counter_store = None
