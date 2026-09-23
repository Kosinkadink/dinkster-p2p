"""The isolated libtorrent session and its authenticated IPC server."""

# pyright: reportUnknownArgumentType=false
# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.metadata
import json
import os
import re
import socket
import stat
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

from dinkster_assets import (
    P2P_FORMAT_POLICY_VERSION,
    P2P_PIECE_LENGTH,
    AssetError,
    AssetVault,
    P2PDescriptorResult,
    P2PPartial,
    P2PStorageError,
    canonical_p2p_info,
    derive_p2p_descriptor,
    verify_p2p_descriptor,
)
from dinkster_assets.p2p_storage import cached_p2p_local_file, verified_p2p_seed_descriptor
from dinkster_workers.boundary import BoundaryError, read_frame, write_frame
from dinkster_workers.transport import connect_endpoint

from .artifacts import LIBTORRENT_VERSION, select_libtorrent_artifact
from .contracts import DownloadLease, P2PLease, P2PLeaseError, SeedLease, lease_from_wire
from .diagnostics import NativeDiagnostics
from .global_leases import validate_global_authorization
from .global_transfers import GlobalTransferController
from .lan import LanNetworkPolicy, current_lan_policy
from .listeners import ListenerBindings
from .settings import default_p2p_settings, normalize_p2p_settings

IPC_VERSION = 4
STATE_VERSION = 6
_LIBTORRENT_NATIVE_VERSION = "2.1.1.0"
_DHT_BOOTSTRAP_NODES = "dht.libtorrent.org:25401"
_GLOBAL_NETWORK_COSTS = frozenset({"metered", "unmetered", "unknown"})
_ACTIVITY_SAMPLE_SECONDS = 1.0
_DIGEST = re.compile(r"^blake3:[0-9a-f]{64}$")
_GRANT_ID = re.compile(r"^[0-9a-f]{64}$")
_TRANSFER_OVERRIDES = frozenset({"paused", "stopped"})
MAX_ACTIVE_DOWNLOADS = 4


class SidecarError(RuntimeError):
    """The sidecar cannot safely fulfill an operation."""


class SidecarConflict(SidecarError):
    """An operation conflicts with the current transfer state."""


class SidecarNotFound(SidecarError):
    """An operation named a transfer that does not exist."""


class StateLockError(SidecarError):
    """Another sidecar owns this vault session."""


@dataclass(slots=True)
class _ActivityRecord:
    digest: str
    size_bytes: int
    downloaded_bytes: int = 0
    uploaded_bytes: int = 0
    state_override: str | None = None
    continuous: bool = False
    seed_uploaded_baseline: int = 0
    seed_active_seconds: int = 0
    seed_seconds_baseline: int = 0
    transport_download_sample: int = 0
    transport_upload_sample: int = 0
    seed_grant_ids: tuple[str, ...] = ()
    global_uploaded_baseline: int = 0
    global_seed_seconds_baseline: int = 0
    global_resume_required: bool = False

    def to_wire(self) -> dict[str, object]:
        return {
            "digest": self.digest,
            "sizeBytes": self.size_bytes,
            "downloadedBytes": self.downloaded_bytes,
            "uploadedBytes": self.uploaded_bytes,
            "stateOverride": self.state_override,
            "continuous": self.continuous,
            "seedUploadedBaseline": self.seed_uploaded_baseline,
            "seedActiveSeconds": self.seed_active_seconds,
            "seedSecondsBaseline": self.seed_seconds_baseline,
            "transportDownloadSample": self.transport_download_sample,
            "transportUploadSample": self.transport_upload_sample,
            "seedGrantIds": list(self.seed_grant_ids),
            "globalUploadedBaseline": self.global_uploaded_baseline,
            "globalSeedSecondsBaseline": self.global_seed_seconds_baseline,
            "globalResumeRequired": self.global_resume_required,
        }

    @classmethod
    def from_wire(cls, value: object, *, version: int) -> _ActivityRecord:
        if not isinstance(value, Mapping):
            raise SidecarError("activity record must be an object")
        body = {str(key): item for key, item in value.items()}
        fields = {
            "digest",
            "sizeBytes",
            "downloadedBytes",
            "uploadedBytes",
            "stateOverride",
            "continuous",
            "seedUploadedBaseline",
            "seedActiveSeconds",
            "seedSecondsBaseline",
        }
        if version >= 3:
            fields |= {"transportDownloadSample", "transportUploadSample"}
        if version >= 4:
            fields.add("seedGrantIds")
        if version >= 5:
            fields |= {"globalUploadedBaseline", "globalSeedSecondsBaseline"}
        if version >= 6:
            fields.add("globalResumeRequired")
        if set(body) != fields:
            raise SidecarError("activity record has an unsupported shape")
        digest = body["digest"]
        state_override = body["stateOverride"]
        counters = (
            body["sizeBytes"],
            body["downloadedBytes"],
            body["uploadedBytes"],
            body["seedUploadedBaseline"],
            body["seedActiveSeconds"],
            body["seedSecondsBaseline"],
        )
        if version >= 3:
            counters += (body["transportDownloadSample"], body["transportUploadSample"])
        if version >= 5:
            counters += (body["globalUploadedBaseline"], body["globalSeedSecondsBaseline"])
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise SidecarError("activity digest must be a canonical BLAKE3 identity")
        if (
            any(type(counter) is not int or counter < 0 for counter in counters)
            or body["sizeBytes"] == 0
            or body["seedUploadedBaseline"] > body["uploadedBytes"]
            or body["seedSecondsBaseline"] > body["seedActiveSeconds"]
        ):
            raise SidecarError("activity counters are malformed")
        if state_override is not None and state_override not in _TRANSFER_OVERRIDES:
            raise SidecarError("activity state override is malformed")
        if not isinstance(body["continuous"], bool):
            raise SidecarError("activity continuous mode is malformed")
        if version >= 6 and not isinstance(body["globalResumeRequired"], bool):
            raise SidecarError("activity global resume requirement is malformed")
        grant_ids_raw = body.get("seedGrantIds", ())
        if (
            not isinstance(grant_ids_raw, Sequence)
            or isinstance(grant_ids_raw, (str, bytes))
            or not all(
                isinstance(item, str) and _GRANT_ID.fullmatch(item) for item in grant_ids_raw
            )
            or len(set(grant_ids_raw)) != len(grant_ids_raw)
        ):
            raise SidecarError("activity seed grant ids are malformed")
        return cls(
            digest=digest,
            size_bytes=body["sizeBytes"],
            downloaded_bytes=body["downloadedBytes"],
            uploaded_bytes=body["uploadedBytes"],
            state_override=state_override,
            continuous=body["continuous"],
            seed_uploaded_baseline=body["seedUploadedBaseline"],
            seed_active_seconds=body["seedActiveSeconds"],
            seed_seconds_baseline=body["seedSecondsBaseline"],
            transport_download_sample=body.get("transportDownloadSample", body["downloadedBytes"]),
            transport_upload_sample=body.get("transportUploadSample", body["uploadedBytes"]),
            seed_grant_ids=tuple(cast("Sequence[str]", grant_ids_raw)),
            global_uploaded_baseline=body.get("globalUploadedBaseline", 0),
            global_seed_seconds_baseline=body.get("globalSeedSecondsBaseline", 0),
            global_resume_required=body.get("globalResumeRequired", False),
        )


@dataclass(frozen=True, slots=True)
class _LiveActivity:
    state: str
    peers: int
    download_rate: int
    upload_rate: int


@dataclass
class _TorrentRuntime:
    lease: P2PLease
    handle: Any
    partial: P2PPartial | None = None
    state: str = "checking"
    error: str | None = None
    durable_pieces: set[int] = field(default_factory=set[int])
    pending_flush: set[int] = field(default_factory=set[int])
    pending_reads: set[int] = field(default_factory=set[int])
    published_path: str | None = None
    stopped: bool = False


class StateLock:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            path.parent.chmod(0o700)
        self._fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.name != "nt":
                os.fchmod(self._fd, 0o600)
            if os.name == "nt":
                import msvcrt

                if os.fstat(self._fd).st_size == 0:
                    os.write(self._fd, b"\0")
                    os.fsync(self._fd)
                os.lseek(self._fd, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                except OSError as error:
                    raise StateLockError("another sidecar owns this vault session") from error
            else:
                import fcntl

                try:
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    raise StateLockError("another sidecar owns this vault session") from error
        except BaseException:
            os.close(self._fd)
            raise

    def close(self) -> None:
        if self._fd < 0:
            return
        if os.name == "nt":
            import msvcrt

            os.lseek(self._fd, 0, os.SEEK_SET)
            with contextlib.suppress(OSError):
                msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            with contextlib.suppress(OSError):
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        os.close(self._fd)
        self._fd = -1


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + ".tmp")
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def _quarantine(path: Path) -> str | None:
    if not path.exists():
        return None
    destination = path.with_name(f"{path.name}.corrupt-{time.time_ns()}")
    os.replace(path, destination)
    return destination.name


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    body: dict[str, object] = {}
    for key, value in pairs:
        if key in body:
            raise ValueError(f"duplicate JSON key: {key!r}")
        body[key] = value
    return body


def _load_libtorrent() -> Any:
    select_libtorrent_artifact()
    installed = importlib.metadata.version("libtorrent")
    if installed != LIBTORRENT_VERSION:
        raise SidecarError(
            f"libtorrent runtime is {installed}, expected the pinned {LIBTORRENT_VERSION}"
        )
    import libtorrent as libtorrent

    if libtorrent.version != _LIBTORRENT_NATIVE_VERSION:
        raise SidecarError(
            f"libtorrent native runtime is {libtorrent.version}, "
            f"expected {_LIBTORRENT_NATIVE_VERSION}"
        )
    return libtorrent


@dataclass(frozen=True, slots=True)
class P2PSessionPlan:
    """Network features applied to the shared LAN and global P2P session."""

    lan_active: bool = False
    global_dht: bool = False
    global_trackers: bool = False
    global_pex: bool = False
    global_tcp: bool = False
    global_utp: bool = False
    global_nat_mapping: bool = False
    dht_bootstrap_nodes: str = ""

    def __post_init__(self) -> None:
        if self.dht_bootstrap_nodes != self.dht_bootstrap_nodes.strip():
            raise ValueError("DHT bootstrap nodes must be trimmed")
        if self.dht_bootstrap_nodes and not self.global_dht:
            raise ValueError("DHT bootstrap nodes require global DHT")
        if self.global_active and not (self.global_tcp or self.global_utp):
            raise ValueError("global features require TCP or uTP")
        if self.lan_active and self.global_active and not self.global_tcp:
            raise ValueError("global features require TCP while LAN is active")

    @property
    def global_active(self) -> bool:
        return any(
            (
                self.global_dht,
                self.global_trackers,
                self.global_pex,
                self.global_tcp,
                self.global_utp,
                self.global_nat_mapping,
            )
        )

    def close_global(self) -> P2PSessionPlan:
        """Close internet features without changing LAN availability."""
        return P2PSessionPlan(lan_active=self.lan_active)


def session_settings(
    settings: Mapping[str, object],
    policy: LanNetworkPolicy,
    plan: P2PSessionPlan,
) -> dict[str, object]:
    """Translate one shared session plan into libtorrent settings."""
    global_active = plan.global_active
    lan_active = plan.lan_active and bool(policy.interfaces)
    listen = (
        f"0.0.0.0:{settings.get('listenPort', 0)}"
        if global_active
        else ",".join(f"{address}:{settings.get('listenPort', 0)}l" for address in policy.addresses)
        if lan_active
        else ""
    )
    return {
        "listen_interfaces": listen,
        "outgoing_interfaces": "" if global_active else ",".join(policy.addresses),
        "listen_system_port_fallback": False,
        "max_retry_port_bind": 0,
        "enable_dht": plan.global_dht,
        "enable_lsd": lan_active,
        "enable_upnp": plan.global_nat_mapping,
        "enable_natpmp": plan.global_nat_mapping,
        "enable_incoming_tcp": lan_active or plan.global_tcp,
        "enable_outgoing_tcp": lan_active or plan.global_tcp,
        "enable_incoming_utp": plan.global_utp,
        "enable_outgoing_utp": plan.global_utp,
        "dht_bootstrap_nodes": plan.dht_bootstrap_nodes,
        "use_dht_as_fallback": False,
        "apply_filter_to_dht": not plan.global_dht,
        "apply_ip_filter_to_trackers": not plan.global_trackers,
        "announce_to_all_trackers": False,
        "announce_to_all_tiers": False,
        "download_rate_limit": settings["internetDownloadBytesPerSecond"],
        "upload_rate_limit": settings["internetUploadBytesPerSecond"],
        "local_download_rate_limit": settings["lanDownloadBytesPerSecond"],
        "local_upload_rate_limit": settings["lanUploadBytesPerSecond"],
    }


def safe_session_settings(
    settings: Mapping[str, object],
    policy: LanNetworkPolicy | None = None,
) -> dict[str, object]:
    policy = policy or current_lan_policy()
    return session_settings(settings, policy, P2PSessionPlan())


def torrent_flags_for_plan(
    libtorrent: Any,
    plan: P2PSessionPlan,
    *,
    scope: str,
) -> int:
    """Restrict one torrent to the features authorized by its scope and plan."""
    flags = libtorrent.torrent_flags.override_web_seeds
    global_scope = scope == "lan-and-internet" and plan.global_active
    if not global_scope:
        flags |= libtorrent.torrent_flags.apply_ip_filter
    if not global_scope or not plan.global_dht:
        flags |= libtorrent.torrent_flags.disable_dht
    if not global_scope or not plan.global_pex:
        flags |= libtorrent.torrent_flags.disable_pex
    if not global_scope or not plan.global_trackers:
        flags |= libtorrent.torrent_flags.override_trackers
    return int(flags)


def apply_session_plan(
    session: Any,
    libtorrent: Any,
    settings: Mapping[str, object],
    policy: LanNetworkPolicy,
    plan: P2PSessionPlan,
    *,
    listeners: ListenerBindings | None = None,
) -> None:
    """Apply settings and peer admission for one shared libtorrent session."""
    applied = session_settings(settings, policy, plan)
    applied["listen_interfaces"] = (listeners or ListenerBindings()).configure(
        cast(str, applied["listen_interfaces"])
    )
    session.apply_settings(applied)
    ip_filter = libtorrent.ip_filter()
    ip_filter.add_rule("0.0.0.0", "255.255.255.255", 1)
    for interface in policy.interfaces:
        ip_filter.add_rule(
            str(interface.network.network_address),
            str(interface.network.broadcast_address),
            0,
        )
    session.set_ip_filter(ip_filter)


def _new_session(
    libtorrent: Any,
    settings: Mapping[str, object],
    policy: LanNetworkPolicy,
) -> Any:
    # The paused flag omits default features and plugins, including PEX, while
    # preventing traffic until restored state has been validated and restricted.
    session = libtorrent.session(
        safe_session_settings(settings, policy), libtorrent.session_flags_t.paused
    )
    session.apply_settings(
        {
            "alert_mask": int(
                libtorrent.alert.category_t.error_notification
                | libtorrent.alert.category_t.status_notification
                | libtorrent.alert.category_t.storage_notification
                | libtorrent.alert.category_t.piece_progress_notification
                | libtorrent.alert.category_t.peer_notification
                | libtorrent.alert.category_t.connect_notification
            )
        }
    )
    session.add_extension("ut_metadata")
    apply_session_plan(session, libtorrent, settings, policy, P2PSessionPlan())
    return session


def _validate_resume_state(value: object, policy: LanNetworkPolicy) -> dict[bytes, object]:
    if not isinstance(value, Mapping) or set(value) != {b"settings"}:
        raise SidecarError("resume state must contain only libtorrent settings")
    settings = value[b"settings"]
    if not isinstance(settings, Mapping):
        raise SidecarError("resume state settings must be an object")
    settings = dict(settings)
    legacy_listen = ",".join(f"{address}:0l" for address in policy.addresses).encode("ascii")
    if settings.get(b"listen_interfaces") == legacy_listen:
        # Persisted port-zero listeners must not open before policy and port validation.
        settings[b"listen_interfaces"] = b""
    safe = safe_session_settings(default_p2p_settings(), policy)
    allowed = {key.encode("ascii") for key in safe}
    if not set(settings) <= allowed:
        raise SidecarError("resume state contains an unsafe libtorrent setting")
    required_values = {
        key.encode("ascii"): value.encode("ascii") if isinstance(value, str) else int(value)
        for key, value in safe.items()
        if isinstance(value, (bool, str))
    }
    # Outgoing selectors describe the current topology, not authoritative resume data.
    settings[b"outgoing_interfaces"] = required_values[b"outgoing_interfaces"]
    if any(
        key in settings and settings[key] != expected for key, expected in required_values.items()
    ):
        raise SidecarError("resume state weakens the safe libtorrent settings")
    return {b"settings": settings}


class SidecarRuntime:
    def __init__(
        self,
        *,
        state_root: Path,
        vault_root: Path,
        installation_root: Path | None,
        settings: object,
        network_paused: bool = False,
    ) -> None:
        self.state_root = state_root.resolve()
        self.vault_root = vault_root.resolve()
        self.installation_root = installation_root.resolve() if installation_root else None
        self.settings = normalize_p2p_settings(settings)
        if not self.settings["downloadsEnabled"] and not self.settings["seedingEnabled"]:
            raise SidecarError("sidecar startup requires an enabled P2P capability")
        self.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != "nt":
            self.state_root.chmod(0o700)
        self._lock = StateLock(self.state_root / "session.lock")
        self._state_path = self.state_root / "state.json"
        self._resume_path = self.state_root / "session.resume"
        self._recovery: dict[str, object] | None = None
        self._leases: dict[str, P2PLease] = {}
        self._global_trackers: dict[str, tuple[str, ...]] = {}
        self._activity: dict[str, _ActivityRecord] = {}
        self._live_activity: dict[str, _LiveActivity] = {}
        self._torrents: dict[str, _TorrentRuntime] = {}
        self._seed_active_at: dict[str, float] = {}
        self._paused = False
        self._network_paused = network_paused
        self._global_network_closure_reason: str | None = None
        self._session_plan = P2PSessionPlan(lan_active=True)
        self._diagnostics = NativeDiagnostics()
        self._listener_errors: list[str] = []
        self._listeners = ListenerBindings(self._record_listener_error)
        self._alert_batch_active = False
        self._global_pex_loaded = False
        self._session: Any = None
        self._global: GlobalTransferController | None = None
        try:
            self._lt = _load_libtorrent()
            self._network_policy = current_lan_policy()
            self._vault = AssetVault(self.vault_root)
            self._session = _new_session(self._lt, self.settings, self._network_policy)
            self._restore()
            if self._network_paused and self._activity:
                self._latch_network_pause()
                self._save_metadata_state()
            self._global = GlobalTransferController(
                self._lt,
                self._session,
                state_root=self.state_root,
                vault_root=self.vault_root,
                torrent_flags=self._torrent_flags,
                shared_handle_for=self._shared_handle_for_global,
                release_shared_handle=self._release_shared_global_handle,
                allows_lan_peer=self._network_policy.allows_peer,
                admit_download=self._require_staging_budget,
            )
            self._apply_settings()
        except BaseException:
            self._close_session()
            self._lock.close()
            raise

    def _restore(self) -> None:
        quarantined: list[str] = []
        try:
            if self._state_path.exists():
                raw = json.loads(
                    self._state_path.read_text("utf-8"),
                    object_pairs_hook=_unique_json_object,
                    parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
                )
                if not isinstance(raw, Mapping):
                    raise SidecarError("state must be an object")
                body = {str(key): item for key, item in raw.items()}
                expected = {
                    "version",
                    "installationRoot",
                    "vaultRoot",
                    "paused",
                    "settings",
                    "leases",
                }
                version = body.get("version")
                if type(version) is not int or version not in {1, 2, 3, 4, 5, STATE_VERSION}:
                    raise SidecarError("state has an unsupported shape or version")
                if set(body) != (expected if version == 1 else expected | {"activity"}):
                    raise SidecarError("state has an unsupported shape or version")
                if body["vaultRoot"] != str(self.vault_root) or body["installationRoot"] != (
                    str(self.installation_root) if self.installation_root else None
                ):
                    raise SidecarError("state belongs to another installation or vault")
                if not isinstance(body["paused"], bool) or not isinstance(body["leases"], list):
                    raise SidecarError("state pause or lease data is malformed")
                restored: list[P2PLease] = []
                discarded_lease_ids: list[str] = []
                for value in body["leases"]:
                    try:
                        lease = lease_from_wire(value)
                        if lease.scope == "lan-only":
                            restored.append(lease)
                    except P2PLeaseError as error:
                        if version >= 4 or not isinstance(value, Mapping):
                            raise
                        lease_body = {
                            str(key): item
                            for key, item in cast("Mapping[object, object]", value).items()
                        }
                        legacy_ids = lease_body.get("grantIds")
                        if (
                            lease_body.get("kind") != "seed"
                            or not isinstance(legacy_ids, Sequence)
                            or isinstance(legacy_ids, (str, bytes))
                            or not legacy_ids
                            or not all(isinstance(item, str) and item for item in legacy_ids)
                            or len(set(cast("Sequence[str]", legacy_ids))) != len(legacy_ids)
                        ):
                            raise
                        legacy_seed = lease_from_wire({**lease_body, "grantIds": ["0" * 64]})
                        if not isinstance(legacy_seed, SeedLease):
                            raise SidecarError(
                                "legacy seed lease migration produced an invalid lease"
                            ) from error
                        self._verify_seed(legacy_seed)
                        discarded_lease_ids.append(legacy_seed.lease_id)
                lease_ids = [lease.lease_id for lease in restored] + discarded_lease_ids
                if len(set(lease_ids)) != len(lease_ids):
                    raise SidecarError("state contains duplicate lease IDs")
                for lease in restored:
                    if isinstance(lease, SeedLease):
                        self._verify_seed(lease)
                normalize_p2p_settings(body["settings"])
                self._paused = body["paused"]
                self._leases = {lease.lease_id: lease for lease in restored}
                if version >= 2:
                    if not isinstance(body["activity"], list):
                        raise SidecarError("state activity data is malformed")
                    activity = [
                        _ActivityRecord.from_wire(value, version=version)
                        for value in body["activity"]
                    ]
                    if len({record.digest for record in activity}) != len(activity):
                        raise SidecarError("state contains duplicate activity digests")
                    self._activity = {record.digest: record for record in activity}
                for lease in restored:
                    self._ensure_activity(lease)
            if self._resume_path.exists():
                decoded = self._lt.bdecode(self._resume_path.read_bytes())
                decoded = _validate_resume_state(decoded, self._network_policy)
                self._session.load_state(decoded, self._lt.save_state_flags_t.save_settings)
        except (
            OSError,
            ValueError,
            TypeError,
            UnicodeError,
            RecursionError,
            RuntimeError,
            SidecarError,
        ) as error:
            for path in (self._state_path, self._resume_path):
                if name := _quarantine(path):
                    quarantined.append(name)
            self._leases.clear()
            self._activity.clear()
            self._paused = True
            self._session = _new_session(self._lt, self.settings, self._network_policy)
            self._recovery = {
                "state": "corrupt-state-quarantined",
                "files": quarantined,
                "error": str(error),
            }

    def _apply_settings(self, *, strict_global: bool = False) -> None:
        self._apply_global_settings(strict=strict_global)
        self._apply_session_plan(self._session_plan)
        self._apply_torrent_policy()

    def _apply_session_plan(self, plan: P2PSessionPlan) -> None:
        if plan.global_active and self.settings["scope"] != "lan-and-internet":
            raise SidecarError("global session features require lan-and-internet scope")
        self._session_plan = plan
        plan = P2PSessionPlan() if self._paused or self._network_paused else self._session_plan
        desired_interfaces = cast(
            str, session_settings(self.settings, self._network_policy, plan)["listen_interfaces"]
        )
        if self._listeners.requires_closed_transition(desired_interfaces):
            self._close_and_drain_listener_template()
        apply_session_plan(
            self._session,
            self._lt,
            self.settings,
            self._network_policy,
            plan,
            listeners=self._listeners,
        )
        self._diagnostics.configure_listeners(self._listeners.interfaces)
        mask = int(
            self._lt.torrent_flags.apply_ip_filter
            | self._lt.torrent_flags.disable_dht
            | self._lt.torrent_flags.disable_pex
            | self._lt.torrent_flags.override_trackers
            | self._lt.torrent_flags.override_web_seeds
        )
        for torrent in self._torrents.values():
            if not torrent.stopped:
                scope = (
                    "lan-and-internet"
                    if self._global is not None and self._global.owns(torrent.handle)
                    else torrent.lease.scope
                )
                torrent.handle.set_flags(
                    torrent_flags_for_plan(self._lt, plan, scope=scope),
                    mask,
                )

    def _close_and_drain_listener_template(self) -> None:
        if self._alert_batch_active:
            raise SidecarError("listener template transition cannot drain a borrowed alert batch")
        self._listeners.configure("")
        self._session.apply_settings({"listen_interfaces": ""})
        if self._session.get_settings()["listen_interfaces"] != "":
            raise SidecarError("libtorrent did not close the previous listener template")
        self._alert_batch_active = True
        try:
            for alert in self._session.pop_alerts():
                self._handle_alert(alert)
        finally:
            self._alert_batch_active = False
        self._listeners = ListenerBindings(self._record_listener_error)

    def _apply_torrent_policy(self) -> None:
        if self._paused or self._network_paused:
            self._session.pause()
        else:
            self._session.resume()
            for torrent in self._torrents.values():
                if torrent.stopped:
                    continue
                authorized = any(
                    isinstance(lease, type(torrent.lease))
                    and lease.digest == torrent.lease.digest
                    and self._lease_authorized(lease)
                    for lease in self._leases.values()
                )
                record = self._activity[torrent.lease.digest]
                if authorized and record.state_override not in {"paused", "stopped"}:
                    torrent.handle.resume()
                else:
                    self._pause_handle(torrent.handle)

    def _set_global_network_plan(self, active: bool, trackers: bool) -> None:
        if not active and (self._paused or self._network_paused):
            return
        plan = P2PSessionPlan(lan_active=True)
        if active:
            if not self._global_pex_loaded:
                self._session.add_extension("ut_pex")
                self._global_pex_loaded = True
            plan = P2PSessionPlan(
                lan_active=True,
                global_dht=True,
                global_trackers=trackers,
                global_pex=True,
                global_tcp=True,
                global_utp=True,
                global_nat_mapping=True,
                dht_bootstrap_nodes=_DHT_BOOTSTRAP_NODES,
            )
        if plan != self._session_plan:
            self.apply_session_plan(plan)

    def _apply_global_settings(self, *, strict: bool = False) -> None:
        self._enforce_staging_budget()
        global_transfers = self._global
        if global_transfers is not None:
            try:
                for digest, record in self._activity.items():
                    global_transfers.set_transfer_policy(
                        digest,
                        enabled=record.state_override is None,
                        continuous=record.continuous,
                        uploaded_baseline=record.global_uploaded_baseline,
                        active_seed_seconds_baseline=record.global_seed_seconds_baseline,
                        resume_required=record.global_resume_required,
                    )
                global_transfers.reconcile(
                    tuple(self._leases.values()),
                    self.settings,
                    trackers=self._global_trackers,
                    closure_reason=(
                        "paused"
                        if self._paused or self._network_paused
                        else self._global_network_closure_reason
                    ),
                    apply_network_plan=self._set_global_network_plan,
                )
                budget_latched = False
                for digest in global_transfers.budget_exhausted_digests:
                    record = self._activity[digest]
                    if not record.global_resume_required:
                        record.global_resume_required = True
                        budget_latched = True
                if budget_latched:
                    self._save_metadata_state()
                if (
                    self._recovery is not None
                    and self._recovery.get("state") == "global-session-closed"
                ):
                    self._recovery = None
            except Exception as error:
                global_transfers.close_transfers(reason="session-error")
                self._set_global_network_plan(False, False)
                self._recovery = {
                    "state": "global-session-closed",
                    "files": [],
                    "error": str(error),
                }
                if strict:
                    raise

    def apply_session_plan(self, plan: P2PSessionPlan) -> None:
        """Apply authorized global features without replacing the LAN session."""
        self._apply_session_plan(plan)
        self._apply_torrent_policy()

    def _state_wire(self) -> dict[str, object]:
        return {
            "version": STATE_VERSION,
            "installationRoot": str(self.installation_root) if self.installation_root else None,
            "vaultRoot": str(self.vault_root),
            "paused": self._paused,
            "settings": dict(self.settings),
            "leases": [
                self._leases[key].to_wire()
                for key in sorted(self._leases)
                if self._leases[key].scope == "lan-only"
            ],
            "activity": [self._activity[key].to_wire() for key in sorted(self._activity)],
        }

    def _save_metadata_state(self) -> None:
        _atomic_write(
            self._state_path,
            (json.dumps(self._state_wire(), sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )

    def save_state(self) -> None:
        self._save_metadata_state()
        safe_settings: dict[bytes, bytes | int] = {}
        for key, value in safe_session_settings(self.settings, self._network_policy).items():
            if isinstance(value, str):
                encoded: bytes | int = value.encode("ascii")
            elif isinstance(value, bool):
                encoded = int(value)
            elif isinstance(value, int):
                encoded = value
            else:
                raise SidecarError("safe libtorrent setting has an unsupported value")
            safe_settings[key.encode("ascii")] = encoded
        _atomic_write(
            self._resume_path,
            bytes(self._lt.bencode({b"settings": safe_settings})),
        )

    def _ensure_activity(self, lease: P2PLease) -> _ActivityRecord:
        record = self._activity.get(lease.digest)
        if record is None:
            record = _ActivityRecord(digest=lease.digest, size_bytes=lease.size_bytes)
            self._activity[lease.digest] = record
        elif record.size_bytes != lease.size_bytes:
            raise SidecarConflict("digest is already bound to a different asset size")
        if isinstance(lease, SeedLease):
            record.seed_grant_ids = tuple(sorted(set(record.seed_grant_ids) | set(lease.grant_ids)))
        return record

    def _torrent_flags(self, lease: P2PLease) -> int:
        plan = P2PSessionPlan() if self._paused or self._network_paused else self._session_plan
        return torrent_flags_for_plan(
            self._lt,
            plan,
            scope=lease.scope,
        )

    def _budget_downloads(self) -> dict[str, DownloadLease]:
        downloads: dict[str, DownloadLease] = {}
        for lease in self._leases.values():
            if not isinstance(lease, DownloadLease) or not self._lease_authorized(lease):
                continue
            if self._activity[lease.digest].state_override is not None:
                continue
            torrent = self._torrents.get(lease.lease_id)
            if torrent is not None and torrent.stopped:
                continue
            if torrent is None and lease.scope == "lan-only" and self._vault.has(lease.digest):
                continue
            if self._global is not None and self._global.download_finished(lease.lease_id):
                continue
            downloads[lease.digest] = lease
        return downloads

    def _download_growth(self, lease: DownloadLease) -> int:
        expected = f"{lease.descriptor.info_hash}/{lease.digest.removeprefix('blake3:')}"
        if lease.staging_path != expected:
            raise SidecarError("download stagingPath does not match its descriptor and digest")
        return self._vault.p2p_partial_growth(lease.descriptor, lease.digest, lease.size_bytes)

    def _require_staging_budget(self, lease: DownloadLease) -> None:
        budget = cast(int, self.settings["stagingBudgetBytes"])
        if budget < lease.size_bytes:
            raise SidecarConflict("download staging budget is exhausted")
        downloads = self._budget_downloads()
        downloads[lease.digest] = lease
        growth = sum(self._download_growth(current) for current in downloads.values())
        # Sample aggregate usage last so concurrent writes cannot be credited
        # against a stale, smaller usage sample.
        if self._vault.p2p_staging_usage().actual_bytes + growth > budget:
            raise SidecarConflict("download staging budget is exhausted")

    def _enforce_staging_budget(self) -> None:
        downloads = self._budget_downloads()
        if not downloads:
            return
        budget = cast(int, self.settings["stagingBudgetBytes"])
        growth = {digest: self._download_growth(lease) for digest, lease in downloads.items()}
        reserved = self._vault.p2p_staging_usage().actual_bytes
        changed = False
        for digest, remaining in growth.items():
            if budget > 0 and reserved + remaining <= budget:
                reserved += remaining
                continue
            self._activity[digest].state_override = "paused"
            for handle in self._torrent_handles(digest):
                self._pause_handle(handle)
            changed = True
        if changed:
            self._save_metadata_state()

    def _shared_handle_for_global(self, lease: P2PLease) -> Any | None:
        torrent = self._torrent_for_digest(lease.digest)
        if torrent is None:
            return None
        local = torrent.lease
        if not (
            isinstance(lease, SeedLease)
            and isinstance(local, SeedLease)
            and local.size_bytes == lease.size_bytes
            and local.descriptor == lease.descriptor
            and local.local_path == lease.local_path
        ):
            raise SidecarError("global lease conflicts with an active LAN torrent")
        return torrent.handle

    def _release_shared_global_handle(self, lease: P2PLease, handle: Any) -> None:
        if not any(
            current.scope == "lan-only"
            and isinstance(current, type(lease))
            and current.digest == lease.digest
            and self._lease_authorized(current)
            for current in self._leases.values()
        ):
            torrent = self._torrent_for_digest(lease.digest)
            if torrent is not None and torrent.handle == handle:
                self._remove_torrent(torrent.lease.lease_id)
            return
        status = handle.status()
        record = self._activity[lease.digest]
        record.transport_download_sample = max(
            record.transport_download_sample,
            max(0, int(status.all_time_download)),
        )
        record.transport_upload_sample = max(
            record.transport_upload_sample,
            max(0, int(status.all_time_upload)),
        )
        self._live_activity.pop(lease.digest, None)

    def _activate_lease(
        self,
        lease: P2PLease,
        seed_descriptor: P2PDescriptorResult | None = None,
        shared_handle: Any | None = None,
    ) -> _TorrentRuntime:
        current = self._torrents.get(lease.lease_id)
        if current is not None:
            if current.lease != lease:
                raise SidecarError("leaseId is already bound to a different torrent")
            return current
        if any(torrent.lease.digest == lease.digest for torrent in self._torrents.values()):
            raise SidecarError("one active torrent per digest is permitted")

        if isinstance(lease, DownloadLease):
            self._require_staging_budget(lease)
        params = self._lt.add_torrent_params()
        params.flags = self._torrent_flags(lease)
        params.storage_mode = self._lt.storage_mode_t.storage_mode_sparse
        params.trackers = []
        params.url_seeds = []
        params.http_seeds = []
        partial = None
        if isinstance(lease, SeedLease):
            derived = seed_descriptor or derive_p2p_descriptor(lease.local_path)
            if (
                derived.asset_digest != lease.digest
                or derived.size != lease.size_bytes
                or derived.descriptor != lease.descriptor
            ):
                raise SidecarError("seed lease descriptor changed during activation")
            # Failed seed verification must not download repairs into the source file.
            params.flags |= self._lt.torrent_flags.seed_mode | self._lt.torrent_flags.upload_mode
            metadata: dict[bytes, object] = {b"info": self._lt.bdecode(derived.info)}
            if derived.piece_layer:
                metadata[b"piece layers"] = {
                    bytes.fromhex(derived.descriptor.file_root): derived.piece_layer
                }
            params.ti = self._lt.torrent_info(self._lt.bencode(metadata))
            params.save_path = str(self.state_root / "seed-files")
            params.renamed_files = {0: str(lease.local_path)}
        else:
            expected_staging = (
                f"{lease.descriptor.info_hash}/{lease.digest.removeprefix('blake3:')}"
            )
            if lease.staging_path != expected_staging:
                raise SidecarError("download stagingPath does not match its descriptor and digest")
            partial = self._vault.open_p2p_partial(
                lease.descriptor,
                lease.digest,
                lease.size_bytes,
            )
            params = self._lt.parse_magnet_uri(
                f"magnet:?xt=urn:btmh:1220{lease.descriptor.info_hash}"
            )
            params.flags = self._torrent_flags(lease)
            params.storage_mode = self._lt.storage_mode_t.storage_mode_sparse
            params.save_path = str(partial.path.parent)
            params.trackers = []
            params.url_seeds = []
            params.http_seeds = []
            self._require_staging_budget(lease)
        if shared_handle is None:
            try:
                handle = self._session.add_torrent(params)
            except RuntimeError as error:
                raise SidecarError(f"could not activate P2P lease: {error}") from error
        else:
            handle = shared_handle
        runtime = _TorrentRuntime(lease, handle, partial)
        self._torrents[lease.lease_id] = runtime
        return runtime

    def _torrent_for_digest(self, digest: str) -> _TorrentRuntime | None:
        return next(
            (torrent for torrent in self._torrents.values() if torrent.lease.digest == digest),
            None,
        )

    def _remove_torrent(self, lease_id: str) -> None:
        torrent = self._torrents.pop(lease_id, None)
        if torrent is not None:
            self._stop_torrent(torrent)

    def _stop_torrent(self, torrent: _TorrentRuntime) -> None:
        if torrent.stopped:
            return
        self._diagnostics.stopped(torrent.lease.digest)
        with contextlib.suppress(RuntimeError):
            if torrent.handle.is_valid():
                self._session.remove_torrent(torrent.handle)
        torrent.stopped = True

    def _fail_torrent(self, torrent: _TorrentRuntime, error: object) -> None:
        torrent.state = "failed"
        torrent.error = str(error)
        self._stop_torrent(torrent)

    @staticmethod
    def _asset_piece_count(lease: DownloadLease) -> int:
        return (lease.size_bytes + P2P_PIECE_LENGTH - 1) // P2P_PIECE_LENGTH

    def _torrent_for_alert(self, alert: Any) -> _TorrentRuntime | None:
        handle = getattr(alert, "handle", None)
        if handle is None:
            return None
        return next(
            (
                torrent
                for torrent in self._torrents.values()
                if not torrent.stopped and torrent.handle.is_valid() and torrent.handle == handle
            ),
            None,
        )

    def _validate_download_metadata(self, torrent: _TorrentRuntime) -> None:
        lease = torrent.lease
        if not isinstance(lease, DownloadLease):
            return
        info = bytes(torrent.handle.torrent_file().info_section())
        expected = canonical_p2p_info(
            asset_digest=lease.digest,
            size=lease.size_bytes,
            file_root=lease.descriptor.file_root,
        )
        if info != expected:
            raise SidecarError("received torrent metadata is not the canonical descriptor info")
        if torrent.handle.trackers() or torrent.handle.url_seeds() or torrent.handle.http_seeds():
            raise SidecarError("received torrent metadata introduced a remote transport")

    def _request_durable_pieces(self, torrent: _TorrentRuntime, pieces: set[int]) -> None:
        if not pieces:
            return
        torrent.pending_flush.update(pieces)
        torrent.handle.flush_cache()

    def _record_listener_error(self, message: str) -> None:
        event = self._diagnostics.selection_failed()
        self._listener_errors = (self._listener_errors + [json.dumps(event)])[-8:]

    def _handle_alert(self, alert: Any) -> None:
        torrent = self._torrent_for_alert(alert)
        event = self._diagnostics.observe_alert(
            alert, self._lt, torrent.lease.digest if torrent is not None else None
        )
        if isinstance(alert, self._lt.listen_succeeded_alert):
            if alert.socket_type == self._lt.socket_type_t.tcp:
                self._listeners.tcp_succeeded(alert.address, alert.port)
            return
        if isinstance(alert, self._lt.listen_failed_alert):
            if event is not None:
                self._listener_errors = (self._listener_errors + [json.dumps(event)])[-8:]
            if alert.socket_type in (self._lt.socket_type_t.tcp, self._lt.socket_type_t.udp):
                if self._listeners.failed(
                    alert.address,
                    alert.port,
                    alert.error.value(),
                    tcp=alert.socket_type == self._lt.socket_type_t.tcp,
                ):
                    self._session.apply_settings({"listen_interfaces": self._listeners.interfaces})
                    self._diagnostics.configure_listeners(self._listeners.interfaces)
            return
        if torrent is None:
            return
        if (
            isinstance(alert, self._lt.hash_failed_alert)
            and isinstance(torrent.lease, DownloadLease)
            and torrent.handle.status().total_failed_bytes == 0
            and alert.piece_index
            not in torrent.durable_pieces | torrent.pending_flush | torrent.pending_reads
            and torrent.partial is not None
        ):
            # BEP 52 checking may reject preallocated bytes before hashes arrive;
            # libtorrent counts failed peer data, but not existing disk data.
            try:
                retained = torrent.partial.completed_ranges
            except (OSError, P2PStorageError) as error:
                self._fail_torrent(torrent, error)
                return
            offset = int(alert.piece_index) * P2P_PIECE_LENGTH
            if not any(
                start < offset + P2P_PIECE_LENGTH and end > offset for start, end in retained
            ):
                return
        if isinstance(
            alert,
            (
                self._lt.metadata_failed_alert,
                self._lt.torrent_error_alert,
                self._lt.file_error_alert,
                self._lt.hash_failed_alert,
            ),
        ):
            self._fail_torrent(torrent, alert.message())
            return
        if isinstance(alert, self._lt.metadata_received_alert):
            try:
                self._validate_download_metadata(torrent)
            except (AssetError, RuntimeError, SidecarError) as error:
                self._fail_torrent(torrent, error)
            else:
                torrent.state = "downloading"
            return
        if isinstance(alert, self._lt.torrent_checked_alert):
            lease = torrent.lease
            if isinstance(lease, DownloadLease) and torrent.partial is not None:
                try:
                    durable_ranges = torrent.partial.completed_ranges
                    durable = {
                        index
                        for index in range(self._asset_piece_count(lease))
                        if any(
                            start <= index * P2P_PIECE_LENGTH
                            and end >= min((index + 1) * P2P_PIECE_LENGTH, lease.size_bytes)
                            for start, end in durable_ranges
                        )
                        and torrent.handle.have_piece(index)
                    }
                    torrent.durable_pieces = durable
                    verified = {
                        index
                        for index in range(self._asset_piece_count(lease))
                        if torrent.handle.have_piece(index) and index not in durable
                    }
                    self._request_durable_pieces(torrent, verified)
                except (OSError, RuntimeError, P2PStorageError) as error:
                    self._fail_torrent(torrent, error)
            return
        if isinstance(alert, self._lt.piece_finished_alert):
            if isinstance(torrent.lease, DownloadLease):
                self._request_durable_pieces(torrent, {int(alert.piece_index)})
            return
        if isinstance(alert, self._lt.cache_flushed_alert):
            pieces = torrent.pending_flush - torrent.pending_reads
            torrent.pending_flush.clear()
            for piece in sorted(pieces):
                torrent.pending_reads.add(piece)
                torrent.handle.read_piece(piece)
            return
        if isinstance(alert, self._lt.read_piece_alert):
            self._record_durable_piece(torrent, alert)

    def _record_durable_piece(self, torrent: _TorrentRuntime, alert: Any) -> None:
        lease = torrent.lease
        partial = torrent.partial
        if not isinstance(lease, DownloadLease) or partial is None:
            return
        piece = int(alert.piece)
        torrent.pending_reads.discard(piece)
        if alert.error.value() != 0:
            self._fail_torrent(torrent, alert.error.message())
            return
        expected = min(P2P_PIECE_LENGTH, lease.size_bytes - piece * P2P_PIECE_LENGTH)
        data = bytes(alert.buffer)
        if expected <= 0 or len(data) < expected:
            self._fail_torrent(torrent, "libtorrent returned a truncated verified piece")
            return
        try:
            partial.write_piece(piece * P2P_PIECE_LENGTH, data[:expected])
        except (OSError, P2PStorageError) as error:
            self._fail_torrent(torrent, error)
            return
        torrent.durable_pieces.add(piece)
        torrent.state = "downloading"
        if len(torrent.durable_pieces) == self._asset_piece_count(lease):
            if not all(torrent.handle.have_piece(index) for index in torrent.durable_pieces):
                self._fail_torrent(torrent, "durable P2P pieces are not held by libtorrent")
                return
            torrent.state = "publishing"
            self._stop_torrent(torrent)

    def _publish_downloads(self) -> None:
        for torrent in self._torrents.values():
            if torrent.state != "publishing":
                continue
            lease = torrent.lease
            partial = torrent.partial
            assert isinstance(lease, DownloadLease) and partial is not None
            try:
                verify_p2p_descriptor(
                    partial.path,
                    lease.descriptor,
                    asset_digest=lease.digest,
                    size=lease.size_bytes,
                )
                path = self._vault.adopt_staged_asset(
                    lease.descriptor,
                    lease.digest,
                    lease.size_bytes,
                    partial.path,
                    P2P_FORMAT_POLICY_VERSION,
                )
            except (AssetError, OSError, RuntimeError) as error:
                self._fail_torrent(torrent, error)
            else:
                torrent.state = "complete"
                torrent.published_path = str(path)

    def poll_alerts(self) -> None:
        if getattr(self, "_alert_batch_active", False):
            raise SidecarError("alert polling cannot borrow a second native alert batch")
        self._alert_batch_active = True
        try:
            for alert in self._session.pop_alerts():
                self._handle_alert(alert)
        finally:
            self._alert_batch_active = False
        for torrent in self._torrents.values():
            lease = torrent.lease
            expires_at = max(
                (
                    current.expires_at
                    for current in self._leases.values()
                    if current.digest == lease.digest
                ),
                default=lease.expires_at,
            )
            if expires_at <= time.time() and torrent.state not in {"complete", "failed"}:
                torrent.state = "expired"
                self._stop_torrent(torrent)
            elif isinstance(lease, SeedLease) and torrent.state not in {"failed", "expired"}:
                status = torrent.handle.status()
                torrent.state = "ready" if status.is_seeding else "checking"
        self._publish_downloads()

    def _torrent_activity(self, status: Any) -> str:
        if bool(status.is_seeding):
            return "seeding"
        if bool(status.is_finished):
            return "complete"
        return "downloading" if status.state == self._lt.torrent_status.downloading else "queued"

    def _torrent_paused(self, status: Any) -> bool:
        return bool(status.flags & self._lt.torrent_flags.paused)

    def _pause_handle(self, handle: Any) -> None:
        status = handle.status()
        if status.flags & self._lt.torrent_flags.auto_managed:
            handle.unset_flags(self._lt.torrent_flags.auto_managed)
        if not self._torrent_paused(status):
            handle.pause()

    def _sync_activity(self, now: float | None = None) -> bool:
        if hasattr(self._session, "pop_alerts"):
            self.poll_alerts()
        by_info_hash = {lease.descriptor.info_hash: lease.digest for lease in self._leases.values()}
        torrents: dict[str, list[tuple[Any, Any]]] = {}
        observed: list[tuple[str, str | None, Any]] = []
        for handle in self._session.get_torrents():
            status = handle.status()
            hashes = status.info_hashes
            digest = by_info_hash.get(str(hashes.v2)) if hashes.has_v2() else None
            if hashes.has_v2():
                observed.append((str(hashes.v2), digest, status))
            if self._global is not None and self._global.owns(handle):
                continue
            if digest is not None:
                torrents.setdefault(digest, []).append((handle, status))

        changed = False
        live_activity: dict[str, _LiveActivity] = {}
        sampled_at = time.monotonic() if now is None else now
        state_priority = {
            "queued": 0,
            "complete": 1,
            "paused": 2,
            "downloading": 3,
            "seeding": 4,
        }
        for digest, items in torrents.items():
            samples = [status for _, status in items]
            record = self._activity[digest]
            downloaded = max(max(0, int(sample.all_time_download)) for sample in samples)
            uploaded = max(max(0, int(sample.all_time_upload)) for sample in samples)
            if downloaded != record.transport_download_sample:
                record.downloaded_bytes += max(0, downloaded - record.transport_download_sample)
                record.transport_download_sample = downloaded
                changed = True
            if uploaded != record.transport_upload_sample:
                record.uploaded_bytes += max(0, uploaded - record.transport_upload_sample)
                record.transport_upload_sample = uploaded
                changed = True
            states = [
                "paused" if self._torrent_paused(sample) else self._torrent_activity(sample)
                for sample in samples
            ]
            live_activity[digest] = _LiveActivity(
                state=max(states, key=state_priority.__getitem__),
                peers=sum(max(0, int(sample.num_peers)) for sample in samples),
                download_rate=sum(max(0, int(sample.download_payload_rate)) for sample in samples),
                upload_rate=sum(max(0, int(sample.upload_payload_rate)) for sample in samples),
            )

        for digest, record in self._activity.items():
            live = live_activity.get(digest)
            download_authorized = self._has_authorized_download_lease(digest)
            seed_authorized = self._has_authorized_seed_lease(digest)
            lan_seed_authorized = self._has_authorized_lan_seed_lease(digest)
            global_seed_authorized = self._has_authorized_global_seed_lease(digest)
            digest_torrents = torrents.get(digest, [])
            actively_budgeted = bool(
                any(
                    self._torrent_activity(status) == "seeding" and not self._torrent_paused(status)
                    for _, status in digest_torrents
                )
                and not self._paused
                and not self._network_paused
                and record.state_override not in {"paused", "stopped"}
                and self.settings["seedMode"] == "budgeted"
                and not record.continuous
                and global_seed_authorized
                and not lan_seed_authorized
            )
            started = self._seed_active_at.get(digest)
            if not actively_budgeted:
                self._seed_active_at.pop(digest, None)
            elif started is None or sampled_at < started:
                self._seed_active_at[digest] = sampled_at
            else:
                elapsed = int(sampled_at - started)
                if elapsed > 0:
                    record.seed_active_seconds += elapsed
                    self._seed_active_at[digest] = started + elapsed
                    changed = True

            budget_exhausted = global_seed_authorized and self._seed_budget_exhausted(record)
            pause_for_policy = record.state_override in {"paused", "stopped"}
            paused_live_state: str | None = None
            for handle, status in digest_torrents:
                activity = self._torrent_activity(status)
                unauthorized = bool(
                    (activity == "downloading" and not download_authorized)
                    or (activity in {"complete", "seeding"} and not seed_authorized)
                    or (activity == "queued" and not (download_authorized or seed_authorized))
                )
                if (
                    pause_for_policy
                    or unauthorized
                    or (activity == "seeding" and budget_exhausted and not lan_seed_authorized)
                ):
                    self._pause_handle(handle)
                    if unauthorized and activity in {"complete", "seeding"} and download_authorized:
                        paused_live_state = "complete"
                    elif unauthorized:
                        paused_live_state = "stopped"
                    else:
                        paused_live_state = "paused"
            if live is not None and paused_live_state is not None:
                if budget_exhausted:
                    self._seed_active_at.pop(digest, None)
                live_activity[digest] = _LiveActivity(
                    state=paused_live_state,
                    peers=0,
                    download_rate=0,
                    upload_rate=0,
                )

        for info_hash, digest, status in observed:
            record = self._activity.get(digest) if digest is not None else None
            self._diagnostics.sample_upload(
                info_hash,
                digest,
                status,
                record.uploaded_bytes if record is not None else None,
                record.transport_upload_sample if record is not None else None,
            )
        self._live_activity = live_activity
        return changed

    def _torrent_handles(self, digest: str) -> list[Any]:
        info_hashes = {
            lease.descriptor.info_hash for lease in self._leases.values() if lease.digest == digest
        }
        handles: list[Any] = []
        for handle in self._session.get_torrents():
            hashes = handle.info_hashes()
            if hashes.has_v2() and str(hashes.v2) in info_hashes:
                handles.append(handle)
        return handles

    def sample_activity(self) -> None:
        if self._sync_activity():
            self._save_metadata_state()

    async def sample_activity_loop(self) -> None:
        loop = asyncio.get_running_loop()
        session = self._session
        alert_reader, alert_writer = socket.socketpair()
        alert_reader.setblocking(False)
        alert_writer.setblocking(False)
        try:
            # A Python alert callback can deadlock with libtorrent while the GIL is held.
            session.set_alert_fd(alert_writer.fileno())
            while True:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        loop.sock_recv(alert_reader, 4096),
                        timeout=_ACTIVITY_SAMPLE_SECONDS,
                    )
                with contextlib.suppress(Exception):
                    SidecarRuntime.poll_alerts(self)
                with contextlib.suppress(Exception):
                    self.sample_activity()
                with contextlib.suppress(Exception):
                    self.maintain()
        finally:
            with contextlib.suppress(Exception):
                session.set_alert_fd(-1)
            alert_reader.close()
            alert_writer.close()

    def _download_path(self, lease: DownloadLease) -> Path:
        staging_root = (self.vault_root / ".p2p" / "staging").resolve()
        path = staging_root.joinpath(*lease.staging_path.split("/"))
        if not path.resolve(strict=False).is_relative_to(staging_root):
            raise SidecarError("download lease stagingPath escaped the staging root")
        return path

    def _partial_bytes(self, lease: DownloadLease) -> int:
        torrent = self._torrents.get(lease.lease_id)
        partial = (
            torrent.partial
            if torrent is not None and torrent.partial is not None
            else P2PPartial(
                self.vault_root,
                self._download_path(lease),
                self._download_path(lease).with_name(
                    self._download_path(lease).name + ".resume.json"
                ),
                lease.descriptor.info_hash,
                lease.digest,
                lease.size_bytes,
            )
        )
        try:
            return sum(end - start for start, end in partial.completed_ranges)
        except FileNotFoundError:
            return 0
        except (OSError, P2PStorageError):
            return 0

    def _lease_enabled(self, lease: P2PLease) -> bool:
        capability_enabled = bool(
            self.settings[
                "downloadsEnabled" if isinstance(lease, DownloadLease) else "seedingEnabled"
            ]
        )
        scope_enabled = self.settings["scope"] != "lan-only" or lease.scope == "lan-only"
        return capability_enabled and scope_enabled

    def _lease_authorized(self, lease: P2PLease) -> bool:
        return self._lease_enabled(lease) and lease.expires_at > time.time()

    def _lease_state(self, lease: P2PLease, global_status: Mapping[str, object] | None) -> str:
        if not self._lease_enabled(lease):
            return "disabled"
        if lease.expires_at <= time.time():
            return "expired"
        if self._paused or self._network_paused:
            return "paused"
        if (
            lease.scope == "lan-and-internet"
            and self._activity[lease.digest].global_resume_required
        ):
            return "paused"
        if lease.scope == "lan-and-internet":
            override = self._activity[lease.digest].state_override
            if override is not None:
                return "paused" if override == "paused" else "inactive"
            return str(global_status["state"]) if global_status is not None else "inactive"
        torrent = self._torrents.get(lease.lease_id) or self._torrent_for_digest(lease.digest)
        if (
            isinstance(lease, SeedLease)
            and torrent is not None
            and torrent.state == "ready"
            and (
                not self._session_plan.lan_active
                or not self._listeners.tcp_ready(self._network_policy.addresses)
            )
        ):
            # The mapping service advertises every eligible LAN interface.
            return "checking"
        return torrent.state if torrent is not None else "inactive"

    def _lease_status(self, lease: P2PLease) -> dict[str, object]:
        global_status = (
            self._global.lease_status(lease.lease_id)
            if lease.scope == "lan-and-internet" and self._global is not None
            else None
        )
        torrent = self._torrents.get(lease.lease_id) or self._torrent_for_digest(lease.digest)
        result: dict[str, object] = {
            "leaseId": lease.lease_id,
            "kind": lease.kind,
            "digest": lease.digest,
            "scope": lease.scope,
            "expiresAt": lease.expires_at,
            "state": self._lease_state(lease, global_status),
        }
        if lease.scope == "lan-and-internet":
            if global_status is not None:
                for key in ("durableBytes", "verifiedBytes", "error"):
                    if key in global_status:
                        result[key] = global_status[key]
                if result["state"] == "complete" and "path" in global_status:
                    result["path"] = global_status["path"]
            return result
        if torrent is not None:
            if isinstance(lease, DownloadLease):
                result["durableBytes"] = sum(
                    min(P2P_PIECE_LENGTH, lease.size_bytes - piece * P2P_PIECE_LENGTH)
                    for piece in torrent.durable_pieces
                )
            if torrent.error is not None:
                result["error"] = torrent.error
            if torrent.published_path is not None:
                result["path"] = torrent.published_path
        return result

    def _transfer_status(
        self,
        record: _ActivityRecord,
        global_transfers: Mapping[str, Mapping[str, object]] | None = None,
    ) -> dict[str, object]:
        leases = [lease for lease in self._leases.values() if lease.digest == record.digest]
        download_leases = [lease for lease in leases if isinstance(lease, DownloadLease)]
        seed_leases = [lease for lease in leases if isinstance(lease, SeedLease)]
        partial_bytes = max((self._partial_bytes(lease) for lease in download_leases), default=0)
        live = self._live_activity.get(record.digest)
        download_authorized = any(self._lease_authorized(lease) for lease in download_leases)
        runtime_states = {
            torrent.state
            for torrent in self._torrents.values()
            if torrent.lease.digest == record.digest
        }
        if record.state_override is not None:
            state = record.state_override
        elif self._paused or self._network_paused:
            state = "paused"
        elif record.global_resume_required and not any(
            lease.scope == "lan-only" and self._lease_authorized(lease) for lease in leases
        ):
            state = "paused"
        elif "failed" in runtime_states:
            state = "error"
        elif not any(self._lease_authorized(lease) for lease in leases):
            state = "stopped"
        elif live is not None:
            state = live.state
        elif "complete" in runtime_states:
            state = "complete"
        elif download_leases and partial_bytes >= record.size_bytes and not seed_leases:
            state = "complete"
        else:
            state = "queued"
        authorized_seed_grant_ids = sorted(
            {
                grant_id
                for lease in seed_leases
                if self._lease_authorized(lease)
                for grant_id in lease.grant_ids
            }
        )
        authorized = bool(authorized_seed_grant_ids)
        upload_authorized = bool(
            authorized or (live is not None and live.state == "downloading" and download_authorized)
        )
        global_seed = any(lease.scope == "lan-and-internet" for lease in seed_leases)
        budgeted = bool(
            global_seed and self.settings["seedMode"] == "budgeted" and not record.continuous
        )
        global_counters = self._global.counters(record.digest) if self._global is not None else None
        global_downloaded = global_counters.downloaded_bytes if global_counters is not None else 0
        global_uploaded = global_counters.uploaded_bytes if global_counters is not None else 0
        uploaded_in_budget = (
            global_uploaded - record.global_uploaded_baseline
            if global_seed
            else record.uploaded_bytes - record.seed_uploaded_baseline
        )
        seconds_in_budget = (
            (global_counters.active_seed_seconds if global_counters is not None else 0)
            - record.global_seed_seconds_baseline
            if global_seed
            else record.seed_active_seconds - record.seed_seconds_baseline
        )
        remaining_ratio = (
            max(
                0.0,
                cast(float, self.settings["internetSeedRatio"])
                - uploaded_in_budget / record.size_bytes,
            )
            if budgeted
            else None
        )
        remaining_seconds = (
            max(0, cast(int, self.settings["internetSeedTimeSeconds"]) - seconds_in_budget)
            if budgeted
            else None
        )
        transferring = state not in {"paused", "stopped", "error"}
        global_transfer = (
            global_transfers.get(record.digest) if global_transfers is not None else None
        )
        return {
            "digest": record.digest,
            "state": global_transfer["state"] if global_transfer is not None else state,
            "sizeBytes": record.size_bytes,
            "peers": (
                (
                    live.peers
                    if live is not None and (download_authorized or authorized) and transferring
                    else 0
                )
                + (cast(int, global_transfer["peers"]) if global_transfer is not None else 0)
            ),
            "downloadRateBytesPerSecond": (
                (
                    live.download_rate
                    if live is not None and download_authorized and transferring
                    else 0
                )
                + (
                    cast(int, global_transfer["downloadRateBytesPerSecond"])
                    if global_transfer is not None
                    else 0
                )
            ),
            "uploadRateBytesPerSecond": (
                (live.upload_rate if live is not None and upload_authorized and transferring else 0)
                + (
                    cast(int, global_transfer["uploadRateBytesPerSecond"])
                    if global_transfer is not None
                    else 0
                )
            ),
            "downloadedBytes": record.downloaded_bytes + global_downloaded,
            "uploadedBytes": record.uploaded_bytes + global_uploaded,
            "partialBytes": partial_bytes,
            "seedGrantIds": list(record.seed_grant_ids),
            "authorizedSeedGrantIds": authorized_seed_grant_ids,
            "remainingSeedRatio": remaining_ratio,
            "remainingSeedTimeSeconds": remaining_seconds,
        }

    def status(self) -> dict[str, object]:
        self.sample_activity()
        recovery = self._recovery
        self._apply_global_settings()
        applied = self._session.get_settings()
        global_status = self._global.status() if self._global is not None else None
        global_transfers = {
            cast(str, row["digest"]): row
            for row in (
                cast("list[Mapping[str, object]]", global_status["transfers"])
                if global_status is not None
                else []
            )
        }
        transfers = [
            self._transfer_status(self._activity[key], global_transfers)
            for key in sorted(self._activity)
        ]
        global_features = cast(
            "Mapping[str, object]",
            global_status["networkFeatures"]
            if global_status is not None
            else {
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
        )
        return {
            "version": IPC_VERSION,
            "state": "paused" if self._paused or self._network_paused else "running",
            "pid": os.getpid(),
            "capabilities": {
                "downloads": self.settings["downloadsEnabled"],
                "seeding": self.settings["seedingEnabled"],
            },
            "libtorrentVersion": LIBTORRENT_VERSION,
            "listenPort": self._session.listen_port() if self._session.is_listening() else None,
            "listenEndpoints": [
                {"address": address, "port": port}
                for address, port in self._listeners.tcp_endpoints
            ],
            "listenInterfaces": list(self._network_policy.addresses),
            "networkPaused": self._network_paused,
            "networkFeatures": {
                **global_features,
                "lsd": bool(applied["enable_lsd"]),
            },
            "global": global_status,
            "leases": [self._lease_status(self._leases[key]) for key in sorted(self._leases)],
            "totals": {
                "downloadedBytes": sum(cast(int, row["downloadedBytes"]) for row in transfers),
                "uploadedBytes": sum(cast(int, row["uploadedBytes"]) for row in transfers),
            },
            "transfers": transfers,
            "recovery": self._recovery if self._recovery is not None else recovery,
            "diagnostics": self._diagnostics.snapshot(
                lsd_peer_events_available=hasattr(self._lt, "lsd_peer_alert")
            ),
        }

    def configure(self, settings: object) -> dict[str, object]:
        normalized = normalize_p2p_settings(settings)
        if not normalized["downloadsEnabled"] and not normalized["seedingEnabled"]:
            raise SidecarError("an active sidecar requires at least one enabled capability")
        self.settings = normalized
        self.sample_activity()
        if normalized["scope"] == "lan-only":
            self._session_plan = self._session_plan.close_global()
        self._apply_settings()
        self.save_state()
        return self.status()

    def _verify_seed(self, lease: SeedLease) -> P2PDescriptorResult:
        try:
            before = lease.local_path.stat(follow_symlinks=False)
        except OSError as error:
            raise SidecarError("seed lease localPath is unavailable") from error
        if not stat.S_ISREG(before.st_mode):
            raise SidecarError("seed lease localPath must be a regular non-symlink file")
        if before.st_size != lease.size_bytes:
            raise SidecarError("seed lease localPath size does not match sizeBytes")
        try:
            derived = (
                verified_p2p_seed_descriptor(
                    self._vault.root, lease.digest, lease.size_bytes, lease.local_path
                )
                if lease.scope == "lan-and-internet"
                or cached_p2p_local_file(self._vault.root, lease.local_path) is not None
                else derive_p2p_descriptor(lease.local_path)
            )
            if (
                derived.asset_digest != lease.digest
                or derived.size != lease.size_bytes
                or derived.descriptor != lease.descriptor
            ):
                raise AssetError("seed bytes do not match the descriptor authority")
            after = lease.local_path.stat(follow_symlinks=False)
        except (AssetError, OSError, ValueError) as error:
            raise SidecarError(f"seed lease localPath verification failed: {error}") from error
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if not stat.S_ISREG(after.st_mode) or after_identity != before_identity:
            raise SidecarError("seed lease localPath changed during verification")
        return derived

    def _grant_lease(
        self,
        lease: P2PLease,
        kind: str,
        *,
        trackers: tuple[str, ...] = (),
    ) -> dict[str, object]:
        if lease.kind != kind:
            raise SidecarError(f"grant-{kind} requires a {kind} lease")
        enabled = self.settings["downloadsEnabled" if kind == "download" else "seedingEnabled"]
        if not enabled:
            raise SidecarError(f"{kind} capability is disabled")
        if lease.expires_at <= time.time():
            raise SidecarError("lease has expired")
        if self.settings["scope"] == "lan-only" and lease.scope != "lan-only":
            raise SidecarError("lease scope exceeds the configured lan-only scope")
        if (
            isinstance(lease, DownloadLease)
            and lease.peer_address is not None
            and not self._network_policy.allows_peer(lease.peer_address)
        ):
            raise SidecarError("download lease peer hint is outside the active LAN")
        existing = self._leases.get(lease.lease_id)
        renewing_seed = bool(
            existing is not None
            and existing != lease
            and isinstance(existing, SeedLease)
            and isinstance(lease, SeedLease)
            and replace(
                existing,
                grant_ids=lease.grant_ids,
                expires_at=lease.expires_at,
            )
            == lease
        )
        if existing is not None and existing != lease and not renewing_seed:
            raise SidecarError("leaseId is already bound to a different lease")
        if lease.scope == "lan-and-internet" and any(
            current.lease_id != lease.lease_id
            and current.scope == "lan-and-internet"
            and current.digest == lease.digest
            for current in self._leases.values()
        ):
            raise SidecarError("global leases must have unique artifact digests")
        if isinstance(lease, DownloadLease) and any(
            isinstance(current, DownloadLease)
            and current.digest == lease.digest
            and current.lease_id != lease.lease_id
            for current in self._leases.values()
        ):
            raise SidecarError("one active torrent per digest is permitted")
        limit = (
            MAX_ACTIVE_DOWNLOADS
            if isinstance(lease, DownloadLease)
            else cast(int, self.settings["maxActiveSeeds"])
        )
        active_lan = sum(
            isinstance(current.lease, type(lease)) and not current.stopped
            for current in self._torrents.values()
        )
        active_global = sum(
            isinstance(current, type(lease)) and current.scope == "lan-and-internet"
            for current in self._leases.values()
        )
        shared_runtime = self._torrent_for_digest(lease.digest)
        already_counted = (
            existing is not None
            if lease.scope == "lan-and-internet"
            else shared_runtime is not None
            and isinstance(shared_runtime.lease, type(lease))
            and not shared_runtime.stopped
        )
        if not already_counted and active_lan + active_global >= limit:
            raise SidecarError(f"active {kind} lease limit reached")
        seed_descriptor = self._verify_seed(lease) if isinstance(lease, SeedLease) else None
        if isinstance(lease, DownloadLease):
            self._require_staging_budget(lease)
        new_activity = lease.digest not in self._activity
        record = self._ensure_activity(lease)
        previous_resume_required = record.global_resume_required
        if self._network_paused and record.state_override != "stopped":
            record.state_override = "paused"
        if lease.scope == "lan-and-internet" and (
            self._network_paused or self._global_network_closure_reason is not None
        ):
            record.global_resume_required = True
        previous_trackers = self._global_trackers.get(lease.lease_id)
        if lease.scope == "lan-and-internet":
            self._leases[lease.lease_id] = lease
            self._global_trackers[lease.lease_id] = trackers
            try:
                if isinstance(lease, SeedLease) and self._global is not None:
                    self._global.credit_seed(lease)
                self._apply_settings(strict_global=True)
                self.save_state()
            except Exception as error:
                recovery = self._recovery
                if existing is None:
                    self._leases.pop(lease.lease_id, None)
                else:
                    self._leases[lease.lease_id] = existing
                if previous_trackers is None:
                    self._global_trackers.pop(lease.lease_id, None)
                else:
                    self._global_trackers[lease.lease_id] = previous_trackers
                if new_activity:
                    self._activity.pop(lease.digest, None)
                else:
                    record.global_resume_required = previous_resume_required
                self._apply_settings()
                self._recovery = recovery
                raise SidecarError(f"global lease activation failed: {error}") from error
            return self._lease_status(lease)
        if (
            isinstance(lease, SeedLease)
            and shared_runtime is not None
            and isinstance(shared_runtime.lease, DownloadLease)
        ):
            self._remove_torrent(shared_runtime.lease.lease_id)
            shared_runtime = None
        global_handle = (
            self._global.share_with_lan(lease)
            if shared_runtime is None and self._global is not None
            else None
        )
        activated_runtime = shared_runtime is None
        if shared_runtime is not None and isinstance(shared_runtime.lease, type(lease)):
            runtime = shared_runtime
            if renewing_seed:
                runtime.lease = lease
        else:
            try:
                runtime = shared_runtime or self._activate_lease(
                    lease,
                    seed_descriptor,
                    shared_handle=global_handle,
                )
            except BaseException:
                if global_handle is not None and self._global is not None:
                    self._global.unshare_with_lan(lease, global_handle)
                raise
        if existing is None or renewing_seed:
            self._leases[lease.lease_id] = lease
        try:
            if (
                activated_runtime
                and isinstance(lease, DownloadLease)
                and lease.peer_address is not None
            ):
                assert lease.peer_port is not None
                runtime.handle.connect_peer((lease.peer_address, lease.peer_port))
            self.save_state()
        except BaseException:
            if existing is None:
                self._leases.pop(lease.lease_id, None)
            elif renewing_seed:
                self._leases[lease.lease_id] = existing
                runtime.lease = existing
            if global_handle is not None:
                self._torrents.pop(lease.lease_id, None)
                if self._global is not None:
                    self._global.unshare_with_lan(lease, global_handle)
            elif activated_runtime:
                self._remove_torrent(lease.lease_id)
            if new_activity:
                self._activity.pop(lease.digest, None)
            raise
        if (
            not self._paused
            and not self._network_paused
            and record.state_override not in {"paused", "stopped"}
            and not runtime.stopped
        ):
            runtime.handle.resume()
        self.sample_activity()
        return self._lease_status(lease)

    def grant(self, value: object, kind: str) -> dict[str, object]:
        lease = lease_from_wire(value)
        if lease.scope != "lan-only":
            raise SidecarError("global leases require trusted provider authority")
        return self._grant_lease(lease, kind)

    def grant_global(self, value: object) -> dict[str, object]:
        if not isinstance(value, Mapping) or set(value) != {"lease", "trackers"}:
            raise SidecarError("global grant must contain exactly lease and trackers")
        lease = lease_from_wire(value["lease"])
        try:
            trackers = validate_global_authorization(lease, value["trackers"])
        except ValueError as error:
            raise SidecarError(str(error)) from error
        return self._grant_lease(lease, lease.kind, trackers=trackers)

    def revoke(self, body: object) -> dict[str, object]:
        lease_id = self._lease_id_body(body)
        lease = self._leases.get(lease_id)
        if lease is not None:
            self._leases.pop(lease_id)
            self._global_trackers.pop(lease_id, None)
        removed = lease is not None
        if lease is not None and not any(
            item.digest == lease.digest for item in self._leases.values()
        ):
            torrent = self._torrent_for_digest(lease.digest)
            if torrent is not None:
                self._remove_torrent(torrent.lease.lease_id)
        elif lease is not None:
            self.sample_activity()
        self._apply_global_settings()
        self.save_state()
        return {"leaseId": lease_id, "revoked": removed}

    @staticmethod
    def _lease_id_body(body: object) -> str:
        if not isinstance(body, Mapping) or set(body) != {"leaseId"}:
            raise SidecarError("operation body must contain exactly leaseId")
        lease_id = body.get("leaseId")
        if not isinstance(lease_id, str):
            raise SidecarError("leaseId must be a string")
        return lease_id

    def remove_partial(self, body: object) -> dict[str, object]:
        lease_id = self._lease_id_body(body)
        lease = self._leases.get(lease_id)
        if not isinstance(lease, DownloadLease):
            raise SidecarError("remove-partial requires a known download lease")
        self._remove_torrent(lease_id)
        self._leases.pop(lease_id)
        self._global_trackers.pop(lease_id, None)
        self._apply_global_settings()
        with contextlib.suppress(FileNotFoundError):
            self._download_path(lease).unlink()
        with contextlib.suppress(FileNotFoundError):
            self._download_path(lease).with_name(
                self._download_path(lease).name + ".resume.json"
            ).unlink()
        if not any(item.digest == lease.digest for item in self._leases.values()):
            self._activity[lease.digest].state_override = "stopped"
        else:
            self.sample_activity()
        self.save_state()
        return {"leaseId": lease_id, "removed": True}

    @staticmethod
    def _digest_body(body: object) -> str:
        if not isinstance(body, Mapping) or set(body) != {"digest"}:
            raise SidecarError("operation body must contain exactly digest")
        digest = body.get("digest")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise SidecarError("digest must be a canonical BLAKE3 identity")
        return digest

    def _activity_for_body(self, body: object) -> _ActivityRecord:
        digest = self._digest_body(body)
        try:
            return self._activity[digest]
        except KeyError as error:
            raise SidecarNotFound("transfer was not found") from error

    def _has_authorized_seed_lease(self, digest: str) -> bool:
        return any(
            isinstance(lease, SeedLease)
            and lease.digest == digest
            and self._lease_authorized(lease)
            for lease in self._leases.values()
        )

    def _has_authorized_lan_seed_lease(self, digest: str) -> bool:
        return any(
            isinstance(lease, SeedLease)
            and lease.scope == "lan-only"
            and lease.digest == digest
            and self._lease_authorized(lease)
            for lease in self._leases.values()
        )

    def _has_authorized_global_seed_lease(self, digest: str) -> bool:
        return any(
            isinstance(lease, SeedLease)
            and lease.scope == "lan-and-internet"
            and lease.digest == digest
            and self._lease_authorized(lease)
            for lease in self._leases.values()
        )

    def _has_authorized_download_lease(self, digest: str) -> bool:
        return any(
            isinstance(lease, DownloadLease)
            and lease.digest == digest
            and self._lease_authorized(lease)
            for lease in self._leases.values()
        )

    def _seed_budget_exhausted(self, record: _ActivityRecord) -> bool:
        if self.settings["seedMode"] != "budgeted" or record.continuous:
            return False
        ratio = cast(float, self.settings["internetSeedRatio"])
        seconds = cast(int, self.settings["internetSeedTimeSeconds"])
        counters = self._global.counters(record.digest) if self._global is not None else None
        return bool(
            counters is not None
            and (
                counters.uploaded_bytes - record.global_uploaded_baseline
                >= ratio * counters.ratio_equivalent_bytes
                or counters.active_seed_seconds - record.global_seed_seconds_baseline >= seconds
            )
        )

    def pause_transfer(self, body: object) -> dict[str, object]:
        record = self._activity_for_body(body)
        if record.state_override == "stopped":
            raise SidecarConflict("stopped transfer cannot be paused")
        for handle in self._torrent_handles(record.digest):
            self._pause_handle(handle)
        record.state_override = "paused"
        self._apply_global_settings()
        self.save_state()
        return {"digest": record.digest, "paused": True}

    def resume_transfer(self, body: object) -> dict[str, object]:
        record = self._activity_for_body(body)
        download_authorized = self._has_authorized_download_lease(record.digest)
        seed_authorized = self._has_authorized_seed_lease(record.digest)
        if not (download_authorized or seed_authorized):
            raise SidecarConflict("transfer has no active authorization to resume")
        handles = self._torrent_handles(record.digest)
        if (
            not handles
            and seed_authorized
            and not download_authorized
            and not self._has_authorized_lan_seed_lease(record.digest)
            and self._seed_budget_exhausted(record)
        ):
            raise SidecarConflict("transfer seed budget is exhausted")
        for handle in handles:
            activity = self._torrent_activity(handle.status())
            if activity == "downloading" and not download_authorized:
                raise SidecarConflict("transfer has no download authorization to resume")
            if activity in {"complete", "seeding"} and not seed_authorized:
                raise SidecarConflict("transfer has no seed authorization to resume")
            if (
                activity in {"complete", "seeding"}
                and not self._has_authorized_lan_seed_lease(record.digest)
                and self._seed_budget_exhausted(record)
            ):
                raise SidecarConflict("transfer seed budget is exhausted")
        if download_authorized:
            for lease in self._leases.values():
                if (
                    isinstance(lease, DownloadLease)
                    and lease.digest == record.digest
                    and self._lease_authorized(lease)
                ):
                    self._require_staging_budget(lease)
                    if not handles and lease.scope == "lan-only":
                        handles.append(self._activate_lease(lease).handle)
        for handle in handles:
            handle.resume()
        record.state_override = None
        record.global_resume_required = False
        self._apply_global_settings()
        self.save_state()
        return {"digest": record.digest, "resumed": True}

    def stop_transfer(self, body: object) -> dict[str, object]:
        record = self._activity_for_body(body)
        for handle in self._torrent_handles(record.digest):
            self._pause_handle(handle)
        record.state_override = "stopped"
        self._apply_global_settings()
        self.save_state()
        return {"digest": record.digest, "stopped": True}

    def remove_transfer_partial(self, body: object) -> dict[str, object]:
        record = self._activity_for_body(body)
        downloads = [
            lease
            for lease in self._leases.values()
            if isinstance(lease, DownloadLease) and lease.digest == record.digest
        ]
        if not downloads:
            raise SidecarConflict("transfer has no removable download partial")
        if record.state_override != "stopped":
            raise SidecarConflict("transfer must be stopped before removing its partial")
        for lease in downloads:
            self._remove_torrent(lease.lease_id)
            self._leases.pop(lease.lease_id)
            self._global_trackers.pop(lease.lease_id, None)
        self._apply_global_settings()
        for lease in downloads:
            with contextlib.suppress(FileNotFoundError):
                self._download_path(lease).unlink()
            with contextlib.suppress(FileNotFoundError):
                self._download_path(lease).with_name(
                    self._download_path(lease).name + ".resume.json"
                ).unlink()
        self.save_state()
        return {"digest": record.digest, "removed": True}

    def reset_transfer_budget(self, body: object) -> dict[str, object]:
        record = self._activity_for_body(body)
        if not self._has_authorized_seed_lease(record.digest):
            raise SidecarConflict("seed budget reset requires a seed authorization")
        record.seed_uploaded_baseline = record.uploaded_bytes
        record.seed_seconds_baseline = record.seed_active_seconds
        counters = self._global.counters(record.digest) if self._global is not None else None
        if counters is not None:
            record.global_uploaded_baseline = counters.uploaded_bytes
            record.global_seed_seconds_baseline = counters.active_seed_seconds
        record.continuous = False
        self._seed_active_at.pop(record.digest, None)
        self._apply_global_settings()
        self.save_state()
        return {"digest": record.digest, "reset": True}

    def make_transfer_continuous(self, body: object) -> dict[str, object]:
        record = self._activity_for_body(body)
        if not self._has_authorized_seed_lease(record.digest):
            raise SidecarConflict("continuous seeding requires a seed authorization")
        record.continuous = True
        self._apply_global_settings()
        self.save_state()
        return {"digest": record.digest, "continuous": True}

    @staticmethod
    def _empty_body(body: object) -> None:
        if not isinstance(body, Mapping) or body:
            raise SidecarError("operation body must be an empty object")

    def pause(self) -> dict[str, object]:
        self._paused = True
        self._apply_settings()
        self.save_state()
        return self.status()

    def resume(self) -> dict[str, object]:
        self._paused = False
        self._apply_settings()
        self.save_state()
        return self.status()

    def set_network_paused(self, body: object) -> dict[str, object]:
        if not isinstance(body, Mapping) or set(body) != {"paused"}:
            raise SidecarError("network pause body must contain exactly paused")
        paused = body.get("paused")
        if not isinstance(paused, bool):
            raise SidecarError("network pause must be a boolean")
        self._network_paused = paused
        latched = self._latch_network_pause() if paused else False
        self._apply_settings()
        if latched:
            self._save_metadata_state()
        return self.status()

    def set_global_network_policy(self, body: object) -> dict[str, object]:
        if not isinstance(body, Mapping) or set(body) != {"cost", "paused"}:
            raise SidecarError("global network policy must contain exactly cost and paused")
        cost = body.get("cost")
        paused = body.get("paused")
        if not isinstance(cost, str) or cost not in _GLOBAL_NETWORK_COSTS:
            raise SidecarError("global network cost is invalid")
        if not isinstance(paused, bool):
            raise SidecarError("global network pause must be a boolean")
        if paused and cost == "unmetered":
            raise SidecarError("unmetered global network policy cannot be paused")
        self._global_network_closure_reason = f"{cost}-network" if paused else None
        latched = self._latch_global_pause() if paused else False
        self._apply_settings()
        if latched:
            self._save_metadata_state()
        return self.status()

    def _latch_network_pause(self) -> bool:
        changed = False
        for record in self._activity.values():
            if record.state_override != "stopped" and record.state_override != "paused":
                record.state_override = "paused"
                changed = True
        return self._latch_global_pause() or changed

    def _latch_global_pause(self) -> bool:
        changed = False
        global_digests = {
            lease.digest for lease in self._leases.values() if lease.scope == "lan-and-internet"
        }
        for record in self._activity.values():
            if record.digest not in global_digests:
                continue
            if not record.global_resume_required:
                record.global_resume_required = True
                changed = True
        return changed

    def maintain(self) -> None:
        self._apply_global_settings()

    def operate(self, operation: str, body: object) -> dict[str, object]:
        self.sample_activity()
        if operation == "configure":
            return self.configure(body)
        if operation == "grant-download":
            return self.grant(body, "download")
        if operation == "grant-seed":
            return self.grant(body, "seed")
        if operation == "grant-global":
            return self.grant_global(body)
        if operation == "revoke":
            return self.revoke(body)
        if operation == "pause":
            self._empty_body(body)
            return self.pause()
        if operation == "resume":
            self._empty_body(body)
            return self.resume()
        if operation == "remove-partial":
            return self.remove_partial(body)
        if operation == "lease-status":
            lease_id = self._lease_id_body(body)
            lease = self._leases.get(lease_id)
            if lease is None:
                raise SidecarError("lease-status requires a known lease")
            if lease.scope == "lan-and-internet":
                self._apply_global_settings()
            return self._lease_status(lease)
        if operation == "pause-transfer":
            return self.pause_transfer(body)
        if operation == "resume-transfer":
            return self.resume_transfer(body)
        if operation == "stop-transfer":
            return self.stop_transfer(body)
        if operation == "remove-transfer-partial":
            return self.remove_transfer_partial(body)
        if operation == "reset-transfer-budget":
            return self.reset_transfer_budget(body)
        if operation == "make-transfer-continuous":
            return self.make_transfer_continuous(body)
        if operation == "set-network-paused":
            return self.set_network_paused(body)
        if operation == "set-global-network-policy":
            return self.set_global_network_policy(body)
        if operation == "save-state":
            self._empty_body(body)
            self.save_state()
            return {"saved": True}
        if operation == "status":
            self._empty_body(body)
            return self.status()
        if operation == "shutdown":
            self._empty_body(body)
            self.save_state()
            return {"stopping": True}
        raise SidecarError(f"unknown operation: {operation!r}")

    def close(self) -> None:
        if self._global is not None:
            self._global.close()
            self._global = None
        self._close_session()
        self._lock.close()

    def _close_session(self) -> None:
        session = self._session
        self._session = None
        self._diagnostics.clear()
        if session is not None:
            with contextlib.suppress(Exception):
                session.apply_settings({"enable_lsd": False})
                session.pause()
            self._torrents.clear()
            del session


async def serve(runtime: SidecarRuntime, endpoint: str) -> None:
    reader, writer = await connect_endpoint(endpoint)
    try:
        while frame := await read_frame(reader):
            request, blobs = frame
            request_id = request.get("id")
            response: dict[str, object] = {"version": IPC_VERSION, "id": request_id}
            try:
                if blobs or set(request) != {"version", "id", "operation", "body", "blobs"}:
                    raise SidecarError("request must use the closed control frame")
                if request["version"] != IPC_VERSION or type(request_id) is not int:
                    raise SidecarError("unsupported IPC version or request ID")
                operation = request["operation"]
                if not isinstance(operation, str):
                    raise SidecarError("operation must be a string")
                response.update({"ok": True, "result": runtime.operate(operation, request["body"])})
            except (BoundaryError, OSError, ValueError, SidecarError) as error:
                response.update(
                    {"ok": False, "error": str(error), "errorType": type(error).__name__}
                )
            await write_frame(writer, response, [])
            if request.get("operation") == "shutdown" and response.get("ok") is True:
                return
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one isolated Dinkster libtorrent session")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--vault-root", type=Path, required=True)
    parser.add_argument("--installation-root", type=Path)
    parser.add_argument("--settings-json", required=True)
    parser.add_argument("--network-paused", action="store_true")
    return parser.parse_args(argv)


async def _run(args: argparse.Namespace) -> None:
    runtime = SidecarRuntime(
        state_root=args.state_root,
        vault_root=args.vault_root,
        installation_root=args.installation_root,
        settings=json.loads(args.settings_json),
        network_paused=args.network_paused,
    )
    sampler = asyncio.create_task(runtime.sample_activity_loop())
    try:
        await serve(runtime, args.endpoint)
    finally:
        sampler.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await sampler
        with contextlib.suppress(Exception):
            runtime.sample_activity()
        runtime.close()


def main() -> None:
    try:
        asyncio.run(_run(parse_args()))
    except (BoundaryError, OSError, ValueError, SidecarError) as error:
        print(f"dinkster-p2p: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
