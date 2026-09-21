"""Trusted-provider authority for host-to-sidecar internet leases."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from dinkster_assets import P2P_REMOTE_GRANT_MAX_SECONDS, P2PGrantSnapshot, SeedGrantV1
from dinkster_assets.p2p_global import (
    MAX_PROVIDER_TRACKERS,
    ProviderP2PSnapshotV1,
    matching_provider_grants_for_snapshots,
)

from .contracts import (
    LEASE_VERSION,
    P2PLease,
    download_lease_from_wire,
    seed_lease_from_wire,
)

_AUTHORITY = object()
MAX_GLOBAL_LEASE_SECONDS = P2P_REMOTE_GRANT_MAX_SECONDS
MAX_GLOBAL_TRACKERS = MAX_PROVIDER_TRACKERS


def _tracker(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 4096:
        raise ValueError("global trackers must be bounded trimmed URLs")
    if any(character.isspace() for character in value):
        raise ValueError("global trackers must not contain whitespace")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("global trackers must be valid URLs") from error
    if (
        parsed.scheme not in {"https", "udp"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.netloc.endswith(":")
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(
            "global trackers must be HTTPS or UDP URLs without credentials or query data"
        )
    return value


def validate_global_authorization(
    lease: P2PLease,
    trackers: object,
) -> tuple[str, ...]:
    if lease.scope != "lan-and-internet":
        raise ValueError("global lease lacks internet scope")
    if lease.expires_at > time.time() + MAX_GLOBAL_LEASE_SECONDS:
        raise ValueError("global lease exceeds the six-hour maximum")
    if not isinstance(trackers, Sequence) or isinstance(trackers, (str, bytes, bytearray)):
        raise ValueError("global trackers must be a list")
    values = tuple(_tracker(value) for value in cast("Sequence[object]", trackers))
    if len(values) > MAX_GLOBAL_TRACKERS or len(values) != len(set(values)):
        raise ValueError(f"global trackers must contain at most {MAX_GLOBAL_TRACKERS} unique URLs")
    return values


@dataclass(frozen=True, slots=True, init=False)
class AuthorizedGlobalLease:
    """A global lease minted only from current trusted provider authority."""

    lease: P2PLease
    trackers: tuple[str, ...]

    def __init__(self, lease: P2PLease, trackers: object, authority: object) -> None:
        if authority is not _AUTHORITY:
            raise ValueError("global lease lacks trusted provider authority")
        object.__setattr__(self, "lease", lease)
        object.__setattr__(self, "trackers", validate_global_authorization(lease, trackers))

    def to_wire(self) -> dict[str, object]:
        return {"lease": self.lease.to_wire(), "trackers": list(self.trackers)}


def authorized_global_leases(
    snapshot: ProviderP2PSnapshotV1,
    grants: P2PGrantSnapshot,
    *,
    trusted_provider_ids: frozenset[str],
    requested_download_digests: frozenset[str],
    now: float,
    local_path_for: Callable[[str], Path | None],
) -> tuple[AuthorizedGlobalLease, ...]:
    """Mint sidecar leases from one provider snapshot."""
    return authorized_global_leases_for_snapshots(
        (snapshot,),
        grants,
        trusted_provider_ids=trusted_provider_ids,
        requested_download_digests=requested_download_digests,
        now=now,
        local_path_for=local_path_for,
    )


def authorized_global_leases_for_snapshots(
    snapshots: Sequence[ProviderP2PSnapshotV1],
    grants: P2PGrantSnapshot,
    *,
    trusted_provider_ids: frozenset[str],
    requested_download_digests: frozenset[str],
    now: float,
    local_path_for: Callable[[str], Path | None],
) -> tuple[AuthorizedGlobalLease, ...]:
    """Mint sidecar leases from provider snapshots with shared grant indexes."""
    if not grants.enabled:
        return ()
    seeds_by_id: dict[str, SeedGrantV1] = {}
    duplicate_seed_ids: set[str] = set()
    for seed in grants.seed_grants:
        if seed.grant_id in seeds_by_id:
            duplicate_seed_ids.add(seed.grant_id)
        else:
            seeds_by_id[seed.grant_id] = seed
    desired_digests = requested_download_digests | frozenset(
        seed.digest for seed in seeds_by_id.values()
    )
    if not desired_digests:
        return ()
    authorized: list[AuthorizedGlobalLease] = []
    for snapshot, declaration, public in matching_provider_grants_for_snapshots(
        snapshots,
        grants,
        trusted_provider_ids=trusted_provider_ids,
        now=now,
        digests=desired_digests,
    ):
        common = {
            "version": LEASE_VERSION,
            "digest": declaration.digest,
            "sizeBytes": declaration.size_bytes,
            "descriptor": declaration.descriptor.to_wire(),
            "scope": "lan-and-internet",
            "expiresAt": public.expires_at,
        }
        seed = seeds_by_id.get(public.grant_id)
        seed_matches = bool(
            public.grant_id not in duplicate_seed_ids
            and seed is not None
            and seed.digest == public.digest
            and seed.source_type == public.source_type
            and seed.source_id == public.source_id
            and seed.source_revision == public.source_revision
            and seed.license == public.license
            and seed.descriptor == public.descriptor
            and seed.expires_at == public.expires_at
            and seed.evidence_id == declaration.evidence_id
            and now < seed.expires_at
        )
        local_path = local_path_for(public.digest) if seed_matches else None
        if seed_matches and local_path is not None and local_path.is_absolute():
            lease = seed_lease_from_wire(
                {
                    **common,
                    "kind": "seed",
                    "leaseId": f"global:seed:{public.grant_id}",
                    "grantIds": [public.grant_id],
                    "localPath": str(local_path),
                }
            )
        elif declaration.digest in requested_download_digests:
            lease = download_lease_from_wire(
                {
                    **common,
                    "kind": "download",
                    "leaseId": f"global:download:{public.grant_id}",
                    "stagingPath": (
                        f"{declaration.descriptor.info_hash}/"
                        f"{declaration.digest.removeprefix('blake3:')}"
                    ),
                }
            )
        else:
            continue
        authorized.append(AuthorizedGlobalLease(lease, snapshot.p2p_trackers, _AUTHORITY))
    return tuple(authorized)
