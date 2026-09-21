"""Closed host-to-sidecar lease contracts."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path, PurePosixPath
from typing import Literal, cast

from dinkster_assets import AssetError, P2PDescriptorV1, validate_p2p_descriptor

LEASE_VERSION = 1
DOWNLOAD_LEASE_VERSION = 2
_SCOPES = frozenset({"lan-only", "lan-and-internet"})
_GRANT_ID = re.compile(r"^[0-9a-f]{64}$")


class P2PLeaseError(ValueError):
    """A host supplied a malformed or unauthorized sidecar lease."""


@dataclass(frozen=True, slots=True)
class DownloadLease:
    version: int
    kind: Literal["download"]
    lease_id: str
    digest: str
    size_bytes: int
    descriptor: P2PDescriptorV1
    staging_path: str
    scope: str
    expires_at: float
    peer_address: str | None = None
    peer_port: int | None = None

    def __post_init__(self) -> None:
        has_peer_hint = self.peer_address is not None or self.peer_port is not None
        if self.version == LEASE_VERSION:
            if has_peer_hint:
                raise P2PLeaseError("download lease version 1 cannot carry a peer hint")
            return
        if self.version != DOWNLOAD_LEASE_VERSION or not has_peer_hint:
            raise P2PLeaseError("download lease version 2 requires a peer hint")
        if self.scope != "lan-only":
            raise P2PLeaseError("download lease version 2 peer hint requires LAN-only scope")
        try:
            canonical_address = str(IPv4Address(self.peer_address or ""))
        except ValueError as error:
            raise P2PLeaseError(
                "download lease peer hint address must be canonical IPv4"
            ) from error
        if canonical_address != self.peer_address:
            raise P2PLeaseError("download lease peer hint address must be canonical IPv4")
        if type(self.peer_port) is not int or not 1 <= self.peer_port <= 65535:
            raise P2PLeaseError("download lease peer hint port must be between 1 and 65535")

    def to_wire(self) -> dict[str, object]:
        wire: dict[str, object] = {
            "version": self.version,
            "kind": self.kind,
            "leaseId": self.lease_id,
            "digest": self.digest,
            "sizeBytes": self.size_bytes,
            "descriptor": self.descriptor.to_wire(),
            "stagingPath": self.staging_path,
            "scope": self.scope,
            "expiresAt": self.expires_at,
        }
        if self.version == DOWNLOAD_LEASE_VERSION:
            wire["peerEndpoint"] = {
                "address": self.peer_address,
                "port": self.peer_port,
            }
        return wire


@dataclass(frozen=True, slots=True)
class SeedLease:
    version: int
    kind: Literal["seed"]
    lease_id: str
    digest: str
    size_bytes: int
    descriptor: P2PDescriptorV1
    grant_ids: tuple[str, ...]
    local_path: Path
    scope: str
    expires_at: float

    def to_wire(self) -> dict[str, object]:
        return {
            "version": self.version,
            "kind": self.kind,
            "leaseId": self.lease_id,
            "digest": self.digest,
            "sizeBytes": self.size_bytes,
            "descriptor": self.descriptor.to_wire(),
            "grantIds": list(self.grant_ids),
            "localPath": str(self.local_path),
            "scope": self.scope,
            "expiresAt": self.expires_at,
        }


P2PLease = DownloadLease | SeedLease


def _closed(body: Mapping[str, object], fields: set[str], where: str) -> None:
    if set(body) != fields:
        raise P2PLeaseError(f"{where} fields must be exactly {sorted(fields)}, got {sorted(body)}")


def _common(
    body: Mapping[str, object], *, allowed_versions: frozenset[int]
) -> tuple[int, str, str, int, P2PDescriptorV1, str, float]:
    version = body.get("version")
    if type(version) is not int or version not in allowed_versions:
        expected = " or ".join(str(item) for item in sorted(allowed_versions))
        raise P2PLeaseError(f"lease.version must be {expected}")
    lease_id = body.get("leaseId")
    if not isinstance(lease_id, str) or not lease_id or len(lease_id) > 128:
        raise P2PLeaseError("lease.leaseId must be a non-empty string of at most 128 characters")
    digest = body.get("digest")
    if not isinstance(digest, str):
        raise P2PLeaseError("lease.digest must be a BLAKE3 identity")
    size_bytes = body.get("sizeBytes")
    if type(size_bytes) is not int or size_bytes <= 0:
        raise P2PLeaseError("lease.sizeBytes must be a positive integer")
    descriptor_body = body.get("descriptor")
    if not isinstance(descriptor_body, Mapping):
        raise P2PLeaseError("lease.descriptor must be an object")
    try:
        descriptor = validate_p2p_descriptor(
            cast("Mapping[str, object]", descriptor_body),
            asset_digest=digest,
            size=size_bytes,
        )
    except (AssetError, ValueError) as error:
        raise P2PLeaseError(f"lease.descriptor: {error}") from error
    scope = body.get("scope")
    if not isinstance(scope, str) or scope not in _SCOPES:
        raise P2PLeaseError(f"lease.scope must be one of {sorted(_SCOPES)}")
    expires_at = body.get("expiresAt")
    if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
        raise P2PLeaseError("lease.expiresAt must be a finite positive Unix timestamp")
    try:
        expires = float(expires_at)
    except OverflowError:
        raise P2PLeaseError("lease.expiresAt must be a finite positive Unix timestamp") from None
    if not math.isfinite(expires) or expires <= 0:
        raise P2PLeaseError("lease.expiresAt must be a finite positive Unix timestamp")
    return version, lease_id, digest, size_bytes, descriptor, scope, expires


def download_lease_from_wire(value: object) -> DownloadLease:
    if not isinstance(value, Mapping):
        raise P2PLeaseError("download lease must be an object")
    body = {str(key): item for key, item in cast("Mapping[object, object]", value).items()}
    version = body.get("version")
    fields = {
        "version",
        "kind",
        "leaseId",
        "digest",
        "sizeBytes",
        "descriptor",
        "stagingPath",
        "scope",
        "expiresAt",
    }
    if version == DOWNLOAD_LEASE_VERSION:
        fields.add("peerEndpoint")
    _closed(
        body,
        fields,
        "download lease",
    )
    if body["kind"] != "download":
        raise P2PLeaseError("download lease.kind must be 'download'")
    staging_path = body["stagingPath"]
    if not isinstance(staging_path, str) or not staging_path:
        raise P2PLeaseError("download lease.stagingPath must be a relative POSIX path")
    path = PurePosixPath(staging_path)
    if (
        path.is_absolute()
        or "\\" in staging_path
        or ".." in path.parts
        or "." in path.parts
        or path.as_posix() != staging_path
    ):
        raise P2PLeaseError("download lease.stagingPath must be a confined relative POSIX path")
    peer_address: str | None = None
    peer_port: int | None = None
    if version == DOWNLOAD_LEASE_VERSION:
        endpoint = body["peerEndpoint"]
        if not isinstance(endpoint, Mapping):
            raise P2PLeaseError("download lease.peerEndpoint must contain address and port")
        peer_endpoint = cast("Mapping[str, object]", endpoint)
        if set(peer_endpoint) != {"address", "port"}:
            raise P2PLeaseError("download lease.peerEndpoint must contain address and port")
        peer_address_raw = peer_endpoint.get("address")
        peer_port_raw = peer_endpoint.get("port")
        if not isinstance(peer_address_raw, str):
            raise P2PLeaseError("download lease peer hint address must be canonical IPv4")
        peer_address = peer_address_raw
        peer_port = cast("int", peer_port_raw)
    version_value, lease_id, digest, size_bytes, descriptor, scope, expires_at = _common(
        body, allowed_versions=frozenset({LEASE_VERSION, DOWNLOAD_LEASE_VERSION})
    )
    return DownloadLease(
        version_value,
        "download",
        lease_id,
        digest,
        size_bytes,
        descriptor,
        staging_path,
        scope,
        expires_at,
        peer_address,
        peer_port,
    )


def seed_lease_from_wire(value: object) -> SeedLease:
    if not isinstance(value, Mapping):
        raise P2PLeaseError("seed lease must be an object")
    body = {str(key): item for key, item in cast("Mapping[object, object]", value).items()}
    _closed(
        body,
        {
            "version",
            "kind",
            "leaseId",
            "digest",
            "sizeBytes",
            "descriptor",
            "grantIds",
            "localPath",
            "scope",
            "expiresAt",
        },
        "seed lease",
    )
    if body["kind"] != "seed":
        raise P2PLeaseError("seed lease.kind must be 'seed'")
    grant_ids_raw = body["grantIds"]
    if (
        not isinstance(grant_ids_raw, Sequence)
        or isinstance(grant_ids_raw, (str, bytes))
        or not grant_ids_raw
    ):
        raise P2PLeaseError("seed lease.grantIds must be a non-empty list of unique strings")
    grant_ids = cast("Sequence[object]", grant_ids_raw)
    if not all(isinstance(item, str) and _GRANT_ID.fullmatch(item) for item in grant_ids) or len(
        set(cast("Sequence[str]", grant_ids))
    ) != len(grant_ids):
        raise P2PLeaseError(
            "seed lease.grantIds must be unique 64-character lowercase hexadecimal ids"
        )
    local_path_raw = body["localPath"]
    if not isinstance(local_path_raw, str):
        raise P2PLeaseError("seed lease.localPath must be an absolute path")
    local_path = Path(local_path_raw)
    if not local_path.is_absolute():
        raise P2PLeaseError("seed lease.localPath must be an absolute path")
    version, lease_id, digest, size_bytes, descriptor, scope, expires_at = _common(
        body, allowed_versions=frozenset({LEASE_VERSION})
    )
    return SeedLease(
        version,
        "seed",
        lease_id,
        digest,
        size_bytes,
        descriptor,
        tuple(cast("Sequence[str]", grant_ids)),
        local_path,
        scope,
        expires_at,
    )


def lease_from_wire(value: object) -> P2PLease:
    if not isinstance(value, Mapping):
        raise P2PLeaseError("lease must be an object")
    body = cast("Mapping[str, object]", value)
    kind = body.get("kind")
    if kind == "download":
        return download_lease_from_wire(body)
    if kind == "seed":
        return seed_lease_from_wire(body)
    raise P2PLeaseError("lease.kind must be 'download' or 'seed'")
