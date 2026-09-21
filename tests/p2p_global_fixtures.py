from __future__ import annotations

import json
import time
from dataclasses import dataclass, replace
from pathlib import Path

from dinkster_assets import P2PDescriptorResult, P2PGrantReconciler, P2PGrantSnapshot
from dinkster_assets.p2p_descriptor import derive_p2p_descriptor
from dinkster_assets.p2p_global import (
    ProviderArtifactP2PV1,
    ProviderLocationV1,
    ProviderP2PEnumerationV1,
    ProviderP2PSnapshotV1,
    ProviderP2PTombstoneV1,
    provider_declarations,
)

from dinkster_p2p import AuthorizedGlobalLease, authorized_global_leases

TRUSTED_PROVIDER_IDS = frozenset({"official.fixture"})


@dataclass(frozen=True, slots=True)
class ProviderFixture:
    source: Path
    descriptor: P2PDescriptorResult
    snapshot: ProviderP2PSnapshotV1
    grants: P2PGrantSnapshot
    observed_at: float

    def authorizations(
        self,
        *,
        local_seed: bool = True,
        request_download: bool = False,
    ) -> tuple[AuthorizedGlobalLease, ...]:
        source = self.source if local_seed else None
        return authorized_global_leases(
            self.snapshot,
            self.grants,
            trusted_provider_ids=TRUSTED_PROVIDER_IDS,
            requested_download_digests=(
                frozenset({self.descriptor.asset_digest}) if request_download else frozenset()
            ),
            now=self.observed_at,
            local_path_for=lambda digest: (
                source if source is not None and digest == self.descriptor.asset_digest else None
            ),
        )

    def tombstoned(self) -> ProviderP2PSnapshotV1:
        return replace(
            self.snapshot,
            tombstones=(
                ProviderP2PTombstoneV1(self.descriptor.asset_digest, self.observed_at + 1),
            ),
        )


def build_provider_fixture(
    root: Path,
    *,
    trackers: tuple[str, ...] = (),
    payload_size: int = 256 * 1024,
    source: Path | None = None,
) -> ProviderFixture:
    root.mkdir(parents=True, exist_ok=True)
    local_path = (
        source.resolve() if source is not None else (root / "fixture.safetensors").resolve()
    )
    if source is None:
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
        local_path.write_bytes(len(header).to_bytes(8, "little") + header + bytes(payload_size))
    descriptor = derive_p2p_descriptor(local_path)
    observed_at = time.time()
    snapshot = ProviderP2PSnapshotV1(
        provider_id="official.fixture",
        source_revision="fixture-r1",
        refreshed_at=observed_at,
        artifacts=(
            ProviderArtifactP2PV1(
                source_id="artifact-1",
                digest=descriptor.asset_digest,
                size_bytes=descriptor.size,
                descriptor=descriptor.descriptor,
                license="Apache-2.0",
                format_safe=True,
                locations=(
                    ProviderLocationV1(
                        "https://models.example/fixture.safetensors",
                        eligible=True,
                        credential_free=True,
                    ),
                ),
            ),
        ),
        p2p_artifacts=(
            ProviderP2PEnumerationV1(
                grant_id="fixture-enumeration",
                digest=descriptor.asset_digest,
                size_bytes=descriptor.size,
                descriptor=descriptor.descriptor,
                expires_at=observed_at + 24 * 60 * 60,
            ),
        ),
        p2p_trackers=trackers,
    )
    declarations = tuple(
        decision.declaration
        for decision in provider_declarations(
            snapshot,
            trusted_provider_ids=TRUSTED_PROVIDER_IDS,
            now=observed_at,
        )
        if decision.declaration is not None
    )
    grants = (
        P2PGrantReconciler(clock=lambda: observed_at)
        .reconcile(
            declarations,
            (),
            lambda digest: local_path if digest == descriptor.asset_digest else None,
            enabled=True,
        )
        .snapshot
    )
    return ProviderFixture(local_path, descriptor, snapshot, grants, observed_at)
