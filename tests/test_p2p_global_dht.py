"""Trackerless global DHT transfer fixture against pinned libtorrent."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, cast

import libtorrent as lt
from dinkster_assets import AssetVault

from dinkster_p2p import (
    DownloadLease,
    SeedLease,
    authorized_global_leases,
    default_p2p_settings,
)
from dinkster_p2p.runtime import SidecarRuntime
from tests.p2p_global_fixtures import TRUSTED_PROVIDER_IDS, build_provider_fixture

LIBTORRENT_DHT_FIXTURE_VERSION = "2.1.1.0"


def test_trackerless_dht_transfers_through_global_session(
    tmp_path: Path,
) -> None:
    assert lt.version == LIBTORRENT_DHT_FIXTURE_VERSION
    fixture = build_provider_fixture(tmp_path)
    seed = cast(SeedLease, fixture.authorizations()[0].lease)
    download = cast(
        DownloadLease,
        fixture.authorizations(local_seed=False, request_download=True)[0].lease,
    )
    settings = {
        **default_p2p_settings(),
        "downloadsEnabled": True,
        "seedingEnabled": True,
        "scope": "lan-and-internet",
        "seedMode": "continuous",
    }

    seeder = SidecarRuntime(
        state_root=tmp_path / "seed-state",
        vault_root=tmp_path / "seed-vault",
        installation_root=None,
        settings=settings,
    )
    downloader = SidecarRuntime(
        state_root=tmp_path / "download-state",
        vault_root=tmp_path / "download-vault",
        installation_root=None,
        settings=settings,
    )
    try:
        seeder.grant_global({"lease": seed.to_wire(), "trackers": []})
        downloader.grant_global({"lease": download.to_wire(), "trackers": []})
        assert cast(Any, seeder.status()["global"])["networkFeatures"] == {
            "dht": True,
            "pex": True,
            "tcp": True,
            "utp": True,
            "trackers": False,
            "upnp": True,
            "natMappings": True,
            "natPmp": True,
            "pcp": True,
        }
        seed_session = cast(Any, seeder)._session
        download_session = cast(Any, downloader)._session
        seed_session.add_dht_node(("127.0.0.1", download_session.listen_port()))
        download_session.add_dht_node(("127.0.0.1", seed_session.listen_port()))
        for runtime in (seeder, downloader):
            for handle in cast(Any, runtime)._global._handles.values():
                assert handle.trackers() == []
                handle.force_dht_announce()

        vault = AssetVault(tmp_path / "download-vault")
        deadline = time.monotonic() + 10.0
        while vault.resolve(download.digest) is None and time.monotonic() < deadline:
            downloader.status()
            lease_status = downloader.operate("lease-status", {"leaseId": download.lease_id})
            assert lease_status["state"] in {"downloading", "publishing", "complete"}
            time.sleep(0.05)

        destination = vault.resolve(download.digest)
        assert destination is not None
        assert destination.read_bytes() == fixture.source.read_bytes()
        assert destination.with_name(destination.name + ".verified.json").is_file()
        lease_status = downloader.operate("lease-status", {"leaseId": download.lease_id})
        assert lease_status["state"] == "complete"
        assert lease_status["durableBytes"] == download.size_bytes
        assert lease_status["path"] == str(destination)
        completed = downloader.status()["global"]
        assert completed["active"] is False  # type: ignore[index]
        assert completed["transfers"][0]["state"] == "complete"  # type: ignore[index]
        assert completed["transfers"][0]["path"] == str(destination)  # type: ignore[index]
        assert cast(Any, downloader)._global.counters(download.digest).uploaded_bytes == 0
        deadline = time.monotonic() + 5.0
        uploaded_bytes = 0
        while uploaded_bytes == 0 and time.monotonic() < deadline:
            seeder.status()
            uploaded_bytes = cast(Any, seeder)._global.counters(seed.digest).uploaded_bytes
            time.sleep(0.05)
        assert uploaded_bytes > 0

        tombstoned = fixture.tombstoned()
        assert (
            authorized_global_leases(
                tombstoned,
                fixture.grants,
                trusted_provider_ids=TRUSTED_PROVIDER_IDS,
                requested_download_digests=frozenset(),
                now=fixture.observed_at,
                local_path_for=lambda _: fixture.source,
            )
            == ()
        )
        seeder.revoke({"leaseId": seed.lease_id})
        downloader.revoke({"leaseId": download.lease_id})
        assert not cast(Any, seeder)._global.active
        assert not cast(Any, downloader)._global.active
        assert downloader.status()["global"]["transfers"] == []  # type: ignore[index]
    finally:
        downloader.close()
        seeder.close()
