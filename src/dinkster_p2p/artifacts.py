"""Pinned libtorrent binary artifacts supported by the sidecar."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass

LIBTORRENT_VERSION = "2.1.1"


@dataclass(frozen=True, slots=True)
class LibtorrentArtifact:
    filename: str
    sha256: str
    size: int


class UnsupportedLibtorrentRuntime(RuntimeError):
    """The pinned release has no approved wheel for this runtime."""


LIBTORRENT_ARTIFACTS: dict[tuple[str, str, tuple[int, int]], LibtorrentArtifact] = {
    ("linux", "x86_64", (3, 12)): LibtorrentArtifact(
        "libtorrent-2.1.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "90c11511a67c118e2fd6043c717d42663e60da03ab8d4851b2ad5a500a5e0134",
        8_245_815,
    ),
    ("linux", "x86_64", (3, 13)): LibtorrentArtifact(
        "libtorrent-2.1.1-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
        "c81d768e04915c1627ac108a6abfa64c740bdd1a1634d5fffcdc56ed6e6d915f",
        8_246_041,
    ),
    ("linux", "aarch64", (3, 12)): LibtorrentArtifact(
        "libtorrent-2.1.1-cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
        "580b07d04b30c9d85f73ceaab5184035e815ee4ff3f37ba5b8f887292ae949f1",
        8_423_265,
    ),
    ("linux", "aarch64", (3, 13)): LibtorrentArtifact(
        "libtorrent-2.1.1-cp313-cp313-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
        "d456d5c772e64267211eca995f5a61cfa9e476de9494b300b42fd6fdf71675ca",
        8_423_724,
    ),
    ("win32", "amd64", (3, 12)): LibtorrentArtifact(
        "libtorrent-2.1.1-cp312-cp312-win_amd64.whl",
        "493954405d15f14b9d9f9b1762ae78e7fecc5a44699f74cb433a9800fa3a7b45",
        5_018_631,
    ),
    ("win32", "amd64", (3, 13)): LibtorrentArtifact(
        "libtorrent-2.1.1-cp313-cp313-win_amd64.whl",
        "fa11aa801d5b9184f067f559c465d3074a4e878d9c671b00dd4930d6dfce2b46",
        5_018_669,
    ),
    ("darwin", "arm64", (3, 12)): LibtorrentArtifact(
        "libtorrent-2.1.1-cp312-cp312-macosx_14_0_arm64.whl",
        "768375f62631acd298a118d6e4f3e288af8220880d6432a49125f0539ce446d4",
        7_418_245,
    ),
    ("darwin", "arm64", (3, 13)): LibtorrentArtifact(
        "libtorrent-2.1.1-cp313-cp313-macosx_14_0_arm64.whl",
        "94767ff3e8bf4fb35cff3f638188ba5ca69dec331bf3b96254289bee635102a1",
        7_418_386,
    ),
}


def select_libtorrent_artifact(
    *,
    sys_platform: str = sys.platform,
    machine: str | None = None,
    python_version: tuple[int, int] | None = None,
) -> LibtorrentArtifact:
    actual_machine = (machine or platform.machine()).lower()
    actual_machine = {
        "x64": "amd64",
        "arm64": "aarch64" if sys_platform == "linux" else "arm64",
    }.get(actual_machine, actual_machine)
    key = (sys_platform, actual_machine, python_version or sys.version_info[:2])
    try:
        return LIBTORRENT_ARTIFACTS[key]
    except KeyError as error:
        version = ".".join(str(part) for part in key[2])
        raise UnsupportedLibtorrentRuntime(
            f"libtorrent {LIBTORRENT_VERSION} has no approved artifact for "
            f"{key[0]}/{key[1]}/CPython {version}"
        ) from error
