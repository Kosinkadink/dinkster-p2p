import sys
from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

_CORE = Path(__file__).parent / ".dinkster"
sys.path.extend((str(_CORE), str(_CORE / "tests")))


@pytest.fixture
def unix_socket_dir() -> Iterator[Path]:
    with TemporaryDirectory(prefix="dinkster-sock-", dir="/tmp") as directory:
        yield Path(directory)
