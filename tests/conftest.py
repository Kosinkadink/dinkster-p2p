import sys
from pathlib import Path

core_tests = Path(__file__).parent.parent / ".dinkster" / "tests"
if core_tests.is_dir():
    sys.path.insert(0, str(core_tests))
