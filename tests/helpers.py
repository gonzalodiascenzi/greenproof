import importlib
import json
import os
import shutil
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


@contextmanager
def temporary_repo_copy():
    with tempfile.TemporaryDirectory() as tmpdir:
        target = Path(tmpdir) / "repo"
        shutil.copytree(
            REPO_ROOT,
            target,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", "*.db-shm", "*.db-wal"),
        )
        yield target


def load_fixture(name):
    with open(REPO_ROOT / "tests" / "fixtures" / name, encoding="utf-8") as f:
        return json.load(f)


def load_script_module(module_name, repo_root):
    os.environ["GREENPROOF_ROOT"] = str(repo_root)
    for dep in (module_name, "gp_common", "gp_state"):
        if dep in sys.modules:
            del sys.modules[dep]
    return importlib.import_module(module_name)
