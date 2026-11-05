import json
import os
import subprocess
from pathlib import Path

import pytest

FIX = Path(__file__).parent / "fixtures"


def state(out: Path, aid: str) -> dict:
    return json.loads((out / "states" / f"{aid}.json").read_text(encoding="utf-8"))


@pytest.fixture
def out(tmp_path: Path) -> Path:
    p = tmp_path / "evidence"
    p.mkdir()
    return p


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Тесты не должны видеть окружение GitHub Actions, в котором их могут запускать."""
    for k in list(os.environ):
        if k.startswith(("GITHUB_", "RUNNER_")) or k in ("GH_TOKEN", "ImageOS", "ImageVersion", "SOURCE_DATE_EPOCH"):
            monkeypatch.delenv(k, raising=False)


class Repo:
    def __init__(self, path: Path):
        self.path = path
        self.env = dict(os.environ, GIT_AUTHOR_NAME="Dev", GIT_AUTHOR_EMAIL="dev@example.invalid",
                        GIT_COMMITTER_NAME="Dev", GIT_COMMITTER_EMAIL="dev@example.invalid",
                        GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        self.git("init", "-q", "-b", "main")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args: str) -> str:
        r = subprocess.run(["git", "-C", str(self.path)] + list(args), capture_output=True, text=True, env=self.env)
        assert r.returncode == 0, r.stderr
        return r.stdout.strip()

    def commit(self, files: dict, msg: str) -> str:
        for name, text in files.items():
            p = self.path / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path, monkeypatch) -> Repo:
    p = tmp_path / "repo"
    p.mkdir()
    r = Repo(p)
    for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
              "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"):
        monkeypatch.setenv(k, r.env[k])
    return r
