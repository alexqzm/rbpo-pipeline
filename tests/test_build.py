import json

import pytest

from rbpo_pipeline import build
from conftest import state

CMD = 'mkdir -p dist && printf "%s" "$SOURCE_DATE_EPOCH" > dist/app-1.0.tar.gz && echo built'


def test_build_run_records_log_and_sums(out, repo, monkeypatch):
    repo.commit({"a.txt": "1\n"}, "init")
    code = build.run(out, "build", CMD, repo.path, "dist")
    assert code == 0
    info = json.loads((out / "build" / "build.json").read_text())
    epoch = repo.git("log", "-1", "--format=%ct")
    assert info["source_date_epoch"] == epoch and info["exit_code"] == 0
    assert (repo.path / "dist" / "app-1.0.tar.gz").read_text() == epoch
    sums = build.read_sums(out / "build" / "SHA256SUMS")
    assert list(sums) == ["app-1.0.tar.gz"] and sums["app-1.0.tar.gz"] == info["outputs"][0]["sha256"]
    log = (out / "build" / "build.log").read_text()
    assert "built" in log and "# exit code: 0" in log
    assert info["log_sha256"] == build.sha256_file(out / "build" / "build.log")
    assert state(out, "5.13.3.4")["state"] == "P"
    with pytest.raises(build.BuildError, match="не пуст"):
        build.run(out, "build", CMD, repo.path, "dist")
    assert build.run(out, "rebuild", CMD, repo.path, "dist", clean=True) == 0
    assert (out / "rebuild" / "SHA256SUMS").exists()


def test_build_failure_returns_code(out, repo):
    repo.commit({"a.txt": "1\n"}, "init")
    assert build.run(out, "build", "echo no; exit 3", repo.path, "dist") == 3
    st = state(out, "5.13.3.4")
    assert st["state"] == "P" and st["summary"]["exit_code"] == 3


def _dist(tmp_path, name, files):
    d = tmp_path / name
    d.mkdir()
    for n, text in files.items():
        (d / n).write_text(text)
    return d


def test_store_verify(out, tmp_path):
    d = _dist(tmp_path, "dist", {"a.whl": "A", "a.tar.gz": "B"})
    build.write_sums(out / "build" / "SHA256SUMS", build.checksums(d))
    build.store_verify(out, d, out / "build" / "SHA256SUMS", {"artifact_id": "42"})
    st = state(out, "5.13.3.5")
    assert st["state"] == "P" and "артефакт 42" in st["note"]
    (d / "a.whl").write_text("tampered")
    (d / "x.txt").write_text("extra")
    build.store_verify(out, d, out / "build" / "SHA256SUMS", {})
    st = state(out, "5.13.3.5")
    assert st["state"] == "F" and st["summary"]["changed"] == ["a.whl"] and st["summary"]["extra"] == ["x.txt"]


def test_repro(out, tmp_path):
    a = build.write_sums(tmp_path / "a", {"x.whl": "1" * 64})
    b = build.write_sums(tmp_path / "b", {"x.whl": "1" * 64})
    build.repro(out, a, b)
    assert state(out, "5.13.3.6")["state"] == "P"
    b = build.write_sums(tmp_path / "b", {"x.whl": "2" * 64})
    build.repro(out, a, b)
    st = state(out, "5.13.3.6")
    assert st["state"] == "F" and "x.whl" in st["note"]
    build.repro(out, a, tmp_path / "missing")
    assert state(out, "5.13.3.6")["state"] == "N"


def test_attest_verify_skip_and_missing_gh(out, tmp_path, monkeypatch):
    d = _dist(tmp_path, "dist", {"a.whl": "A"})
    build.attest_verify(out, d, "o/r", "o/p/.github/workflows/rbpo.yml", "abc", skip="запрос на слияние")
    st = state(out, "5.20.3.4")
    assert st["state"] == "N" and "запрос на слияние" in st["note"]
    monkeypatch.setattr(build.shutil, "which", lambda _: None)
    build.attest_verify(out, d, "o/r", "", "")
    assert "нет gh" in state(out, "5.20.3.4")["note"]


def test_attest_verify_with_fake_gh(out, tmp_path, monkeypatch):
    d = _dist(tmp_path, "dist", {"a.whl": "A", "b.tar.gz": "B"})
    fake = tmp_path / "bin" / "gh"
    fake.parent.mkdir()
    verified = [{"verificationResult": {"statement": {"predicateType": "https://slsa.dev/provenance/v1"},
                                        "signature": {"certificate": {
                                            "buildSignerURI": "https://github.com/o/p/.github/workflows/rbpo.yml@refs/heads/main",
                                            "sourceRepositoryURI": "https://github.com/o/r",
                                            "sourceRepositoryDigest": "abc", "runnerEnvironment": "github-hosted"}}}}]
    (tmp_path / "ok.json").write_text(json.dumps(verified))
    fake.write_text('#!/bin/sh\ncase "$3" in *b.tar.gz) echo "no attestations" >&2; exit 1;; esac\n'
                    f'cat {tmp_path / "ok.json"}\n')
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake.parent}:/usr/bin:/bin")
    res = build.attest_verify(out, d, "o/r", "o/p/.github/workflows/rbpo.yml", "abc")
    by = {r["file"]: r for r in res["results"]}
    assert by["a.whl"]["verified"] and by["a.whl"]["runner"] == "github-hosted"
    assert not by["b.tar.gz"]["verified"] and "no attestations" in by["b.tar.gz"]["error"]
    st = state(out, "5.20.3.4")
    assert st["state"] == "F" and "b.tar.gz" in st["note"]
