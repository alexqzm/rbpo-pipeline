import datetime as dt
import json
import shutil

import pytest

from rbpo_pipeline import analysis, triage
from conftest import FIX, state

TODAY = dt.date(2026, 11, 5)


def _sast(out, project, entries=(), fail_on="error", exclusions=None, scan_json=True):
    sarif = out / "sast" / "semgrep.sarif"
    sarif.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIX / "semgrep-findings.sarif", sarif)
    js = None
    if scan_json:
        js = out / "sast" / "semgrep.json"
        shutil.copy(FIX / "semgrep-findings.json", js)
    return analysis.sast(out, sarif, js, "p/python", fail_on, list(entries), project, exclusions or {}, TODAY)


@pytest.fixture
def project(repo):
    repo.commit({"src/bad.py": "x = 1\n", "src/other.py": "y = 2\n", "README.md": "demo\n"}, "init")
    return repo.path


def test_sast_untriaged_error_refutes(out, project):
    s = _sast(out, project)
    assert s["results"] == 2 and s["by_level"] == {"error": 1, "warning": 1}
    st = state(out, "5.10.3.4")
    assert st["state"] == "F" and st["summary"]["blocking"] == 1
    tri = json.loads((out / "sast" / "semgrep.triaged.sarif").read_text())
    assert [r["properties"]["rbpoTriage"] for r in tri["runs"][0]["results"]] == ["untriaged", "untriaged"]
    assert state(out, "5.10.3.2")["state"] == "P"
    cfg = state(out, "5.10.3.3")
    assert cfg["state"] == "P" and cfg["summary"]["rules"] == 2


def test_sast_false_positive_gets_sarif_suppression(out, project, tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text("sast:\n  - rule: 'python.lang.security.audit.subprocess-shell-true.*'\n    path: src/bad.py\n"
                 "    verdict: false_positive\n    reason: команда из констант\n", encoding="utf-8")
    _sast(out, project, triage.load(p))
    assert state(out, "5.10.3.4")["state"] == "P"
    res = json.loads((out / "sast" / "semgrep.triaged.sarif").read_text())["runs"][0]["results"]
    assert res[0]["suppressions"] == [{"kind": "external", "status": "accepted", "justification": "команда из констант"}]
    assert "suppressions" not in res[1]


def test_sast_confirmed_blocks_and_threshold_moves(out, project, tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text("sast:\n  - rule: 'python.lang.*'\n    verdict: confirmed\n    reason: исправить\n", encoding="utf-8")
    _sast(out, project, triage.load(p))
    assert state(out, "5.10.3.4")["state"] == "F"
    _sast(out, project, fail_on="none")
    assert state(out, "5.10.3.4")["state"] == "P"


def test_sast_warning_threshold(out, project, tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text("sast:\n  - rule: 'python.lang.*'\n    verdict: accepted\n    reason: принято\n", encoding="utf-8")
    _sast(out, project, triage.load(p), fail_on="warning")
    st = state(out, "5.10.3.4")
    assert st["state"] == "F" and st["summary"]["blocking"] == 1  # warning-правило без решения


def test_sast_language_coverage(out, project, repo):
    repo.commit({"scripts/x.lua": "print(1)\n"}, "lua")
    _sast(out, project)
    st = state(out, "5.10.3.2")
    assert st["state"] == "F" and st["summary"]["uncovered"] == ["Lua"]
    _sast(out, project, exclusions={"Lua": "служебный скрипт сборки, не входит в поставку"})
    st = state(out, "5.10.3.2")
    assert st["state"] == "P" and "Lua" in st["note"]


def test_sast_without_scan_json_is_not_presented(out, project):
    _sast(out, project, scan_json=False)
    assert state(out, "5.10.3.2")["state"] == "N"


def _sca(out, entries=(), fail_on="critical", grype="grype-old-deps.json"):
    for f in ("sbom-old-deps.cdx.json", grype):
        (out / "sca").mkdir(exist_ok=True)
        shutil.copy(FIX / f, out / "sca" / f)
    return analysis.sca(out, out / "sca" / "sbom-old-deps.cdx.json", out / "sca" / grype, fail_on, list(entries), TODAY)


def test_sca_components_and_critical_block(out):
    s = _sca(out)
    sb = state(out, "5.16.3.2")
    assert sb["state"] == "P" and sb["summary"]["components"] == 2  # файл requirements.txt не считается
    assert s["by_severity"] == {"critical": 2, "high": 1, "medium": 4}
    st = state(out, "5.16.3.4")
    assert st["state"] == "F" and st["summary"]["blocking"] == 2 and "pyyaml 5.3" in st["note"]
    assert st["summary"]["db_built"].startswith("2026-")


def test_sca_triage_by_alias_clears(out, tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text("vulnerabilities:\n"
                 "  - id: CVE-2020-14343\n    verdict: not_affected\n    reason: FullLoader не используется\n"
                 "  - id: GHSA-6757-jp84-gxfx\n    package: pyyaml\n    verdict: accepted\n    reason: принято до 0.2\n",
                 encoding="utf-8")
    _sca(out, triage.load(p))
    assert state(out, "5.16.3.4")["state"] == "P"
    _sca(out, triage.load(p), fail_on="high")
    st = state(out, "5.16.3.4")
    assert st["state"] == "F" and "requests 2.19.0" in st["note"]


def test_sca_clean_and_none_threshold(out):
    _sca(out, grype="grype-clean.json")
    assert state(out, "5.16.3.4")["state"] == "P"
    _sca(out, fail_on="none")
    assert state(out, "5.16.3.4")["state"] == "P"


@pytest.mark.parametrize("log, code, expected", [
    ("clamscan-clean.log", 0, "P"),
    ("clamscan-infected.log", 1, "F"),
    ("clamscan-clean.log", 2, "N"),
])
def test_av(out, log, code, expected):
    (out / "av").mkdir()
    shutil.copy(FIX / log, out / "av" / "clamscan.log")
    s = analysis.av(out, out / "av" / "clamscan.log", code, ["project", "site-packages"])
    st = state(out, "5.17.3.5")
    assert st["state"] == expected
    assert s["signatures"] == "27812" and s["engine"] == "1.5.4"


def test_av_not_run(out):
    analysis.av(out, None, None, [])
    assert state(out, "5.17.3.5")["state"] == "N"


def test_tests_pass_fail_absent(out):
    (out / "tests").mkdir()
    shutil.copy(FIX / "junit-pass.xml", out / "tests" / "junit.xml")
    s = analysis.tests(out, out / "tests" / "junit.xml", None, 0)
    assert s["tests"] == 3 and s["skipped"] == 1
    assert state(out, "5.18.3.2")["state"] == "P" and state(out, "5.18.3.3")["state"] == "P"
    shutil.copy(FIX / "junit-fail.xml", out / "tests" / "junit.xml")
    s = analysis.tests(out, out / "tests" / "junit.xml", None, 1)
    assert s["failed"] == ["tests.test_manifest::test_b", "tests.test_manifest::test_c"]
    assert state(out, "5.18.3.2")["state"] == "F"
    analysis.tests(out, None, None, None)
    assert state(out, "5.18.3.2")["state"] == "N"


def test_secrets_summary(out):
    (out / "secrets").mkdir()
    shutil.copy(FIX / "gitleaks-findings.json", out / "secrets" / "gitleaks.json")
    s = analysis.secrets(out, out / "secrets" / "gitleaks.json", 3, "fail")
    assert s["ran"] and s["findings"] == 1 and s["rules"] == {"github-pat": 1}
    shutil.copy(FIX / "gitleaks-clean.json", out / "secrets" / "gitleaks.json")
    s = analysis.secrets(out, out / "secrets" / "gitleaks.json", 0, "fail")
    assert s["ran"] and s["findings"] == 0
    s = analysis.secrets(out, out / "secrets" / "gitleaks.json", 1, "fail")
    assert not s["ran"]
