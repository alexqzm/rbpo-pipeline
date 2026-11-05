import datetime as dt

import pytest

from rbpo_pipeline import config, triage


def test_defaults_without_file(tmp_path):
    cfg = config.load(str(tmp_path / "absent.yaml"))
    assert cfg["policy"]["sast_fail_on"] == "error"
    assert cfg["policy"]["sca_fail_on"] == "critical"
    assert cfg["policy"]["commit_signatures"] == "report"
    assert cfg["organizational"] == {}


def test_policy_values_are_validated(tmp_path):
    p = tmp_path / "rbpo.yaml"
    p.write_text("policy:\n  sca_fail_on: severe\n", encoding="utf-8")
    with pytest.raises(config.ConfigError, match="sca_fail_on"):
        config.load(str(p))


@pytest.mark.parametrize("text, match", [
    ("polcy: {}\n", "неизвестные ключи"),
    ("policy:\n  secret: fail\n", "policy: неизвестные ключи"),
    ("scope:\n  exclude:\n    - process: '5.21'\n", "без обоснования"),
    ("sast_exclude_languages:\n  Lua: ''\n", "без обоснования"),
])
def test_config_errors(tmp_path, text, match):
    p = tmp_path / "rbpo.yaml"
    p.write_text(text, encoding="utf-8")
    with pytest.raises(config.ConfigError, match=match):
        config.load(str(p))


def test_at_or_above():
    assert config.at_or_above("critical", "high", config.SCA_LEVELS)
    assert config.at_or_above("high", "high", config.SCA_LEVELS)
    assert not config.at_or_above("medium", "high", config.SCA_LEVELS)
    assert not config.at_or_above("critical", "none", config.SCA_LEVELS)
    assert not config.at_or_above("unknown", "low", config.SCA_LEVELS)


def test_triage_requires_reason_and_known_verdicts(tmp_path):
    p = tmp_path / "triage.yaml"
    p.write_text("sast:\n  - rule: x\n    verdict: ignore\nvulnerabilities:\n  - id: CVE-1\n    verdict: accepted\n",
                 encoding="utf-8")
    with pytest.raises(triage.TriageError) as e:
        triage.load(p)
    msg = str(e.value)
    assert "verdict 'ignore'" in msg and "sast[0]: нет обоснования" in msg and "vulnerabilities[0]: нет обоснования" in msg


def test_triage_matching_globs_lines_and_expiry(tmp_path):
    p = tmp_path / "triage.yaml"
    p.write_text(
        "sast:\n"
        "  - rule: 'python.lang.*'\n    path: 'src/*.py'\n    line: 5\n    verdict: false_positive\n    reason: r1\n"
        "  - rule: 'python.lang.*'\n    verdict: accepted\n    reason: r2\n    until: 2026-01-31\n"
        "vulnerabilities:\n"
        "  - id: CVE-2020-14343\n    package: 'py*'\n    verdict: not_affected\n    reason: r3\n",
        encoding="utf-8")
    entries = triage.load(p)
    today = dt.date(2026, 11, 5)
    e, expired = triage.match_sast(entries, "python.lang.security.x", "src/bad.py", 5, today)
    assert e.reason == "r1" and expired == []
    e, expired = triage.match_sast(entries, "python.lang.security.x", "src/bad.py", 6, today)
    assert e is None and [x.reason for x in expired] == ["r2"]
    e, _ = triage.match_sast(entries, "python.lang.security.x", "src/bad.py", 6, dt.date(2026, 1, 1))
    assert e.reason == "r2"
    e, _ = triage.match_vuln(entries, ["GHSA-8q59-q68h-6hv4", "CVE-2020-14343"], "pyyaml", today)
    assert e.verdict == "not_affected"
    e, _ = triage.match_vuln(entries, ["CVE-2020-14343"], "requests", today)
    assert e is None


def test_missing_triage_file_is_empty(tmp_path):
    assert triage.load(tmp_path / "none.yaml") == []
