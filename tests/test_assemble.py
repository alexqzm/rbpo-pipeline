import json
import shutil

import yaml

from rbpo_pipeline import analysis, assemble, build, config
from rbpo_pipeline.states import put_state, sha256_file
from conftest import FIX, state


def _cfg(**policy):
    cfg = config.load(None)
    cfg["policy"].update(policy)
    cfg["project"] = "demo"
    cfg["organizational"] = {"5.10.3.1": "docs/guide.md#sast"}
    return cfg


def _all_pass(out):
    for aid in assemble.AUTOMATED:
        put_state(out, aid, "P", [], {}, "ok", "test")
    put_state(out, "5.10.3.1", "N", [], {}, "документ docs/guide.md не найден", "organizational")
    (out / "secrets").mkdir(exist_ok=True)
    (out / "secrets" / "summary.json").write_text(json.dumps({"ran": True, "findings": 0, "policy": "fail"}))
    for d, fail_on in (("sast", "error"), ("sca", "critical")):
        (out / d).mkdir(exist_ok=True)
        (out / d / "triage.json").write_text(json.dumps({"fail_on": fail_on, "items": []}))


def test_assemble_pass_writes_bundle(out):
    _all_pass(out)
    res = assemble.assemble(out, _cfg(), {"analyze": {"result": "success"}})
    assert res["decision"]["decision"] == "pass"
    man = yaml.safe_load((out / "manifest.yaml").read_text(encoding="utf-8"))
    assert man["schema"] == "rbpo-evidence/manifest/v1" and len(man["artifacts"]) == 17
    assert man["artifacts"]["5.10.3.1"]["state"] == "N"
    assert res["overall"] == "missing" and res["presented"] == 16 and res["total"] == 98
    report = (out / "report.md").read_text(encoding="utf-8")
    assert report.startswith("# Полнота свидетельств РБПО: demo")
    idx = json.loads((out / "index.json").read_text())["files"]
    assert idx["manifest.yaml"] == sha256_file(out / "manifest.yaml") and "index.json" not in idx
    summary = (out / "SUMMARY.md").read_text(encoding="utf-8")
    assert "выпуск допустим" in summary and "| 5.13.3.6 |" in summary and "| 5.10.3.1 |" in summary


def test_missing_steps_become_n_and_failures_block(out):
    put_state(out, "5.18.3.2", "F", [], {}, "тестов 3, не прошли 1", "junit")
    res = assemble.assemble(out, _cfg(), {"build": {"result": "failure"}})
    man = yaml.safe_load((out / "manifest.yaml").read_text(encoding="utf-8"))
    assert man["artifacts"]["5.13.3.6"]["state"] == "N"
    reasons = res["decision"]["reasons"]
    assert any(r.startswith("5.18.3.2") for r in reasons)
    assert "поиск секретов не выполнен" in reasons
    assert any("задача build" in r for r in reasons)
    assert res["overall"] == "refuted"


def test_reproducibility_report_policy_and_secrets_report(out):
    _all_pass(out)
    put_state(out, "5.13.3.6", "F", [], {}, "повторная сборка дала другие результаты", "test")
    (out / "secrets" / "summary.json").write_text(json.dumps({"ran": True, "findings": 2, "policy": "report"}))
    res = assemble.assemble(out, _cfg(reproducible="report", secrets="report"))
    assert res["decision"]["decision"] == "pass"
    assert state(out, "5.13.3.6")["state"] == "F"  # свидетельство остаётся опровергающим
    res = assemble.assemble(out, _cfg())
    assert res["decision"]["decision"] == "fail" and len(res["decision"]["reasons"]) == 2


def test_release_analysis_from_triage(out, repo, tmp_path):
    repo.commit({"src/bad.py": "1\n", "src/other.py": "2\n"}, "init")
    (out / "sast").mkdir()
    shutil.copy(FIX / "semgrep-findings.sarif", out / "sast" / "s.sarif")
    from rbpo_pipeline import triage
    t = tmp_path / "t.yaml"
    t.write_text("sast:\n  - rule: 'python.lang.*'\n    verdict: accepted\n    reason: влияние оценено\n", encoding="utf-8")
    analysis.sast(out, out / "sast" / "s.sarif", None, "p/python", "error", triage.load(t), repo.path, {})
    (out / "sca").mkdir()
    for f in ("sbom-old-deps.cdx.json", "grype-old-deps.json"):
        shutil.copy(FIX / f, out / "sca" / f)
    analysis.sca(out, out / "sca" / "sbom-old-deps.cdx.json", out / "sca" / "grype-old-deps.json", "critical", [])
    res = assemble.release_analysis(out)
    assert len(res["sast"]["accepted"]) == 1 and res["sast"]["below_threshold"] == {"warning": 1}
    assert len(res["sca"]["blocking"]) == 2 and res["sca"]["below_threshold"] == {"high": 1, "medium": 4}
    st = state(out, "5.20.3.2")
    assert st["state"] == "F" and st["summary"]["blocking"] == 2


def test_release_analysis_without_inputs(out):
    assemble.release_analysis(out)
    assert state(out, "5.20.3.2")["state"] == "N"


def test_build_exit_code_blocks(out, repo):
    _all_pass(out)
    repo.commit({"a": "1"}, "init")
    build.run(out, "build", "exit 4", repo.path, "dist")
    res = assemble.assemble(out, _cfg())
    assert "сборка завершилась с кодом 4" in res["decision"]["reasons"]
