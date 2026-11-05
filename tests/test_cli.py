import json
import shutil

from rbpo_pipeline.cli import main
from conftest import FIX, state


def test_cli_steps_and_decision(tmp_path, repo, monkeypatch, capsys):
    repo.commit({"src/bad.py": "1\n", "src/other.py": "2\n", "docs/guide.md": "# Guide\n## SAST\n",
                 "rbpo.yaml": "project: demo\norganizational:\n  '5.10.3.1': docs/guide.md#sast\n"}, "init")
    monkeypatch.chdir(repo.path)
    out = tmp_path / "ev"
    o = ["--out", str(out)]
    assert main(["source", *o, "--no-api"]) == 0
    assert main(["sast", *o, "--sarif", str(FIX / "semgrep-findings.sarif"),
                 "--json", str(FIX / "semgrep-findings.json"), "--config-name", "p/python"]) == 0
    assert (out / "sast" / "semgrep-findings.sarif").exists()  # входной файл скопирован в комплект
    assert main(["sca", *o, "--sbom", str(FIX / "sbom-old-deps.cdx.json"), "--grype", str(FIX / "grype-clean.json")]) == 0
    assert main(["secrets", *o, "--report", str(FIX / "gitleaks-clean.json"), "--exit-code", "0"]) == 0
    assert main(["av", *o, "--log", str(FIX / "clamscan-clean.log"), "--exit-code", "0", "--target", "project"]) == 0
    assert main(["tests", *o, "--junit", str(FIX / "junit-pass.xml"), "--exit-code", "0"]) == 0
    assert main(["org", *o]) == 0
    assert state(out, "5.10.3.1")["state"] == "P"
    assert main(["env", *o]) == 0
    assert state(out, "5.12.3.2")["state"] in ("P", "F")
    capsys.readouterr()
    assert main(["assemble", *o]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["decision"]["decision"] == "fail"  # SAST: срабатывание уровня error без решения
    assert main(["decision", *o]) == 1
    assert "5.10.3.4" in capsys.readouterr().out


def test_cli_input_errors_return_2(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rbpo.yaml").write_text("policy:\n  secrets: maybe\n", encoding="utf-8")
    assert main(["secrets", "--out", str(tmp_path / "ev")]) == 2
    assert "policy.secrets" in capsys.readouterr().err
    (tmp_path / "rbpo.yaml").write_text("organizational:\n  '9.9.9.9': x.md\n", encoding="utf-8")
    assert main(["org", "--out", str(tmp_path / "ev")]) == 2
    assert main(["decision", "--out", str(tmp_path / "none")]) == 2


def test_cli_missing_reports_mark_not_presented(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "ev"
    assert main(["sast", "--out", str(out), "--sarif", str(tmp_path / "none.sarif")]) == 0
    assert state(out, "5.10.3.4")["state"] == "N"
    assert main(["sca", "--out", str(out), "--sbom", str(tmp_path / "none.json")]) == 0
    assert state(out, "5.16.3.2")["state"] == "N" and state(out, "5.16.3.4")["state"] == "N"
    shutil.rmtree(out)
