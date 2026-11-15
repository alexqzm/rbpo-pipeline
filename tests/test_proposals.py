import argparse
import copy
import datetime as dt
import json
import os
import re
import shutil
from pathlib import Path

import pytest
import yaml

from rbpo_pipeline import analysis, proposals, triage
from rbpo_pipeline.cli import build_parser, main
from rbpo_pipeline.states import write_json
from conftest import FIX

TODAY = dt.date(2026, 11, 16)
ROOT = Path(__file__).parent.parent
KIT = ROOT / "agent"
SHELL_RULE = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
FILES = {
    "src/bad.py": 'import subprocess\n\nCMD = "ls -la"\n\nsubprocess.run(CMD, shell=True)\n',
    "src/other.py": "import yaml\n\ndef load(fh):\n    return yaml.safe_load(fh)\n",
    "README.md": "demo\n",
}


def _evidence(out: Path, project: Path, entries=(), sca_fail_on="high") -> Path:
    """Комплект свидетельств из фикстур через шаги конвейера: порог high, блокируют 3 уязвимости и 1 срабатывание."""
    for sub, names in (("sca", ("sbom-old-deps.cdx.json", "grype-old-deps.json")),
                       ("sast", ("semgrep-findings.sarif", "semgrep-findings.json"))):
        (out / sub).mkdir(parents=True, exist_ok=True)
        for name in names:
            shutil.copy(FIX / name, out / sub / name)
    analysis.sca(out, out / "sca" / "sbom-old-deps.cdx.json", out / "sca" / "grype-old-deps.json", sca_fail_on,
                 list(entries), TODAY)
    analysis.sast(out, out / "sast" / "semgrep-findings.sarif", out / "sast" / "semgrep-findings.json", "p/python",
                  "error", list(entries), project, {}, TODAY)
    return out


@pytest.fixture
def project(repo):
    repo.commit(FILES, "init")
    return repo.path


@pytest.fixture
def evidence(out, project):
    return _evidence(out, project)


def good() -> dict:
    return {
        "schema": proposals.SCHEMA,
        "meta": {"agent": "оболочка 1.0", "model": "модель 1.0"},
        "proposals": [
            {"kind": "vulnerability", "id": "GHSA-8q59-q68h-6hv4", "package": "pyyaml", "version": "5.3",
             "verdict": "not_affected",
             "reason": "YAML в проекте читается только через safe_load, FullLoader не используется.",
             "until": "2027-02-01",
             "refs": [{"path": "src/other.py", "line": 4, "quote": "return yaml.safe_load(fh)"}]},
            {"kind": "sast", "rule": SHELL_RULE, "path": "src/bad.py", "line": 5, "verdict": "false_positive",
             "reason": "Команда собрана из константы CMD, ввод пользователя в неё не попадает.",
             "until": "2027-02-01",
             "refs": [{"path": "src/bad.py", "line": 3, "quote": 'CMD = "ls -la"'}]},
        ],
    }


def vuln(doc: dict) -> dict:
    return doc["proposals"][0]


def sast(doc: dict) -> dict:
    return doc["proposals"][1]


def put(project: Path, doc, name="p.yaml") -> Path:
    f = project / ".rbpo" / "proposals" / name
    f.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(doc, bytes):
        f.write_bytes(doc)
    else:
        f.write_text(doc if isinstance(doc, str) else yaml.safe_dump(doc, allow_unicode=True, sort_keys=False),
                     encoding="utf-8")
    return f


def run(project: Path, evidence: Path, doc, **kw) -> dict:
    return proposals.check([put(project, doc)], evidence, project, TODAY, **kw)


def codes(res: dict) -> list:
    return sorted({v["code"] for r in res["files"] for v in r["violations"]})


# ---------------------------------------------------------------- очередь
def test_queue_lists_what_needs_decision(evidence):
    q = proposals.queue(evidence)
    assert q["summary"] == {"blocking": 4, "below_threshold": 5, "confirmed": 0, "decided": 0, "expired": 0}
    assert q["fail_on"] == {"sca": "high", "sast": "error"}
    assert [i["key"] for i in q["items"][:4]] == [
        "vulnerability:GHSA-6757-jp84-gxfx:pyyaml@5.3", "vulnerability:GHSA-8q59-q68h-6hv4:pyyaml@5.3",
        "vulnerability:GHSA-x84v-xcm2-53pg:requests@2.19.0", f"sast:{SHELL_RULE}:src/bad.py:5"]
    assert [i["status"] for i in q["items"]] == ["blocking"] * 4 + ["below_threshold"] * 5
    text = proposals.render_queue(q)
    assert "блокирует выпуск 4" in text and "pyyaml 5.3, исправлено в 5.4" in text and "src/bad.py:5" in text


def test_queue_decided_confirmed_and_expired(out, project, tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text("vulnerabilities:\n"
                 "  - id: GHSA-8q59-q68h-6hv4\n    verdict: not_affected\n    reason: r1\n"
                 "  - id: GHSA-6757-jp84-gxfx\n    verdict: accepted\n    reason: r2\n    until: 2026-01-31\n"
                 "  - id: GHSA-x84v-xcm2-53pg\n    verdict: confirmed\n    reason: r3\n", encoding="utf-8")
    q = proposals.queue(_evidence(out, project, triage.load(p)))
    assert q["summary"] == {"blocking": 2, "below_threshold": 5, "confirmed": 1, "decided": 1, "expired": 1}
    assert "vulnerability:GHSA-8q59-q68h-6hv4:pyyaml@5.3" not in [i["key"] for i in q["items"]]
    assert "прежнее решение истекло" in proposals.render_queue(q)


def test_queue_reports_secrets_without_details(evidence):
    (evidence / "secrets").mkdir()
    shutil.copy(FIX / "gitleaks-findings.json", evidence / "secrets" / "gitleaks.json")
    analysis.secrets(evidence, evidence / "secrets" / "gitleaks.json", 3, "fail")
    q = proposals.queue(evidence)
    assert q["secrets"] == {"ran": True, "findings": 1}
    assert "Секреты: найдено 1" in proposals.render_queue(q) and "github-pat" not in json.dumps(q)


def test_queue_needs_analysis_results(tmp_path):
    with pytest.raises(proposals.ProposalError, match="нет результатов анализа"):
        proposals.queue(tmp_path)


# ---------------------------------------------------------------- проверка предложений
def test_valid_proposals_pass_and_fit_the_triage_file(evidence, project, tmp_path):
    res = run(project, evidence, good())
    assert res["ok"] and codes(res) == []
    assert res["summary"] == {"proposals": 2, "ok": 2, "rejected": 0, "violations": 0, "blocking": 4,
                              "blocking_cleared": 2, "blocking_confirmed": 0, "blocking_without_proposal": 2}
    assert [x["key"] for x in res["files"][0]["proposals"]] == [
        "vulnerability:GHSA-8q59-q68h-6hv4:pyyaml@5.3", f"sast:{SHELL_RULE}:src/bad.py:5"]
    # Фрагмент для переноса читается загрузчиком разметки и снимает именно эти элементы.
    t = tmp_path / "triage.yaml"
    t.write_text(proposals.fragment(res), encoding="utf-8")
    entries = triage.load(t)
    assert [(e.kind, e.verdict) for e in entries] == [("sast", "false_positive"), ("vuln", "not_affected")]
    q = proposals.queue(_evidence(evidence, project, entries))
    assert q["summary"]["decided"] == 2 and q["summary"]["blocking"] == 2


def test_confirmed_needs_neither_refs_nor_until(evidence, project):
    doc = good()
    for k in ("refs", "until"):
        vuln(doc).pop(k)
    vuln(doc).update(verdict="confirmed", reason="Пакет используется для разбора входных файлов, нужно обновление.")
    res = run(project, evidence, doc)
    assert res["ok"] and res["summary"]["blocking_confirmed"] == 1 and res["summary"]["blocking_cleared"] == 1


def test_related_identifier_and_multiline_quote(evidence, project):
    doc = good()
    vuln(doc).update(id="CVE-2020-14343")
    vuln(doc)["refs"][0].update(line=3, quote="def load(fh):\n        return   yaml.safe_load(fh)\n")
    res = run(project, evidence, doc)
    assert res["ok"] and res["files"][0]["proposals"][0]["key"] == "vulnerability:GHSA-8q59-q68h-6hv4:pyyaml@5.3"
    assert "id: CVE-2020-14343" in proposals.fragment(res)


def test_empty_list_of_proposals_is_valid(evidence, project):
    res = run(project, evidence, dict(good(), proposals=[]))
    assert res["ok"] and res["summary"]["blocking_without_proposal"] == 4 and proposals.fragment(res) == ""


CASES = [
    ("шаблон пакета", lambda d: vuln(d).update(package="py*"), ["ПП03"]),
    ("шаблон идентификатора", lambda d: vuln(d).update(id="GHSA-*"), ["ПП03"]),
    ("шаблон правила", lambda d: sast(d).update(rule="python.lang.*"), ["ПП03"]),
    ("шаблон пути", lambda d: sast(d).update(path="src/*.py"), ["ПП03"]),
    ("принятие риска", lambda d: vuln(d).update(verdict="accepted"), ["ПП04"]),
    ("принятие риска по срабатыванию", lambda d: sast(d).update(verdict="accepted"), ["ПП04"]),
    ("неизвестный вердикт", lambda d: vuln(d).update(verdict="ignore"), ["ПП01"]),
    ("вердикт другого вида", lambda d: vuln(d).update(verdict="false_positive"), ["ПП01"]),
    ("нет такой уязвимости", lambda d: vuln(d).update(id="GHSA-0000-0000-0000"), ["ПП02"]),
    ("уязвимость другого пакета", lambda d: vuln(d).update(package="requests"), ["ПП02"]),
    ("нет такого срабатывания", lambda d: sast(d).update(line=6), ["ПП02"]),
    ("версия устарела", lambda d: vuln(d).update(version="5.4"), ["ПП10"]),
    ("версия числом", lambda d: vuln(d).update(version=5.3), ["ПП01"]),
    ("короткое обоснование", lambda d: vuln(d).update(reason="не используется"), ["ПП05"]),
    ("нет ссылок на код", lambda d: vuln(d).pop("refs"), ["ПП06"]),
    ("пустой список ссылок", lambda d: sast(d).update(refs=[]), ["ПП06"]),
    ("цитата выдумана", lambda d: vuln(d)["refs"][0].update(quote="return yaml.full_load(fh)"), ["ПП07"]),
    ("цитата из другой строки", lambda d: vuln(d)["refs"][0].update(line=3), ["ПП07"]),
    ("строки нет", lambda d: vuln(d)["refs"][0].update(line=40), ["ПП07"]),
    ("файла нет", lambda d: vuln(d)["refs"][0].update(path="src/none.py"), ["ПП07"]),
    ("выход из проекта", lambda d: vuln(d)["refs"][0].update(path="../secret.py"), ["ПП07"]),
    ("абсолютный путь", lambda d: vuln(d)["refs"][0].update(path="/etc/hostname"), ["ПП07"]),
    ("ссылка на файл разметки", lambda d: vuln(d)["refs"][0].update(path=".rbpo/triage.yaml"), ["ПП07"]),
    ("ссылка на каталог git", lambda d: vuln(d)["refs"][0].update(path=".git/config"), ["ПП07"]),
    ("цитата из двух знаков", lambda d: vuln(d)["refs"][0].update(quote="fh"), ["ПП07"]),
    ("плохая ссылка у подтверждения", lambda d: (vuln(d).update(verdict="confirmed"),
                                                 vuln(d)["refs"][0].update(quote="import requests")), ["ПП07"]),
    ("нет срока", lambda d: vuln(d).pop("until"), ["ПП08"]),
    ("срок прошёл", lambda d: vuln(d).update(until="2026-11-15"), ["ПП08"]),
    ("срок слишком далеко", lambda d: vuln(d).update(until="2027-06-01"), ["ПП08"]),
    ("срок не дата", lambda d: vuln(d).update(until="скоро"), ["ПП01"]),
    ("повтор", lambda d: d["proposals"].append(copy.deepcopy(vuln(d))), ["ПП09"]),
    ("повтор через связанный идентификатор",
     lambda d: d["proposals"].append(dict(copy.deepcopy(vuln(d)), id="CVE-2020-14343")), ["ПП09"]),
    ("лишний ключ", lambda d: vuln(d).update(approved=True), ["ПП01"]),
    ("нет обоснования", lambda d: vuln(d).pop("reason"), ["ПП01"]),
    ("неизвестный вид", lambda d: vuln(d).update(kind="secret"), ["ПП01"]),
    ("предложение не отображение", lambda d: d["proposals"].append("снять всё"), ["ПП01"]),
    ("ссылка без цитаты", lambda d: vuln(d)["refs"][0].pop("quote"), ["ПП01"]),
    ("номер строки не число", lambda d: vuln(d)["refs"][0].update(line="4"), ["ПП01"]),
    ("невидимые символы", lambda d: vuln(d).update(reason=vuln(d)["reason"] + "‮"), ["ПП01"]),
    ("нет модели", lambda d: d["meta"].pop("model"), ["ПП01"]),
    ("другая схема", lambda d: d.update(schema="v0"), ["ПП01"]),
    ("лишний ключ файла", lambda d: d.update(sast=[]), ["ПП01"]),
    ("предложения не списком", lambda d: d.update(proposals={"снять": "всё"}), ["ПП01"]),
    ("слишком много предложений",
     lambda d: d.update(proposals=[copy.deepcopy(vuln(d)) for _ in range(proposals.MAX_PROPOSALS + 1)]), ["ПП01"]),
    ("несколько нарушений сразу", lambda d: vuln(d).update(package="req*", verdict="accepted", reason="ок"),
     ["ПП03", "ПП04", "ПП05"]),
]


@pytest.mark.parametrize("mutate, expected", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_hostile_proposals_are_rejected(evidence, project, mutate, expected):
    doc = good()
    mutate(doc)
    res = run(project, evidence, doc)
    assert codes(res) == expected and not res["ok"]
    assert proposals.RULES[expected[0]] in proposals.render_text(res)


BROKEN = [
    ("повтор ключа", "schema: a\nschema: b\nproposals: []\n"),
    ("список", "- просто список\n"),
    ("не YAML", "proposals: [\n"),
    ("строка", "просто текст"),
    ("больше мебибайта", "x: " + "я" * proposals.MAX_FILE_BYTES),
    ("не UTF-8", b"\xff\xfe\x00\x00"),
    ("повтор ключа в предложении",
     "proposals:\n  - kind: sast\n    verdict: confirmed\n    verdict: false_positive\n"),
    ("якоря", "a: &a [x, x, x]\nb: &b [*a, *a, *a]\nc: [*b, *b, *b]\n"),
]


@pytest.mark.parametrize("text", [b[1] for b in BROKEN], ids=[b[0] for b in BROKEN])
def test_broken_files_are_format_violations(evidence, project, text):
    res = run(project, evidence, text)
    assert codes(res) == ["ПП01"] and res["summary"]["proposals"] == 0 and not res["ok"]


WEIRD = [None, True, False, 0, -1, 1.5, 10 ** 30, "", " ", "\x00", "*", "x" * 3000, [], [[]], [None], {}, {"a": 1},
         {1: 2}, dt.date(2027, 1, 1), dt.datetime(2027, 1, 1, 12, 0)]
FIELDS = [("schema",), ("meta",), ("meta", "agent"), ("meta", "model"), ("meta", "created"), ("proposals",),
          ("proposals", 0), ("proposals", 0, "kind"), ("proposals", 0, "id"), ("proposals", 0, "package"),
          ("proposals", 0, "version"), ("proposals", 0, "verdict"), ("proposals", 0, "reason"),
          ("proposals", 0, "until"), ("proposals", 0, "refs"), ("proposals", 0, "refs", 0),
          ("proposals", 0, "refs", 0, "path"), ("proposals", 0, "refs", 0, "line"),
          ("proposals", 0, "refs", 0, "quote"), ("proposals", 0, "refs", 0, "note"), ("proposals", 1, "rule"),
          ("proposals", 1, "path"), ("proposals", 1, "line")]


def test_any_value_in_any_field_gives_a_result_not_a_crash(evidence, project):
    """Файл недоверенный: что бы ни стояло в полях, проверка даёт результат, пригодный для вывода и JSON."""
    outcomes = set()
    for path in FIELDS:
        for value in WEIRD:
            doc = good()
            node = doc
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            res = run(project, evidence, doc)
            json.dumps(res)
            assert proposals.render_text(res) and proposals.render_markdown(res)
            assert res["ok"] == (codes(res) == [])
            outcomes.add(res["ok"])
    assert outcomes == {True, False}  # среди подстановок есть и допустимые значения


def test_existing_decision_is_not_reconsidered_but_expired_one_is(out, project, tmp_path):
    p = tmp_path / "t.yaml"
    p.write_text("vulnerabilities:\n  - id: GHSA-8q59-q68h-6hv4\n    verdict: accepted\n    reason: принято\n",
                 encoding="utf-8")
    res = run(project, _evidence(out, project, triage.load(p)), good())
    assert codes(res) == ["ПП11"]
    p.write_text(p.read_text(encoding="utf-8") + "    until: 2026-01-31\n", encoding="utf-8")
    assert run(project, _evidence(out, project, triage.load(p)), good())["ok"]


def test_references_must_be_plain_relative_paths_to_project_code(evidence, project):
    """Цитата везде настоящая: отклоняется сам путь, а не несовпадение текста."""
    (project / ".rbpo").mkdir(exist_ok=True)
    (project / ".rbpo" / "notes.md").write_text("return yaml.safe_load(fh)\n", encoding="utf-8")
    safe_load = "return yaml.safe_load(fh)"
    for path, line, quote, why in (
            (str(project / "src" / "other.py"), 4, safe_load, "относительным"),
            ("src/../src/other.py", 4, safe_load, "относительным"),
            ("src\\other.py", 4, safe_load, "относительным"),
            ("~/src/other.py", 4, safe_load, "относительным"),
            ("C:src/other.py", 4, safe_load, "относительным"),
            (".rbpo/notes.md", 1, safe_load, "служебный каталог"),
            (".git/config", 2, "repositoryformatversion = 0", "служебный каталог")):
        doc = good()
        vuln(doc)["refs"][0].update(path=path, line=line, quote=quote)
        res = run(project, evidence, doc)
        assert codes(res) == ["ПП07"] and why in res["files"][0]["violations"][0]["message"], path


def test_symlink_out_of_project_is_rejected(evidence, project, tmp_path):
    (tmp_path / "outside.py").write_text("return yaml.safe_load(fh)\n", encoding="utf-8")
    os.symlink(tmp_path / "outside.py", project / "src" / "link.py")
    doc = good()
    vuln(doc)["refs"][0].update(path="src/link.py", line=1)
    assert codes(run(project, evidence, doc)) == ["ПП07"]


def test_reference_into_evidence_bundle_is_rejected(project):
    ev = _evidence(project / "build" / "ev", project)
    doc = good()
    vuln(doc)["refs"][0].update(path="build/ev/sca/triage.json", line=2, quote='"fail_on": "high"')
    res = run(project, ev, doc)
    assert codes(res) == ["ПП07"] and "служебный каталог" in res["files"][0]["violations"][0]["message"]


def test_duplicates_are_found_across_files(evidence, project):
    files = [put(project, good(), "a.yaml"), put(project, good(), "b.yaml")]
    res = proposals.check(files, evidence, project, TODAY)
    assert [codes({"files": [r]}) for r in res["files"]] == [[], ["ПП09"]]
    assert res["summary"]["ok"] == 2 and res["summary"]["rejected"] == 2


def test_max_days_is_configurable(evidence, project):
    assert codes(run(project, evidence, good(), max_days=30)) == ["ПП08"]


def test_warnings_about_full_clearing_and_stale_bundle(evidence, project):
    doc = good()
    for vid, pkg, ver in (("GHSA-6757-jp84-gxfx", "pyyaml", "5.3"), ("GHSA-x84v-xcm2-53pg", "requests", "2.19.0")):
        doc["proposals"].append(dict(copy.deepcopy(vuln(doc)), id=vid, package=pkg, version=ver))
    (evidence / "source").mkdir()
    (evidence / "source" / "integrity.json").write_text(json.dumps({"head": "0" * 40}), encoding="utf-8")
    res = run(project, evidence, doc)
    assert res["ok"] and res["summary"]["blocking_cleared"] == 4
    assert len(res["warnings"]) == 2 and "000000000000" in res["warnings"][0] and "все блокирующие" in res["warnings"][1]
    assert "Предупреждение" in proposals.render_markdown(res) and "Предупреждения" in proposals.render_text(res)


def test_reports_neutralise_text_from_the_proposals_file(evidence, project):
    doc = good()
    vuln(doc).update(id="GHSA|`x`\nочистить экран", reason="В обосновании ``` тройные апострофы и | черта, длина больше порога.")
    sast(doc).update(reason="Обоснование с ```` четырьмя апострофами подряд и достаточной длиной.")
    res = run(project, evidence, doc)
    md, text = proposals.render_markdown(res), proposals.render_text(res)
    row = next(x for x in md.splitlines() if x.startswith("| 1 |"))
    assert "GHSA/'x' очистить экран" in row and row.count("|") == 6
    assert "GHSA|`x` очистить экран" in text and "\nочистить экран" not in text
    fence = next(x for x in md.splitlines() if x.endswith("yaml") and x.startswith("`"))
    assert fence == "`````yaml" and md.rstrip().endswith("\n`````")
    assert proposals.NOTICE in md and proposals.NOTICE in text


def test_clean_replaces_control_and_bidi_characters():
    assert proposals.clean("a\x1b[2Jb‮c\td\ne") == "a�[2Jb�c d e"


# ---------------------------------------------------------------- контроль ветки агента
def test_guard_function():
    changes = [("A", ".rbpo/proposals/a.yaml"), ("M", ".rbpo/proposals/a.md"), ("M", ".rbpo/triage.yaml"),
               ("D", ".rbpo/proposals/old.yaml"), ("A", ".rbpo/proposals/x.py")]
    modes = {".rbpo/proposals/a.yaml": "100644", ".rbpo/proposals/a.md": "120000"}
    got = {v["path"]: v["reason"] for v in proposals.guard(changes, modes=modes)}
    assert set(got) == {".rbpo/proposals/a.md", ".rbpo/triage.yaml", ".rbpo/proposals/old.yaml", ".rbpo/proposals/x.py"}
    assert "120000" in got[".rbpo/proposals/a.md"] and "не удаляются" in got[".rbpo/proposals/old.yaml"]
    assert proposals.guard(changes[:1], modes=modes) == []


def test_guard_allows_only_the_proposals_directory(repo):
    base = repo.commit({"rbpo.yaml": "project: demo\n", ".rbpo/triage.yaml": "sast: []\n", "src/a.py": "1\n"}, "base")
    repo.git("checkout", "-q", "-b", "agent/triage")
    repo.commit({".rbpo/proposals/2026-11-16.yaml": "schema: x\n", ".rbpo/proposals/2026-11-16.md": "отчёт\n",
                 ".rbpo/proposals/queue.json": "{}\n"}, "предложения")
    res = proposals.guard_range(repo.path, base)
    assert res["violations"] == [] and res["changed"] == 3
    assert "все в разрешённых путях" in proposals.render_guard(res)
    repo.commit({".rbpo/triage.yaml": "vulnerabilities: []\n", "rbpo.yaml": "policy: {sca_fail_on: none}\n",
                 ".github/workflows/ci.yml": "on: push\n", "src/a.py": "2\n", ".rbpo/proposals/run.sh": "exit 0\n",
                 ".rbpo/proposals/2026-11-16.yaml": "schema: y\n"}, "подмена")
    res = proposals.guard_range(repo.path, base)
    assert [v["path"] for v in res["violations"]] == [
        ".github/workflows/ci.yml", ".rbpo/proposals/run.sh", ".rbpo/triage.yaml", "rbpo.yaml", "src/a.py"]
    assert "rbpo.yaml — вне разрешённых путей" in proposals.render_guard(res)


def test_guard_rejects_deletion_symlink_and_executable(repo):
    base = repo.commit({".rbpo/proposals/old.yaml": "schema: x\n", ".rbpo/triage.yaml": "sast: []\n"}, "base")
    (repo.path / ".rbpo" / "proposals" / "old.yaml").unlink()
    os.symlink("../triage.yaml", repo.path / ".rbpo" / "proposals" / "link.yaml")
    tool = repo.path / ".rbpo" / "proposals" / "tool.yaml"
    tool.write_text("x\n", encoding="utf-8")
    tool.chmod(0o755)
    repo.git("add", "-A")
    repo.git("commit", "-q", "-m", "x")
    got = {v["path"]: v["reason"] for v in proposals.guard_range(repo.path, base)["violations"]}
    assert set(got) == {".rbpo/proposals/old.yaml", ".rbpo/proposals/link.yaml", ".rbpo/proposals/tool.yaml"}
    assert "120000" in got[".rbpo/proposals/link.yaml"] and "100755" in got[".rbpo/proposals/tool.yaml"]


def test_guard_in_subdirectory_project_and_custom_patterns(repo):
    base = repo.commit({"app/rbpo.yaml": "project: demo\n", "README.md": "x\n"}, "base")
    repo.commit({"app/.rbpo/proposals/p.yaml": "x\n"}, "agent")
    assert proposals.guard_range(repo.path / "app", base)["violations"] == []
    assert [v["path"] for v in proposals.guard_range(repo.path, base)["violations"]] == ["app/.rbpo/proposals/p.yaml"]
    assert proposals.guard_range(repo.path, base, allowed=["app/*"])["violations"] == []
    repo.commit({".rbpo/proposals/p.yaml": "x\n"}, "каталог предложений не того проекта")
    assert [v["path"] for v in proposals.guard_range(repo.path / "app", base)["violations"]] == [".rbpo/proposals/p.yaml"]
    for rev in ("--output=/tmp/x", "-p", ""):
        with pytest.raises(proposals.ProposalError, match="ветка или коммит"):
            proposals.guard_range(repo.path, rev)
        with pytest.raises(proposals.ProposalError, match="ветка или коммит"):
            proposals.guard_range(repo.path, base, rev)


# ---------------------------------------------------------------- командная строка
def test_cli_queue_check_and_guard(evidence, project, repo, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(project)
    ev = ["--out", str(evidence)]
    assert main(["triage-queue", *ev, "--json", str(tmp_path / "q.json")]) == 0
    assert "блокирует выпуск 4" in capsys.readouterr().out
    assert json.loads((tmp_path / "q.json").read_text(encoding="utf-8"))["summary"]["blocking"] == 4

    base = repo.git("rev-parse", "HEAD")
    f = put(project, good())
    check = ["proposals-check", *ev, "--date", TODAY.isoformat()]
    assert main([*check, "--json", str(tmp_path / "r.json"), "--md", str(tmp_path / "r.md"), str(f)]) == 0
    assert "прошли проверку 2" in capsys.readouterr().out
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["ok"] is True
    assert "### Для переноса в файл разметки" in (tmp_path / "r.md").read_text(encoding="utf-8")
    doc = good()
    vuln(doc).update(verdict="accepted")
    assert main([*check, str(put(project, doc, "bad.yaml"))]) == 1
    assert "ПП04" in capsys.readouterr().out

    assert main(["proposals-check", "--out", str(tmp_path / "none"), str(f)]) == 2
    assert main([*check, str(tmp_path / "none.yaml")]) == 2
    assert main(["proposals-check", *ev, "--date", "вчера", str(f)]) == 2
    assert main(["triage-queue", "--out", str(tmp_path / "none")]) == 2
    assert "нет результатов анализа" in capsys.readouterr().err

    repo.commit({}, "предложения агента")
    assert main(["agent-guard", "--base", base]) == 0
    repo.commit({"rbpo.yaml": "policy: {sca_fail_on: none}\n"}, "порог")
    assert main(["agent-guard", "--base", base]) == 1
    assert "rbpo.yaml" in capsys.readouterr().out
    assert main(["agent-guard", "--base", base, "--allow", "*"]) == 0
    assert main(["agent-guard", "--base", "нет-такой-ветки"]) == 2


# ---------------------------------------------------------------- набор для агента и документация
def test_example_proposals_file_passes_the_check(repo, tmp_path):
    """Образец из скилла остаётся верным: вымышленная очередь и файлы проекта под его ссылки."""
    def item(**kw):
        return dict({"verdict": "untriaged", "reason": "", "expired_decisions": [], "blocking": True}, **kw)

    ev = tmp_path / "ev"
    write_json(ev / "sca" / "triage.json", {"fail_on": "high", "items": [
        item(id="GHSA-aaaa-bbbb-cccc", aliases=["CVE-2099-0001"], severity="critical", package="examplelib",
             version="1.4.2", purl="pkg:pypi/examplelib@1.4.2", fix_state="fixed", fixed_in=["1.4.3"]),
        item(id="GHSA-dddd-eeee-ffff", aliases=[], severity="high", package="netclient", version="2.0.0",
             purl="pkg:pypi/netclient@2.0.0", fix_state="fixed", fixed_in=["2.0.1"])]})
    write_json(ev / "sast" / "triage.json", {"fail_on": "error", "items": [
        item(rule=SHELL_RULE, level="error", path="src/tool/run.py", line=12)]})
    repo.commit({"src/tool/parse.py": "\n" * 8 + "    return examplelib.parse_strict(text)\n",
                 "src/tool/fetch.py": "\n" * 4 + "    return netclient.get(url, auth=(user, token))\n",
                 "src/tool/run.py": "\n" * 3 + 'LIST_CMD = "ls -la /var/lib/tool"\n'}, "init")
    res = proposals.check([KIT / "skills" / "rbpo-triage" / "assets" / "proposals.example.yaml"], ev, repo.path, TODAY)
    assert res["ok"], proposals.render_text(res)
    s = res["summary"]
    assert (s["proposals"], s["blocking_cleared"], s["blocking_confirmed"], s["blocking_without_proposal"]) == (3, 2, 1, 0)


def test_kit_readme_counts_match_the_tests():
    text = (KIT / "README.md").read_text(encoding="utf-8")
    assert f"на {len(CASES)} враждебных и {len(BROKEN)} испорченных файлах предложений" in text


def test_docs_list_every_rule_and_only_existing_commands():
    doc = (ROOT / "docs" / "agent.md").read_text(encoding="utf-8")
    for code, text in proposals.RULES.items():
        assert f"| {code} | {text} |" in doc
    assert sorted(set(re.findall(r"ПП\d\d", doc))) == sorted(proposals.RULES)
    commands = next(a for a in build_parser()._actions if isinstance(a, argparse._SubParsersAction)).choices
    texts = [doc, (ROOT / "README.md").read_text(encoding="utf-8")]
    texts += [p.read_text(encoding="utf-8") for p in sorted(KIT.rglob("*"))
              if p.suffix in (".md", ".yml", ".yaml", ".py") and "project" not in p.parts]
    used = {m for t in texts for m in re.findall(r"rbpo-pipeline ([a-z][a-z-]+)", t)}
    assert {"triage-queue", "proposals-check", "agent-guard"} <= used and used <= set(commands)
    skill = (KIT / "skills" / "rbpo-triage" / "SKILL.md").read_text(encoding="utf-8")
    front = yaml.safe_load(skill.split("---")[1])
    assert front["name"] == "rbpo-triage" and 0 < len(front["description"]) <= 1024
    for text in (skill, (KIT / "ERRORS.md").read_text(encoding="utf-8"), (KIT / "PMI.md").read_text(encoding="utf-8")):
        assert set(re.findall(r"ПП\d\d", text)) <= set(proposals.RULES)
