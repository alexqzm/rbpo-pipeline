# -*- coding: utf-8 -*-
"""Отчёты инструментов анализа -> состояния артефактов.

  SARIF и JSON Semgrep, разметка     -> 5.10.3.2, 5.10.3.3, 5.10.3.4
  SBOM CycloneDX, JSON Grype, разметка -> 5.16.3.2, 5.16.3.4
  журнал clamscan                    -> 5.17.3.5
  JUnit XML и журнал запуска тестов  -> 5.18.3.2, 5.18.3.3
  отчёт Gitleaks                     -> дополнительное свидетельство (требование 5.15.2.3 по усмотрению)
"""
from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from . import languages
from .config import SAST_LEVELS, SCA_LEVELS, at_or_above
from .states import put_state, rel, write_json
from .triage import CLEARING, Entry, match_sast, match_vuln


def _today() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


# ---------------------------------------------------------------- статический анализ
def _result_level(res: dict, rules: Dict[str, dict]) -> str:
    if res.get("level"):
        return res["level"]
    rule = rules.get(res.get("ruleId", ""), {})
    return (rule.get("defaultConfiguration") or {}).get("level", "warning")


def _location(res: dict):
    try:
        pl = res["locations"][0]["physicalLocation"]
        return pl["artifactLocation"]["uri"], pl.get("region", {}).get("startLine")
    except (KeyError, IndexError):
        return "", None


def triage_sarif(sarif: dict, entries: List[Entry], fail_on: str, today: Optional[_dt.date] = None):
    """Размечает срабатывания решениями из файла разметки.

    Возвращает (размеченный SARIF, список срабатываний с решениями). Ложные и принятые срабатывания
    получают SARIF-подавление (suppressions) с обоснованием; у каждого срабатывания в properties
    записывается решение: false_positive, accepted, confirmed или untriaged.
    """
    today = today or _today()
    out = copy.deepcopy(sarif)
    items = []
    for run in out.get("runs", []):
        rules = {r.get("id", ""): r for r in run.get("tool", {}).get("driver", {}).get("rules", []) or []}
        for res in run.get("results", []) or []:
            level = _result_level(res, rules)
            path, line = _location(res)
            entry, expired = match_sast(entries, res.get("ruleId", ""), path, line, today)
            verdict = entry.verdict if entry else "untriaged"
            props = res.setdefault("properties", {})
            props["rbpoTriage"] = verdict
            if entry and entry.verdict in CLEARING:
                res["suppressions"] = [{"kind": "external", "status": "accepted", "justification": entry.reason}]
            blocking = at_or_above(level, fail_on, SAST_LEVELS) and verdict in ("untriaged", "confirmed")
            items.append({"rule": res.get("ruleId", ""), "level": level, "path": path, "line": line,
                          "verdict": verdict, "reason": entry.reason if entry else "",
                          "expired_decisions": [e.to_dict() for e in expired], "blocking": blocking})
    return out, items


def sast(out: Path, sarif_path: Path, scan_json: Optional[Path], config_name: str, fail_on: str,
         entries: List[Entry], project_root: Path, language_exclusions: Dict[str, str],
         today: Optional[_dt.date] = None) -> dict:
    sarif = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    triaged, items = triage_sarif(sarif, entries, fail_on, today)
    tri_path = write_json(out / "sast" / "semgrep.triaged.sarif", triaged)

    by_level = Counter(i["level"] for i in items)
    by_verdict = Counter(i["verdict"] for i in items)
    blocking = [i for i in items if i["blocking"]]
    summary = {"results": len(items), "by_level": dict(by_level), "by_verdict": dict(by_verdict),
               "blocking": len(blocking), "fail_on": fail_on}
    write_json(out / "sast" / "triage.json", {"fail_on": fail_on, "items": items})
    if blocking:
        note = (f"срабатываний не ниже уровня «{fail_on}» без решения или подтверждённых: {len(blocking)}; "
                "нужна разметка в файле решений или исправление")
    else:
        note = (f"всего срабатываний {len(items)}; не ниже уровня «{fail_on}» — все размечены "
                f"(ложные или принятые с обоснованием)" if items else "срабатываний нет")
    files = [rel(out, tri_path), rel(out, sarif_path)]
    put_state(out, "5.10.3.4", "F" if blocking else "P", files, summary, note, "semgrep")

    # Инструменты и языки (5.10.3.2): покрытие проверяется по файлам, которые анализатор разобрал.
    tools = []
    for run in sarif.get("runs", []):
        drv = run.get("tool", {}).get("driver", {})
        tools.append({"name": drv.get("name", ""), "version": drv.get("semanticVersion") or drv.get("version", "")})
    scanned_files: List[str] = []
    if scan_json and Path(scan_json).exists():
        sj = json.loads(Path(scan_json).read_text(encoding="utf-8"))
        scanned_files = list((sj.get("paths") or {}).get("scanned") or [])
    cov = languages.coverage(languages.count(languages.tracked_files(project_root)),
                             languages.count(scanned_files), language_exclusions)
    tools_path = write_json(out / "sast" / "tools.json", {"tools": tools, "languages": cov})
    if not scanned_files:
        st, note = "N", "нет сведений о разобранных анализатором файлах (JSON-вывод Semgrep)"
    elif cov["uncovered"]:
        st, note = "F", f"языки без статического анализа: {', '.join(cov['uncovered'])}"
    else:
        st = "P"
        note = f"инструменты: {', '.join(t['name'] + ' ' + t['version'] for t in tools)}; языки: {', '.join(cov['covered'])}"
        if cov["excluded"]:
            note += f"; исключены с обоснованием: {', '.join(cov['excluded'])}"
    put_state(out, "5.10.3.2", st, [rel(out, tools_path)], {"tools": tools, "uncovered": cov["uncovered"]}, note,
              "rbpo-pipeline")

    # Конфигурация (5.10.3.3): набор правил с уровнями и хэшем, порог, правила разметки.
    rules = []
    for run in sarif.get("runs", []):
        for r in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            rules.append({"id": r.get("id", ""), "level": (r.get("defaultConfiguration") or {}).get("level", "")})
    rules.sort(key=lambda r: r["id"])
    digest = hashlib.sha256(json.dumps(rules, sort_keys=True).encode("utf-8")).hexdigest()
    cfg_path = write_json(out / "sast" / "config.json", {
        "config": config_name, "fail_on": fail_on, "rules_count": len(rules), "rules_sha256": digest,
        "rules": rules, "triage_decisions": [e.to_dict() for e in entries if e.kind == "sast"]})
    put_state(out, "5.10.3.3", "P" if rules else "N", [rel(out, cfg_path)],
              {"config": config_name, "rules": len(rules), "rules_sha256": digest},
              f"набор правил «{config_name}», правил {len(rules)}, порог «{fail_on}»" if rules
              else "в отчёте нет сведений о правилах", "semgrep")
    return summary


# ---------------------------------------------------------------- композиционный анализ
def sbom_components(sbom: dict) -> List[dict]:
    """Компоненты SBOM с идентификатором пакета (purl): имя, версия, источник."""
    res = []
    for c in sbom.get("components", []) or []:
        if c.get("purl"):
            res.append({"name": c.get("name", ""), "version": c.get("version", ""), "purl": c["purl"],
                        "type": c.get("type", "")})
    return res


def triage_grype(grype: dict, entries: List[Entry], fail_on: str, today: Optional[_dt.date] = None) -> List[dict]:
    today = today or _today()
    items = []
    for m in grype.get("matches", []) or []:
        v = m.get("vulnerability", {}) or {}
        art = m.get("artifact", {}) or {}
        ids = [v.get("id", "")] + [r.get("id", "") for r in m.get("relatedVulnerabilities", []) or []]
        sev = str(v.get("severity", "Unknown")).lower()
        entry, expired = match_vuln(entries, ids, art.get("name", ""), today)
        verdict = entry.verdict if entry else "untriaged"
        fix = v.get("fix") or {}
        items.append({"id": v.get("id", ""), "aliases": ids[1:], "severity": sev, "package": art.get("name", ""),
                      "version": art.get("version", ""), "purl": art.get("purl", ""),
                      "fix_state": fix.get("state", ""), "fixed_in": fix.get("versions", []) or [],
                      "verdict": verdict, "reason": entry.reason if entry else "",
                      "expired_decisions": [e.to_dict() for e in expired],
                      "blocking": at_or_above(sev, fail_on, SCA_LEVELS) and verdict in ("untriaged", "confirmed")})
    return items


def sca(out: Path, sbom_path: Path, grype_path: Optional[Path], fail_on: str, entries: List[Entry],
        today: Optional[_dt.date] = None) -> dict:
    sbom = json.loads(Path(sbom_path).read_text(encoding="utf-8"))
    comps = sbom_components(sbom)
    put_state(out, "5.16.3.2", "P" if comps else "N", [rel(out, sbom_path)], {"components": len(comps)},
              f"компонентов с указанием версии и источника (purl): {len(comps)}" if comps
              else "в SBOM нет заимствованных компонентов", "syft")
    if grype_path is None or not Path(grype_path).exists():
        put_state(out, "5.16.3.4", "N", [], {}, "анализ известных уязвимостей не выполнялся", "grype")
        return {"components": len(comps)}
    grype = json.loads(Path(grype_path).read_text(encoding="utf-8"))
    items = triage_grype(grype, entries, fail_on, today)
    db = ((grype.get("descriptor") or {}).get("db") or {})
    db_status = db.get("status", db) if isinstance(db, dict) else {}
    blocking = [i for i in items if i["blocking"]]
    summary = {"matches": len(items), "by_severity": dict(Counter(i["severity"] for i in items)),
               "by_verdict": dict(Counter(i["verdict"] for i in items)), "blocking": len(blocking),
               "fail_on": fail_on, "db_built": db_status.get("built", ""),
               "db_schema": db_status.get("schemaVersion", "")}
    tri = write_json(out / "sca" / "triage.json", {"fail_on": fail_on, "items": items})
    if blocking:
        note = (f"уязвимостей уровня «{fail_on}» и выше без решения или подтверждённых: {len(blocking)} "
                f"({', '.join(sorted({i['package'] + ' ' + i['version'] for i in blocking}))})")
    else:
        note = (f"известных уязвимостей: {len(items)}; уровня «{fail_on}» и выше без решения нет"
                if items else "известных уязвимостей не найдено")
    if summary["db_built"]:
        note += f"; база уязвимостей от {summary['db_built'][:10]}"
    put_state(out, "5.16.3.4", "F" if blocking else "P", [rel(out, tri), rel(out, grype_path)], summary, note, "grype")
    return summary


# ---------------------------------------------------------------- антивирусная проверка
_INFECTED = re.compile(r"^Infected files:\s*(\d+)", re.M)
_SCANNED = re.compile(r"^Scanned files:\s*(\d+)", re.M)
_ENGINE = re.compile(r"^ClamAV (\S+)/(\d+)/(.+)$", re.M)


def av(out: Path, log: Optional[Path], exit_code: Optional[int], targets: List[str]) -> dict:
    if log is None or not Path(log).exists():
        put_state(out, "5.17.3.5", "N", [], {}, "антивирусная проверка не выполнялась", "clamav")
        return {}
    text = Path(log).read_text(encoding="utf-8", errors="replace")
    inf, sc, eng = _INFECTED.search(text), _SCANNED.search(text), _ENGINE.search(text)
    summary = {"exit_code": exit_code, "targets": targets}
    if eng:
        summary.update(engine=eng.group(1), signatures=eng.group(2), signatures_date=eng.group(3).strip())
    if not inf or exit_code not in (0, 1):
        put_state(out, "5.17.3.5", "N", [rel(out, log)], summary,
                  f"антивирусная проверка завершилась с ошибкой (код {exit_code}), итог не получен", "clamav",
                  error=True)
        return summary
    summary.update(scanned_files=int(sc.group(1)) if sc else 0, infected_files=int(inf.group(1)))
    note = f"проверено файлов {summary['scanned_files']}, заражённых {summary['infected_files']}"
    if eng:
        note += f"; ClamAV {summary['engine']}, база {summary['signatures']} от {summary['signatures_date']}"
    put_state(out, "5.17.3.5", "F" if summary["infected_files"] else "P", [rel(out, log)], summary, note, "clamav")
    return summary


# ---------------------------------------------------------------- функциональное тестирование
def junit_summary(path: Path) -> dict:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    t = f = e = s = 0
    failed, stamps = [], []
    for su in suites:
        t += int(su.get("tests", 0))
        f += int(su.get("failures", 0))
        e += int(su.get("errors", 0))
        s += int(su.get("skipped", 0))
        if su.get("timestamp"):
            stamps.append(su.get("timestamp"))
        for tc in su.iter("testcase"):
            if tc.find("failure") is not None or tc.find("error") is not None:
                failed.append(f"{tc.get('classname', '')}::{tc.get('name', '')}")
    return {"tests": t, "failures": f, "errors": e, "skipped": s, "failed": failed, "timestamps": stamps}


def tests(out: Path, junit: Optional[Path], log: Optional[Path], exit_code: Optional[int]) -> dict:
    files = [rel(out, p) for p in (junit, log) if p is not None and Path(p).exists()]
    if junit is None or not Path(junit).exists():
        note = "тесты не запускались (не задана команда тестирования)" if exit_code is None else \
            f"отчёт JUnit не получен, команда тестирования завершилась с кодом {exit_code}"
        put_state(out, "5.18.3.2", "N", files, {"exit_code": exit_code}, note, "junit", error=exit_code is not None)
        put_state(out, "5.18.3.3", "P" if log is not None and Path(log).exists() else "N", files,
                  {"exit_code": exit_code}, "журнал запуска тестов без отчёта JUnit", "junit")
        return {}
    s = junit_summary(junit)
    s["exit_code"] = exit_code
    write_json(out / "tests" / "summary.json", s)
    bad = s["failures"] + s["errors"]
    if s["tests"] == 0:
        st, note = "N", "в отчёте нет тестов"
    elif bad:
        st, note = "F", f"тестов {s['tests']}, не прошли {bad}: {', '.join(s['failed'][:5])}"
    else:
        st, note = "P", f"тестов {s['tests']}, пройдены все" + (f", пропущено {s['skipped']}" if s["skipped"] else "")
    put_state(out, "5.18.3.2", st, files, s, note, "junit")
    put_state(out, "5.18.3.3", "P" if s["tests"] else "N", files, {"timestamps": s["timestamps"]},
              "журнал: время запуска, результат и длительность каждого теста (JUnit) и вывод запуска",
              "junit")
    return s


# ---------------------------------------------------------------- поиск секретов
def secrets(out: Path, report: Optional[Path], exit_code: Optional[int], policy: str) -> dict:
    """Итог поиска секретов; отдельного артефакта в стандарте нет, итог входит в решение по выпуску."""
    findings = []
    ran = report is not None and Path(report).exists()
    if ran and Path(report).stat().st_size:
        findings = json.loads(Path(report).read_text(encoding="utf-8")) or []
    error = exit_code not in (0, 3, None) or not ran
    res = {"ran": ran and not error, "findings": len(findings), "policy": policy, "exit_code": exit_code,
           "rules": dict(Counter(x.get("RuleID", "") for x in findings)),
           "locations": [{"file": x.get("File", ""), "line": x.get("StartLine"), "commit": x.get("Commit", ""),
                          "rule": x.get("RuleID", "")} for x in findings][:100],
           "report": rel(out, report) if ran else ""}
    write_json(out / "secrets" / "summary.json", res)
    return res
