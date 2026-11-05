# -*- coding: utf-8 -*-
"""Сборка комплекта свидетельств: анализ неустранённых ошибок (5.20.3.2), манифест для rbpo-evidence,
отчёт о полноте свидетельств, опись файлов с SHA-256, сводка и решение по выпуску."""
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from . import __version__
from .build import sha256_file
from .states import put_state, read_states, write_json

# Артефакты, которые формирует конвейер, в порядке процессов стандарта.
AUTOMATED = [
    "5.4.3.3", "5.10.3.2", "5.10.3.3", "5.10.3.4", "5.12.3.2", "5.13.3.4", "5.13.3.5", "5.13.3.6",
    "5.14.3.3", "5.16.3.2", "5.16.3.4", "5.17.3.5", "5.18.3.2", "5.18.3.3", "5.20.3.2", "5.20.3.4",
]
STATE_RU = {"P": "подтверждает", "N": "не предъявлен", "F": "опровергает"}
JOBS_RU = {"success": "выполнена", "failure": "завершилась с ошибкой", "cancelled": "отменена", "skipped": "пропущена"}


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def release_analysis(out: Path) -> dict:
    """Неустранённые ошибки выпуска и решения по ним (5.20.3.2)."""
    sast, sca, tests = (_load(out / "sast" / "triage.json"), _load(out / "sca" / "triage.json"),
                        _load(out / "tests" / "summary.json"))
    res: Dict[str, dict] = {}
    blocking = 0
    expired: List[dict] = []
    if sast is not None:
        items = sast["items"]
        res["sast"] = {
            "fail_on": sast["fail_on"],
            "accepted": [i for i in items if i["verdict"] == "accepted"],
            "false_positive": sum(1 for i in items if i["verdict"] == "false_positive"),
            "blocking": [i for i in items if i["blocking"]],
            "below_threshold": dict(Counter(i["level"] for i in items if not i["blocking"]
                                            and i["verdict"] in ("untriaged", "confirmed"))),
        }
        blocking += len(res["sast"]["blocking"])
        expired += [dict(d, kind="sast") for i in items for d in i["expired_decisions"]]
    if sca is not None:
        items = sca["items"]
        res["sca"] = {
            "fail_on": sca["fail_on"],
            "accepted": [i for i in items if i["verdict"] == "accepted"],
            "not_affected": [i for i in items if i["verdict"] == "not_affected"],
            "blocking": [i for i in items if i["blocking"]],
            "below_threshold": dict(Counter(i["severity"] for i in items if not i["blocking"]
                                            and i["verdict"] in ("untriaged", "confirmed"))),
        }
        blocking += len(res["sca"]["blocking"])
        expired += [dict(d, kind="vulnerability") for i in items for d in i["expired_decisions"]]
    if tests is not None:
        res["tests"] = {"failed": tests.get("failed", []), "skipped": tests.get("skipped", 0)}
        blocking += len(res["tests"]["failed"])
    res["expired_decisions"] = expired
    path = write_json(out / "release" / "unresolved.json", res)
    if sast is None and sca is None:
        put_state(out, "5.20.3.2", "N", [], {}, "нет результатов статического и композиционного анализа",
                  "rbpo-pipeline")
        return res
    accepted = len(res.get("sast", {}).get("accepted", [])) + len(res.get("sca", {}).get("accepted", []))
    below = sum(res.get("sast", {}).get("below_threshold", {}).values()) + \
        sum(res.get("sca", {}).get("below_threshold", {}).values())
    if blocking:
        st = "F"
        note = f"неустранённых ошибок без решения о влиянии на безопасность: {blocking}"
    else:
        st = "P"
        note = (f"неустранённых ошибок выше порогов без решения нет; принято с обоснованием {accepted}, "
                f"ниже порогов {below}")
    if expired:
        note += f"; истёкших решений {len(expired)}"
    put_state(out, "5.20.3.2", st, [path.relative_to(out).as_posix()],
              {"blocking": blocking, "accepted": accepted, "below_threshold": below, "expired": len(expired)},
              note, "rbpo-pipeline")
    return res


def _run_url() -> str:
    srv, repo, rid = (os.environ.get("GITHUB_SERVER_URL", ""), os.environ.get("GITHUB_REPOSITORY", ""),
                      os.environ.get("GITHUB_RUN_ID", ""))
    return f"{srv}/{repo}/actions/runs/{rid}" if srv and repo and rid else ""


def manifest(out: Path, cfg: dict, states: Dict[str, dict], organizational: List[str]) -> dict:
    arts = {}
    for aid in AUTOMATED + sorted(organizational, key=lambda a: [int(x) for x in a.split(".")]):
        s = states.get(aid)
        if s is None:
            arts[aid] = {"state": "N", "evidence": "rbpo-pipeline", "note": "шаг конвейера не выполнялся"}
            continue
        entry = {"state": s["state"], "evidence": s.get("producer", ""), "note": s.get("note", "")}
        if s.get("files"):
            entry["ref"] = s["files"][0]
            p = out / s["files"][0]
            if p.is_file():
                entry["sha256"] = sha256_file(p)
        arts[aid] = entry
    return {
        "schema": "rbpo-evidence/manifest/v1",
        "project": cfg.get("project") or os.environ.get("GITHUB_REPOSITORY", "") or "проект",
        "standard": "ГОСТ Р 56939-2024",
        "source": {"generator": f"rbpo-pipeline {__version__}", "repository": os.environ.get("GITHUB_REPOSITORY", ""),
                   "commit": os.environ.get("GITHUB_SHA", ""), "ref": os.environ.get("GITHUB_REF", ""),
                   "run": _run_url()},
        "scope": {"exclude": cfg.get("scope", {}).get("exclude", []) or []},
        "artifacts": arts,
    }


def evaluate(out: Path, man: dict) -> dict:
    from rbpo_evidence.check import Manifest, evaluate as ev, render_json, render_markdown
    from rbpo_evidence.model import Model

    model = Model.load(None)
    rep = ev(model, Manifest.from_dict(man, model))
    (out / "report.md").write_text(render_markdown(model, rep), encoding="utf-8")
    (out / "report.json").write_text(render_json(rep), encoding="utf-8")
    labels = {aid: model.artifact[aid].label for aid in man["artifacts"] if aid in model.artifact}
    return {"overall": rep.overall, "counts": rep.counts, "presented": rep.artifacts_presented,
            "total": rep.artifacts_total, "labels": labels}


def decide(out: Path, cfg: dict, states: Dict[str, dict], needs: Optional[dict]) -> dict:
    reasons = []
    pol = cfg["policy"]
    for aid in AUTOMATED:
        s = states.get(aid)
        if s and s["state"] == "F":
            if aid == "5.13.3.6" and pol["reproducible"] == "report":
                continue
            reasons.append(f"{aid}: {s.get('note', '')}")
        elif s and s["state"] == "N" and s.get("error"):
            reasons.append(f"{aid}: сбой инструмента — {s.get('note', '')}")
    sec = _load(out / "secrets" / "summary.json")
    if pol["secrets"] == "fail":
        if sec is None or not sec.get("ran"):
            reasons.append("поиск секретов не выполнен")
        elif sec.get("findings"):
            reasons.append(f"найдены секреты: {sec['findings']}")
    build = _load(out / "build" / "build.json")
    if build and build.get("exit_code"):
        reasons.append(f"сборка завершилась с кодом {build['exit_code']}")
    for job, r in (needs or {}).items():
        if r.get("result") not in ("success", None):
            reasons.append(f"задача {job} {JOBS_RU.get(r.get('result'), r.get('result'))}")
    dec = {"decision": "fail" if reasons else "pass", "reasons": reasons}
    write_json(out / "decision.json", dec)
    return dec


def index(out: Path) -> dict:
    files = {p.relative_to(out).as_posix(): sha256_file(p) for p in sorted(out.rglob("*"))
             if p.is_file() and p.name != "index.json"}
    write_json(out / "index.json", {"generator": f"rbpo-pipeline {__version__}", "files": files})
    return files


def summary_md(out: Path, man: dict, ev: dict, dec: dict, states: Dict[str, dict], organizational: List[str]) -> str:
    L: List[str] = []
    w = L.append
    w(f"## РБПО: свидетельства выпуска — {man['project']}")
    w("")
    if dec["decision"] == "pass":
        w("**Решение конвейера: выпуск допустим** — опровергнутых технических свидетельств нет.")
    else:
        w("**Решение конвейера: выпуск не допускается.**")
        w("")
        for r in dec["reasons"]:
            w(f"- {r}")
    w("")
    overall = {"refuted": "есть опровергнутые свидетельства", "missing": "свидетельств не хватает",
               "confirmed": "полнота свидетельств подтверждена"}[ev["overall"]]
    c = ev["counts"]
    w(f"Полнота по ГОСТ Р 56939-2024 (rbpo-evidence): {overall}; предъявлено артефактов {ev['presented']} "
      f"из {ev['total']}; процессов подтверждено {c.get('confirmed', 0)}, не хватает свидетельств "
      f"{c.get('missing', 0)}, опровергнуто {c.get('refuted', 0)}, по усмотрению {c.get('optional', 0)}, "
      f"вне области {c.get('excluded', 0)}. Это проверка полноты свидетельств, а не оценка соответствия.")
    w("")
    w("### Технические артефакты (формирует конвейер)")
    w("")
    w("| Артефакт | Содержание | Состояние | Пояснение |")
    w("|---|---|---|---|")
    for aid in AUTOMATED:
        a = man["artifacts"][aid]
        w(f"| {aid} | {ev['labels'].get(aid, '')} | {a['state']} — {STATE_RU[a['state']]} | "
          f"{a.get('note', '').replace('|', '/')} |")
    if organizational:
        w("")
        w("### Организационные артефакты (документы проекта)")
        w("")
        w("| Артефакт | Содержание | Состояние | Документ |")
        w("|---|---|---|---|")
        for aid in sorted(organizational, key=lambda a: [int(x) for x in a.split(".")]):
            a = man["artifacts"][aid]
            w(f"| {aid} | {ev['labels'].get(aid, '')} | {a['state']} — {STATE_RU[a['state']]} | "
              f"{a.get('note', '')} |")
    sec = _load(out / "secrets" / "summary.json")
    w("")
    w("### Дополнительно")
    w("")
    if sec is None or not sec.get("ran"):
        w("- Поиск секретов: не выполнен.")
    else:
        w(f"- Поиск секретов (Gitleaks, вся история репозитория): найдено {sec['findings']}, политика «{sec['policy']}».")
    w("- Опись комплекта: `index.json` (SHA-256 каждого файла); полный отчёт о полноте — `report.md`.")
    w("")
    return "\n".join(L)


def assemble(out: Path, cfg: dict, needs: Optional[dict] = None) -> dict:
    out = Path(out)
    release_analysis(out)
    states = read_states(out)
    organizational = sorted(cfg.get("organizational", {}))
    man = manifest(out, cfg, states, organizational)
    (out / "manifest.yaml").write_text(
        "# Манифест свидетельств РБПО, сформирован rbpo-pipeline; проверка: rbpo-evidence check manifest.yaml\n"
        + yaml.safe_dump(man, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8")
    ev = evaluate(out, man)
    dec = decide(out, cfg, states, needs)
    (out / "SUMMARY.md").write_text(summary_md(out, man, ev, dec, states, organizational), encoding="utf-8")
    index(out)
    return {"decision": dec, "overall": ev["overall"], "presented": ev["presented"], "total": ev["total"]}
