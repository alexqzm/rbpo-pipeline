# -*- coding: utf-8 -*-
"""Разметка срабатываний: решения разработчиков по результатам SAST и по уязвимостям зависимостей.

Файл разметки (по умолчанию .rbpo/triage.yaml):

    sast:
      - rule: "python.lang.security.audit.*"   # шаблон идентификатора правила
        path: "src/demo_app/cli.py"            # шаблон пути (как в SARIF)
        line: 42                               # необязательно
        verdict: false_positive                # false_positive | accepted | confirmed
        reason: "аргумент строится из констант"
        until: 2027-03-01                      # необязательно: после даты решение не действует
    vulnerabilities:
      - id: GHSA-xxxx-xxxx-xxxx                # или CVE; сравнивается и со связанными идентификаторами
        package: "pyyaml"                      # необязательно, шаблон
        verdict: not_affected                  # not_affected | accepted | confirmed
        reason: "уязвимая функция не вызывается"

false_positive и not_affected — срабатывание ложное или уязвимость недостижима; accepted — ошибка
признана и оставлена в выпуске с обоснованием (это и есть анализ влияния для 5.20.3.2); confirmed —
признана и подлежит исправлению, выпуск с ней не допускается.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import List, Optional

import yaml

SAST_VERDICTS = ("false_positive", "accepted", "confirmed")
VULN_VERDICTS = ("not_affected", "accepted", "confirmed")
CLEARING = {"false_positive", "accepted", "not_affected"}


class TriageError(ValueError):
    pass


@dataclass
class Entry:
    kind: str
    verdict: str
    reason: str
    rule: str = "*"
    path: str = "*"
    line: Optional[int] = None
    id: str = ""
    package: str = "*"
    until: Optional[_dt.date] = None

    def expired(self, today: _dt.date) -> bool:
        return self.until is not None and today > self.until

    def to_dict(self) -> dict:
        d = {"verdict": self.verdict, "reason": self.reason}
        if self.kind == "sast":
            d.update(rule=self.rule, path=self.path)
            if self.line is not None:
                d["line"] = self.line
        else:
            d.update(id=self.id, package=self.package)
        if self.until:
            d["until"] = self.until.isoformat()
        return d


def _date(v) -> Optional[_dt.date]:
    if v is None or v == "":
        return None
    if isinstance(v, _dt.date):
        return v
    try:
        return _dt.date.fromisoformat(str(v))
    except ValueError as e:
        raise TriageError(f"until: {v} — ожидается дата ГГГГ-ММ-ДД") from e


def load(path: Optional[Path]) -> List[Entry]:
    if not path or not Path(path).exists():
        return []
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    entries: List[Entry] = []
    errors: List[str] = []
    for i, x in enumerate(data.get("sast") or []):
        v, r = str(x.get("verdict", "")), str(x.get("reason", "")).strip()
        if v not in SAST_VERDICTS:
            errors.append(f"sast[{i}]: verdict {v!r} (допустимо: {', '.join(SAST_VERDICTS)})")
        if not r:
            errors.append(f"sast[{i}]: нет обоснования (reason)")
        if not x.get("rule"):
            errors.append(f"sast[{i}]: не указано правило (rule)")
        entries.append(Entry("sast", v, r, rule=str(x.get("rule", "*")), path=str(x.get("path", "*")),
                             line=int(x["line"]) if x.get("line") is not None else None, until=_date(x.get("until"))))
    for i, x in enumerate(data.get("vulnerabilities") or []):
        v, r = str(x.get("verdict", "")), str(x.get("reason", "")).strip()
        if v not in VULN_VERDICTS:
            errors.append(f"vulnerabilities[{i}]: verdict {v!r} (допустимо: {', '.join(VULN_VERDICTS)})")
        if not r:
            errors.append(f"vulnerabilities[{i}]: нет обоснования (reason)")
        if not x.get("id"):
            errors.append(f"vulnerabilities[{i}]: не указан идентификатор (id)")
        entries.append(Entry("vuln", v, r, id=str(x.get("id", "")), package=str(x.get("package", "*")),
                             until=_date(x.get("until"))))
    if errors:
        raise TriageError("; ".join(errors))
    return entries


def match_sast(entries: List[Entry], rule: str, path: str, line: Optional[int], today: _dt.date):
    """Первое действующее решение для срабатывания и список истёкших подходящих решений."""
    expired = []
    for e in entries:
        if e.kind != "sast" or not fnmatchcase(rule, e.rule) or not fnmatchcase(path, e.path):
            continue
        if e.line is not None and e.line != line:
            continue
        if e.expired(today):
            expired.append(e)
            continue
        return e, expired
    return None, expired


def match_vuln(entries: List[Entry], ids: List[str], package: str, today: _dt.date):
    expired = []
    for e in entries:
        if e.kind != "vuln" or e.id not in ids or not fnmatchcase(package, e.package):
            continue
        if e.expired(today):
            expired.append(e)
            continue
        return e, expired
    return None, expired
