# -*- coding: utf-8 -*-
"""Настройки конвейера для проекта (rbpo.yaml)."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Optional

import yaml

SAST_LEVELS = ("error", "warning", "note")
SCA_LEVELS = ("critical", "high", "medium", "low")

DEFAULTS = {
    "project": "",
    "policy": {
        "sast_fail_on": "error",        # error | warning | note | none
        "sca_fail_on": "critical",      # critical | high | medium | low | none
        "secrets": "fail",              # fail | report
        "commit_signatures": "report",  # report | require
        "reproducible": "require",      # require | report
    },
    "triage": ".rbpo/triage.yaml",
    "sast_exclude_languages": {},       # язык -> обоснование, почему статический анализ не нужен
    "scope": {"exclude": []},
    "organizational": {},               # номер артефакта -> путь к документу (можно с #якорем)
}

CHOICES = {
    "sast_fail_on": SAST_LEVELS + ("none",),
    "sca_fail_on": SCA_LEVELS + ("none",),
    "secrets": ("fail", "report"),
    "commit_signatures": ("report", "require"),
    "reproducible": ("require", "report"),
}


class ConfigError(ValueError):
    pass


def load(path: Optional[str]) -> dict:
    """Настройки из rbpo.yaml поверх значений по умолчанию; файла может не быть."""
    cfg = copy.deepcopy(DEFAULTS)
    if path and Path(path).exists():
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        unknown = set(data) - set(DEFAULTS)
        if unknown:
            raise ConfigError(f"неизвестные ключи: {', '.join(sorted(unknown))}")
        cfg["project"] = str(data.get("project", "") or "")
        pol = data.get("policy") or {}
        unknown = set(pol) - set(DEFAULTS["policy"])
        if unknown:
            raise ConfigError(f"policy: неизвестные ключи: {', '.join(sorted(unknown))}")
        cfg["policy"].update(pol)
        cfg["triage"] = str(data.get("triage", cfg["triage"]))
        cfg["sast_exclude_languages"] = {str(k): str(v) for k, v in (data.get("sast_exclude_languages") or {}).items()}
        for lang, why in cfg["sast_exclude_languages"].items():
            if not why.strip():
                raise ConfigError(f"sast_exclude_languages: {lang} без обоснования")
        cfg["scope"] = data.get("scope") or {"exclude": []}
        cfg["organizational"] = {str(k): str(v) for k, v in (data.get("organizational") or {}).items()}
    for k, allowed in CHOICES.items():
        if cfg["policy"][k] not in allowed:
            raise ConfigError(f"policy.{k}: {cfg['policy'][k]} (допустимо: {', '.join(allowed)})")
    for x in cfg["scope"].get("exclude", []) or []:
        if not str(x.get("reason", "")).strip():
            raise ConfigError(f"scope.exclude: процесс {x.get('process')} исключён без обоснования")
    return cfg


def at_or_above(level: str, threshold: str, order) -> bool:
    """Уровень не ниже порога; order — от самого серьёзного к наименее серьёзному."""
    if threshold == "none" or level not in order:
        return False
    return order.index(level) <= order.index(threshold)
