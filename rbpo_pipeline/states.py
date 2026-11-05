# -*- coding: utf-8 -*-
"""Записи о состоянии артефактов ГОСТ Р 56939-2024, которые выпускает конвейер.

Каждый шаг конвейера пишет одну запись на артефакт: <out>/states/<артефакт>.json
с полями artifact, state (P — подтверждает, F — опровергает, N — не предъявлен), files
(пути внутри каталога свидетельств), summary (числа), note (пояснение) и error (свидетельство
не получено из-за сбоя инструмента).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

STATES = ("P", "N", "F")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def put_state(out: Path, artifact: str, state: str, files: Iterable[str] = (), summary: Optional[dict] = None,
              note: str = "", producer: str = "", error: bool = False) -> dict:
    """error=True — свидетельство не получено из-за сбоя инструмента (а не потому, что шаг не нужен)."""
    if state not in STATES:
        raise ValueError(f"состояние {state} (допустимо P, N, F)")
    rec = {"artifact": artifact, "state": state, "files": list(files), "summary": summary or {},
           "note": note, "producer": producer}
    if error:
        rec["error"] = True
    d = Path(out) / "states"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{artifact}.json").write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
    return rec


def read_states(out: Path) -> Dict[str, dict]:
    d = Path(out) / "states"
    res: Dict[str, dict] = {}
    if d.is_dir():
        for p in sorted(d.glob("*.json")):
            rec = json.loads(p.read_text(encoding="utf-8"))
            res[rec["artifact"]] = rec
    return res


def write_json(path: Path, data) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def rel(out: Path, path: Path) -> str:
    return str(Path(path).resolve().relative_to(Path(out).resolve()))


def worst(states: List[str]) -> str:
    """F, если есть F; иначе P, если есть P; иначе N."""
    return "F" if "F" in states else ("P" if "P" in states else "N")
