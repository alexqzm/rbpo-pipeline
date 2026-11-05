# -*- coding: utf-8 -*-
"""Манифест обновления: имя, размер и SHA-256 каждого файла; проверка каталога по манифесту."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List

import yaml

FORMAT = "demo-app/manifest/v1"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def build(root: Path) -> Dict:
    """Манифест каталога: файлы в лексикографическом порядке, пути относительно корня."""
    root = Path(root)
    files = []
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        files.append({"path": p.relative_to(root).as_posix(), "size": p.stat().st_size, "sha256": digest(p)})
    return {"format": FORMAT, "files": files}


def dump(manifest: Dict) -> str:
    return yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True)


def load(text: str) -> Dict:
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError(f"ожидается манифест формата {FORMAT}")
    return data


def verify(manifest: Dict, root: Path) -> List[str]:
    """Расхождения каталога с манифестом; пустой список — каталог совпадает."""
    root = Path(root)
    problems = []
    listed = set()
    for item in manifest["files"]:
        rel = item["path"]
        listed.add(rel)
        p = root / rel
        if ".." in Path(rel).parts or not p.is_file():
            problems.append(f"нет файла: {rel}")
        elif p.stat().st_size != item["size"] or digest(p) != item["sha256"]:
            problems.append(f"изменён: {rel}")
    for p in sorted(x for x in root.rglob("*") if x.is_file()):
        rel = p.relative_to(root).as_posix()
        if rel not in listed:
            problems.append(f"лишний файл: {rel}")
    return problems
