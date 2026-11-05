# -*- coding: utf-8 -*-
"""Организационные артефакты: регламенты, схемы, перечни — документы проекта, указанные в rbpo.yaml.

Конвейер проверяет только наличие документа (и раздела, если указан якорь), фиксирует его SHA-256
и кладёт копию в комплект свидетельств. Содержание документов оценивает человек.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Dict, List

from .states import put_state, sha256_file, write_json

_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
_ID = re.compile(r"""(?:id|name)\s*=\s*["']([^"']+)["']""")
_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")


def slug(text: str) -> str:
    """Якорь заголовка так, как его строит GitHub: строчные буквы, без знаков, пробелы -> дефисы."""
    t = _LINK.sub(r"\1", text)
    t = t.replace("`", "").replace("*", "")
    t = t.strip().lower()
    t = re.sub(r"[^\w\- ]", "", t)
    return t.replace(" ", "-")


def anchors(text: str) -> List[str]:
    res: List[str] = []
    seen: Dict[str, int] = {}
    in_code = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        m = _HEADING.match(line)
        if m:
            s = slug(m.group(1))
            n = seen.get(s, 0)
            seen[s] = n + 1
            res.append(s if n == 0 else f"{s}-{n}")
        res.extend(_ID.findall(line))
    return res


def collect(out: Path, project_dir: Path, mapping: Dict[str, str], automated: List[str]) -> List[dict]:
    project_dir = Path(project_dir).resolve()
    items = []
    for aid, ref in sorted(mapping.items(), key=lambda kv: [int(x) for x in kv[0].split(".")]):
        if aid in automated:
            raise ValueError(f"organizational: артефакт {aid} формирует конвейер, документ для него не указывается")
        path, _, anchor = ref.partition("#")
        p = (project_dir / path).resolve()
        item = {"artifact": aid, "ref": ref, "path": path, "anchor": anchor}
        if project_dir not in p.parents and p != project_dir:
            raise ValueError(f"organizational: {aid}: путь {path} вне каталога проекта")
        if not p.is_file():
            item.update(state="N", note=f"документ {path} не найден")
        else:
            text = p.read_text(encoding="utf-8", errors="replace") if p.suffix.lower() in (".md", ".markdown") else ""
            if anchor and p.suffix.lower() in (".md", ".markdown") and anchor not in anchors(text):
                item.update(state="N", note=f"в документе {path} нет раздела #{anchor}")
            else:
                dest = Path(out) / "org" / "files" / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, dest)
                item.update(state="P", sha256=sha256_file(p), copy=f"org/files/{path}",
                            note=f"документ {ref}")
        files = [item["copy"]] if item.get("copy") else []
        put_state(out, aid, item["state"], files, {"sha256": item.get("sha256", "")}, item["note"], "organizational")
        items.append(item)
    write_json(Path(out) / "org" / "organizational.json", items)
    return items
