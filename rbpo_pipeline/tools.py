# -*- coding: utf-8 -*-
"""Закреплённые инструменты: загрузка с проверкой SHA-256 и опрос фактических версий."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

LOCK = Path(__file__).with_name("tools.json")


class ToolError(RuntimeError):
    pass


def lock() -> dict:
    return json.loads(LOCK.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_member(archive: Path, member: str, dest: Path) -> Path:
    """Достаёт из tar.gz один исполняемый файл верхнего уровня; ссылки и пути с «..» отвергаются."""
    with tarfile.open(archive, "r:gz") as tf:
        m = tf.getmember(member)
        if not m.isfile() or "/" in m.name or m.name in ("", ".", ".."):
            raise ToolError(f"{archive.name}: {member} — не обычный файл верхнего уровня")
        src = tf.extractfile(m)
        if src is None:
            raise ToolError(f"{archive.name}: не удалось прочитать {member}")
        dest.mkdir(parents=True, exist_ok=True)
        out = dest / member
        with open(out, "wb") as f:
            shutil.copyfileobj(src, f)
    out.chmod(0o755)
    return out


def install(dest: Path, only: Optional[List[str]] = None, cache: Optional[Path] = None) -> Dict[str, str]:
    """Скачивает и проверяет архивы; возвращает {инструмент: путь}. cache — каталог с уже скачанными архивами."""
    res = {}
    for name, t in lock()["binaries"].items():
        if only and name not in only:
            continue
        fname = t["url"].rsplit("/", 1)[1]
        with tempfile.TemporaryDirectory() as tmp:
            arc = Path(tmp) / fname
            cached = cache / fname if cache else None
            if cached and cached.exists():
                shutil.copyfile(cached, arc)
            else:
                with urllib.request.urlopen(t["url"], timeout=120) as r, open(arc, "wb") as f:
                    shutil.copyfileobj(r, f)
            got = _sha256(arc)
            if got != t["sha256"]:
                raise ToolError(f"{name}: SHA-256 архива {got}, ожидалось {t['sha256']}")
            res[name] = str(extract_member(arc, t["member"], Path(dest)))
    return res


def probe(cmd: List[str], timeout: int = 60) -> str:
    """Первая непустая строка вывода команды версии; пустая строка, если команды нет."""
    exe = shutil.which(cmd[0])
    if not exe:
        return ""
    try:
        r = subprocess.run([exe] + cmd[1:], capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return (r.stdout or r.stderr).strip()


def version_matches(expected: str, output: str) -> bool:
    return bool(output) and expected in output


def probe_all() -> Dict[str, dict]:
    """Фактические версии закреплённых инструментов, доступных в PATH."""
    out: Dict[str, dict] = {}
    lk = lock()
    for group in ("binaries", "python"):
        for name, t in lk[group].items():
            if "probe" not in t:
                continue
            text = probe(t["probe"])
            out[name] = {"expected": t["version"], "found": bool(text),
                         "matches": version_matches(t["version"], text) if text else None,
                         "output": text[:400]}
    img = lk["images"]["clamav"]["image"]
    docker = shutil.which("docker")
    if docker:
        try:
            r = subprocess.run([docker, "image", "inspect", img, "--format", "{{json .RepoDigests}}"],
                               capture_output=True, text=True, timeout=60)
            digests = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else []
        except (OSError, subprocess.TimeoutExpired, ValueError):
            digests = []
        out["clamav"] = {"expected": img, "found": bool(digests), "matches": None, "output": " ".join(digests)}
    return out
