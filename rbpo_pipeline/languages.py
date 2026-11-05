# -*- coding: utf-8 -*-
"""Языки исходного кода проекта — для перечня инструментов статического анализа (5.10.3.2).

Язык определяется по расширению или имени файла среди файлов, которые отслеживает git. Покрытие
языка инструментом проверяется по факту: среди файлов, которые статический анализатор
действительно разобрал (paths.scanned в JSON-выводе Semgrep), есть файлы этого языка.
"""
from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional

EXT = {
    ".py": "Python", ".pyi": "Python",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".go": "Go", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
    ".cs": "C#", ".rb": "Ruby", ".php": "PHP", ".swift": "Swift", ".rs": "Rust",
    ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++",
    ".hxx": "C++", ".sh": "Bash", ".bash": "Bash", ".lua": "Lua", ".ex": "Elixir", ".exs": "Elixir",
    ".sol": "Solidity", ".tf": "Terraform", ".dart": "Dart", ".ml": "OCaml", ".r": "R",
    ".pl": "Perl", ".pm": "Perl", ".s": "Assembly", ".asm": "Assembly", ".hs": "Haskell",
    ".erl": "Erlang", ".f90": "Fortran", ".f": "Fortran", ".pas": "Pascal", ".adb": "Ada", ".ads": "Ada",
    ".vhd": "VHDL", ".vhdl": "VHDL", ".sv": "SystemVerilog", ".groovy": "Groovy", ".ps1": "PowerShell",
    ".zig": "Zig",
}
NAMES = {"Dockerfile": "Dockerfile", "Containerfile": "Dockerfile"}


def language_of(path: str) -> Optional[str]:
    p = Path(path)
    if p.name in NAMES or p.name.startswith("Dockerfile."):
        return "Dockerfile"
    return EXT.get(p.suffix.lower())


def tracked_files(root: Path) -> List[str]:
    """Файлы, которые отслеживает git, относительно root; без git — обход каталога без скрытых."""
    try:
        r = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, timeout=60)
        if r.returncode == 0:
            return [x for x in r.stdout.decode("utf-8", "replace").split("\0") if x]
    except (OSError, subprocess.TimeoutExpired):
        pass
    root = Path(root)
    return [p.relative_to(root).as_posix() for p in root.rglob("*")
            if p.is_file() and not any(part.startswith(".") for part in p.relative_to(root).parts)]


def count(files: Iterable[str]) -> Dict[str, int]:
    c: Counter = Counter()
    for f in files:
        lang = language_of(f)
        if lang:
            c[lang] += 1
    return dict(sorted(c.items()))


def coverage(project: Dict[str, int], scanned: Dict[str, int], exclusions: Dict[str, str]) -> dict:
    """Какие языки проекта разобраны анализатором, какие исключены с обоснованием, какие не покрыты."""
    covered = sorted(x for x in project if scanned.get(x))
    excluded = {x: exclusions[x] for x in project if not scanned.get(x) and x in exclusions}
    uncovered = sorted(x for x in project if not scanned.get(x) and x not in exclusions)
    return {"project": project, "scanned": scanned, "covered": covered, "excluded": excluded,
            "uncovered": uncovered}
