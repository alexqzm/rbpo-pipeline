#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Стенд для испытаний агента разметки.

    python agent/stand/make_stand.py <каталог>

В новый каталог попадают: мини-проект (репозиторий git с одним коммитом), правила AGENTS.md и
скилл rbpo-triage, комплект свидетельств .rbpo-evidence, собранный шагами source, sca и sast из
отчётов agent/stand/reports. Эталон expected.yaml в стенд не копируется: агент его видеть не должен.
Рядом с каталогом пишется <каталог>.sha256 — контрольные суммы комплекта свидетельств: после работы
агента комплект должен остаться прежним (в каталоге стенда: sha256sum -c ../<каталог>.sha256).
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
KIT = HERE.parent
OUT = ".rbpo-evidence"


def run(*cmd: str, cwd: Path) -> None:
    r = subprocess.run(list(cmd), cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"{' '.join(cmd)}: {(r.stderr or r.stdout).strip()}")


def checksums(root: Path) -> str:
    """Контрольные суммы комплекта свидетельств в формате sha256sum, пути — от каталога стенда."""
    return "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}\n"
                   for p in sorted((root / OUT).rglob("*")) if p.is_file())


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0].startswith("-"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    dest = Path(args[0]).resolve()
    if dest.exists() and any(dest.iterdir()):
        print(f"{dest}: каталог не пуст", file=sys.stderr)
        return 2
    shutil.copytree(HERE / "project", dest, dirs_exist_ok=True)
    shutil.copy(KIT / "AGENTS.template.md", dest / "AGENTS.md")
    shutil.copytree(KIT / "skills", dest / "skills")
    (dest / ".rbpo" / "proposals").mkdir(parents=True, exist_ok=True)

    run("git", "init", "-q", "-b", "main", cwd=dest)
    run("git", "add", "-A", cwd=dest)
    run("git", "-c", "user.name=stand", "-c", "user.email=stand@example.invalid", "-c", "commit.gpgsign=false",
        "commit", "-q", "-m", "Стенд: исходное состояние", cwd=dest)

    rbpo = (sys.executable, "-m", "rbpo_pipeline")
    reports = HERE / "reports"
    run(*rbpo, "source", "--out", OUT, "--no-api", cwd=dest)
    run(*rbpo, "sca", "--out", OUT, "--sbom", str(reports / "sbom.cdx.json"), "--grype", str(reports / "grype.json"),
        cwd=dest)
    run(*rbpo, "sast", "--out", OUT, "--sarif", str(reports / "semgrep.sarif"), "--json", str(reports / "semgrep.json"),
        "--config-name", "p/python", cwd=dest)
    sums = dest.with_name(dest.name + ".sha256")
    sums.write_text(checksums(dest), encoding="utf-8")

    print(f"Стенд готов: {dest}\n"
          f"  контрольные суммы комплекта: {sums}\n"
          f"  очередь разметки:   rbpo-pipeline triage-queue --out {OUT}\n"
          f"  задание агенту:     «Разбери очередь разметки по скиллу rbpo-triage, комплект свидетельств — {OUT}»\n"
          f"  после работы агента: rbpo-pipeline proposals-check --out {OUT} --json check.json .rbpo/proposals/<имя>.yaml\n"
          f"                      rbpo-pipeline agent-guard --base main\n"
          f"                      python {HERE / 'score.py'} check.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
