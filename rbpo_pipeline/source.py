# -*- coding: utf-8 -*-
"""Исходный код: свидетельства контроля изменений (5.4.3.3) и контроля целостности (5.14.3.3).

Диапазон изменений определяется по событию GitHub Actions:
  pull_request          — от базы запроса до его последнего коммита;
  push тега             — от предыдущего тега до текущего;
  push ветки            — от состояния ветки до отправки (before) до текущего коммита;
  прочие события        — от последнего тега до текущего коммита; без тегов — последний коммит.

Подписи коммитов проверяются через GitHub API (поле verification), без него — локально git.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .states import put_state, write_json

ZERO = "0" * 40
MAX_COMMITS = 250
DOC_EXT = {".md", ".rst", ".txt", ".adoc", ".tex", ".odt", ".docx", ".pdf"}
BAD_REASONS = {"invalid", "malformed_signature", "bad_email", "bad_cert", "ocsp_revoked"}
LOCAL_SIG = {"G": "valid", "U": "valid", "B": "invalid", "R": "ocsp_revoked", "X": "expired_key",
             "Y": "expired_key", "E": "unknown_key", "N": "unsigned"}


class GitError(RuntimeError):
    pass


def git(root: Path, *args: str, binary: bool = False):
    r = subprocess.run(["git", "-C", str(root)] + list(args), capture_output=True, timeout=120)
    if r.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {r.stderr.decode('utf-8', 'replace').strip()}")
    return r.stdout if binary else r.stdout.decode("utf-8", "replace")


def _ok(root: Path, *args: str) -> bool:
    try:
        git(root, *args)
        return True
    except GitError:
        return False


def _tag_before(root: Path, rev: str) -> Optional[str]:
    try:
        tag = git(root, "describe", "--tags", "--abbrev=0", rev).strip()
        return git(root, "rev-list", "-n", "1", tag).strip() if tag else None
    except GitError:
        return None


def resolve_range(root: Path, event_name: str, event: dict, ref: str) -> Tuple[Optional[str], str, str]:
    """(база или None, конец диапазона, как определён)."""
    head = git(root, "rev-parse", "HEAD").strip()
    if event_name in ("pull_request", "pull_request_target") and event.get("pull_request"):
        pr = event["pull_request"]
        h, b = pr.get("head", {}).get("sha", ""), pr.get("base", {}).get("sha", "")
        if h and _ok(root, "cat-file", "-e", f"{h}^{{commit}}"):
            head = h
        if b and _ok(root, "cat-file", "-e", f"{b}^{{commit}}"):
            return b, head, f"запрос на слияние #{pr.get('number', '')}: база..последний коммит"
    if ref.startswith("refs/tags/"):
        prev = _tag_before(root, f"{head}^") if _ok(root, "rev-parse", f"{head}^") else None
        if prev:
            return prev, head, "выпуск: предыдущий тег..текущий тег"
        return None, head, "выпуск: предыдущего тега нет, учтён последний коммит"
    before = str(event.get("before") or "")
    if event_name == "push" and before and before != ZERO and _ok(root, "cat-file", "-e", f"{before}^{{commit}}"):
        return before, head, "отправка в ветку: before..after"
    prev = _tag_before(root, head)
    if prev and prev != head:
        return prev, head, "последний тег..текущий коммит"
    return None, head, "последний коммит"


def list_commits(root: Path, base: Optional[str], head: str) -> List[dict]:
    fmt = "%H%x1f%an%x1f%aI%x1f%cn%x1f%cI%x1f%G?%x1f%P%x1f%s%x1e"
    spec = [f"{base}..{head}"] if base else ["-1", head]
    out = git(root, "log", f"--max-count={MAX_COMMITS}", f"--format={fmt}", *spec)
    res = []
    for rec in out.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, an, ad, cn, cd, sig, parents, subj = rec.split("\x1f", 7)
        res.append({"sha": sha, "author": an, "authored": ad, "committer": cn, "committed": cd,
                    "local_signature": sig, "merge": len(parents.split()) > 1, "subject": subj})
    return res


def changed_files(root: Path, base: Optional[str], head: str, subdir: str = ".") -> List[dict]:
    """Изменённые файлы диапазона по всему репозиторию; in_project — файл в каталоге проекта."""
    if base:
        out = git(root, "diff", "--name-status", "--no-renames", base, head)
    else:
        out = git(root, "diff-tree", "--no-commit-id", "--name-status", "--no-renames", "-r", "--root", head)
    prefix = "" if subdir in ("", ".") else subdir.rstrip("/") + "/"
    res = []
    for line in out.splitlines():
        if not line.strip():
            continue
        st, path = line.split("\t", 1)
        p = Path(path)
        kind = "documentation" if p.suffix.lower() in DOC_EXT or "docs" in p.parts or "doc" in p.parts else "software"
        res.append({"status": st, "path": path, "kind": kind, "in_project": path.startswith(prefix)})
    return res


def github_verification(repo: str, base: Optional[str], head: str) -> Dict[str, dict]:
    """sha -> {verified, reason} из GitHub API; пустой словарь, если API недоступен."""
    gh = shutil.which("gh")
    if not gh or not repo or not (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")):
        return {}
    path = f"repos/{repo}/compare/{base}...{head}" if base else f"repos/{repo}/commits/{head}"
    try:
        r = subprocess.run([gh, "api", path], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return {}
        data = json.loads(r.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {}
    commits = data.get("commits", []) if base else [data]
    return {c["sha"]: {"verified": bool(c["commit"]["verification"]["verified"]),
                       "reason": c["commit"]["verification"]["reason"]}
            for c in commits if c.get("commit", {}).get("verification")}


def classify(reason: str) -> str:
    if reason == "valid":
        return "verified"
    if reason == "unsigned":
        return "unsigned"
    if reason in BAD_REASONS:
        return "bad"
    return "unverifiable"


def _archive_sha256(root: Path, head: str, subdir: str) -> str:
    args = ["archive", "--format=tar", head]
    if subdir and subdir != ".":
        args.append(subdir)
    data = git(root, *args, binary=True)
    return hashlib.sha256(data).hexdigest()


def collect(out: Path, project_dir: Path, repo: str, event_name: str, event: dict, ref: str,
            signature_policy: str, use_api: bool = True) -> dict:
    project_dir = Path(project_dir).resolve()
    try:
        top = Path(git(project_dir, "rev-parse", "--show-toplevel").strip())
    except GitError as e:
        put_state(out, "5.4.3.3", "N", [], {}, f"нет репозитория git: {e}", "git")
        put_state(out, "5.14.3.3", "N", [], {}, "нет репозитория git", "git")
        return {}
    subdir = project_dir.relative_to(top).as_posix() if project_dir != top else "."
    try:
        shallow = git(top, "rev-parse", "--is-shallow-repository").strip() == "true"
    except GitError:
        shallow = False
    base, head, how = resolve_range(top, event_name, event, ref)
    commits = list_commits(top, base, head)
    files = changed_files(top, base, head, subdir)

    # 5.4.3.3 — изменения ПО и документации в диапазоне
    proj = [f for f in files if f["in_project"]]
    changes = {"range": {"base": base, "head": head, "how": how, "shallow_clone": shallow},
               "project_dir": subdir, "commits": commits, "files": files,
               "counts": {"commits": len(commits), "files": len(files), "project_files": len(proj),
                          "software": sum(1 for f in proj if f["kind"] == "software"),
                          "documentation": sum(1 for f in proj if f["kind"] == "documentation")}}
    ch_path = write_json(out / "source" / "changes.json", changes)
    where = "в репозитории" if subdir == "." else f"в репозитории, из них в каталоге проекта {len(proj)}"
    note = (f"{how}; коммитов {len(commits)}, изменённых файлов {len(files)} {where} "
            f"(ПО {changes['counts']['software']}, документация {changes['counts']['documentation']})")
    if shallow:
        note += "; неполная история (shallow clone)"
    put_state(out, "5.4.3.3", "P" if commits else "N", ["source/changes.json"], changes["counts"], note, "git")

    # 5.14.3.3 — целостность: дерево совпадает с коммитом, снимок зафиксирован, подписи проверены
    status = git(project_dir, "status", "--porcelain=v1", "--untracked-files=all", "--", ".").splitlines()
    api = github_verification(repo, base, head) if use_api else {}
    sigs = []
    for c in commits:
        if c["sha"] in api:
            src, reason = "github", api[c["sha"]]["reason"]
        else:
            src, reason = "git", LOCAL_SIG.get(c["local_signature"], "unknown_signature_type")
        sigs.append({"sha": c["sha"], "source": src, "reason": reason, "class": classify(reason)})
    counts = {k: sum(1 for s in sigs if s["class"] == k) for k in ("verified", "unsigned", "unverifiable", "bad")}
    integrity = {"project_dir": subdir, "head": head, "tree": git(top, "rev-parse", f"{head}^{{tree}}").strip(),
                 "source_archive_sha256": _archive_sha256(top, head, subdir),
                 "working_tree_clean": not status, "working_tree_changes": status[:50],
                 "signature_policy": signature_policy, "signatures": sigs, "signature_counts": counts}
    in_path = write_json(out / "source" / "integrity.json", integrity)
    problems = []
    if status:
        problems.append(f"рабочее дерево отличается от коммита ({len(status)} путей)")
    if counts["bad"]:
        problems.append(f"недействительных подписей: {counts['bad']}")
    if signature_policy == "require" and (counts["unsigned"] or counts["unverifiable"]):
        problems.append(f"коммитов без проверенной подписи: {counts['unsigned'] + counts['unverifiable']} "
                        "(политика require)")
    note = (f"коммит {head[:12]}, дерево {integrity['tree'][:12]}; подписи: проверено {counts['verified']}, "
            f"без подписи {counts['unsigned']}, не проверяется {counts['unverifiable']}, "
            f"недействительно {counts['bad']} (политика {signature_policy})")
    if problems:
        note = "; ".join(problems) + "; " + note
    put_state(out, "5.14.3.3", "F" if problems else "P", ["source/integrity.json"],
              {"working_tree_clean": not status, **counts}, note, "git")
    return {"changes": str(ch_path), "integrity": str(in_path)}
