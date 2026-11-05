# -*- coding: utf-8 -*-
"""Сборка и её проверки.

  build-run      журнал аудита сборки и контрольные суммы результатов        -> 5.13.3.4
  store-verify   результаты, полученные из хранилища, совпадают с собранными -> 5.13.3.5
  repro          две независимые сборки дали одинаковые результаты           -> 5.13.3.6
  attest-verify  аттестации происхождения проверяются так, как их проверит
                 пользователь (gh attestation verify)                        -> 5.20.3.4
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List

from .states import put_state, write_json

RUNNER_VARS = ("RUNNER_NAME", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT", "ImageOS", "ImageVersion")
RUN_VARS = ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
            "GITHUB_WORKFLOW_REF", "GITHUB_JOB", "GITHUB_EVENT_NAME", "GITHUB_ACTOR", "GITHUB_SERVER_URL")


class BuildError(RuntimeError):
    pass


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def checksums(dist: Path) -> Dict[str, str]:
    dist = Path(dist)
    if not dist.is_dir():
        return {}
    return {p.relative_to(dist).as_posix(): sha256_file(p) for p in sorted(dist.rglob("*")) if p.is_file()}


def write_sums(path: Path, sums: Dict[str, str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{h}  {name}\n" for name, h in sorted(sums.items())), encoding="utf-8")
    return path


def read_sums(path: Path) -> Dict[str, str]:
    res = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            h, name = line.split(None, 1)
            res[name.strip().lstrip("*")] = h
    return res


def source_date_epoch(project_dir: Path) -> str:
    if os.environ.get("SOURCE_DATE_EPOCH"):
        return os.environ["SOURCE_DATE_EPOCH"]
    try:
        r = subprocess.run(["git", "-C", str(project_dir), "log", "-1", "--format=%ct"], capture_output=True,
                           text=True, timeout=60)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def run(out: Path, role: str, command: str, project_dir: Path, dist: str, clean: bool = False) -> int:
    """Выполняет команду сборки, пишет журнал и сведения о сборке; возвращает код завершения команды."""
    project_dir = Path(project_dir).resolve()
    dist_dir = (project_dir / dist).resolve()
    if dist_dir.exists() and any(dist_dir.iterdir()):
        if not clean:
            raise BuildError(f"каталог результатов {dist_dir} не пуст (используйте --clean)")
        shutil.rmtree(dist_dir)
    d = Path(out) / role
    d.mkdir(parents=True, exist_ok=True)
    log_path = d / "build.log"
    env = dict(os.environ)
    sde = source_date_epoch(project_dir)
    if sde:
        env["SOURCE_DATE_EPOCH"] = sde
    started, t0 = _now(), time.monotonic()
    with open(log_path, "w", encoding="utf-8") as log:
        log.write(f"# rbpo-pipeline build-run ({role}) {started}\n# command: {command}\n"
                  f"# SOURCE_DATE_EPOCH={sde}\n")
        log.flush()
        proc = subprocess.Popen(["bash", "-c", command], cwd=project_dir, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, errors="replace")
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            log.write(line)
        code = proc.wait()
        log.write(f"# exit code: {code}\n")
    finished, duration = _now(), round(time.monotonic() - t0, 1)
    sums = checksums(dist_dir)
    write_sums(d / "SHA256SUMS", sums)
    head = ""
    try:
        head = subprocess.run(["git", "-C", str(project_dir), "rev-parse", "HEAD"], capture_output=True, text=True,
                              timeout=60).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    info = {"role": role, "command": command, "project_dir": str(project_dir), "dist": dist, "head": head,
            "source_date_epoch": sde, "started": started, "finished": finished, "duration_s": duration,
            "exit_code": code, "log_sha256": sha256_file(log_path),
            "outputs": [{"path": n, "sha256": h, "size": (dist_dir / n).stat().st_size} for n, h in sums.items()],
            "runner": {k: os.environ.get(k, "") for k in RUNNER_VARS},
            "run": {k: os.environ.get(k, "") for k in RUN_VARS}}
    write_json(d / "build.json", info)
    if role == "build":
        files = [f"{role}/build.log", f"{role}/build.json", f"{role}/SHA256SUMS"]
        note = (f"журнал сборки и сведения о ней: команда, время, код завершения {code}, SHA-256 журнала и "
                f"{len(sums)} результатов; целостность журнала защищена аттестацией комплекта свидетельств")
        put_state(out, "5.13.3.4", "P", files, {"exit_code": code, "outputs": len(sums), "duration_s": duration},
                  note, "rbpo-pipeline")
    return code


def store_verify(out: Path, dist: Path, sums_path: Path, storage: dict) -> dict:
    """Сверка результатов, полученных из хранилища артефактов, с контрольными суммами сборки."""
    if not Path(sums_path).exists():
        put_state(out, "5.13.3.5", "N", [], {}, "нет контрольных сумм сборки", "rbpo-pipeline")
        return {}
    expected, got = read_sums(sums_path), checksums(Path(dist))
    missing = sorted(set(expected) - set(got))
    extra = sorted(set(got) - set(expected))
    changed = sorted(n for n in set(expected) & set(got) if expected[n] != got[n])
    res = {"storage": storage, "expected": len(expected), "retrieved": len(got), "missing": missing,
           "extra": extra, "changed": changed}
    write_json(Path(out) / "verify" / "storage.json", res)
    if not expected:
        st, note = "N", "сборка не дала результатов"
    elif missing or extra or changed:
        st, note = "F", (f"результаты из хранилища не совпадают с собранными: нет {len(missing)}, "
                         f"лишних {len(extra)}, изменено {len(changed)}")
    else:
        st = "P"
        note = f"{len(expected)} результатов получены из хранилища и совпали с контрольными суммами сборки"
        if storage.get("artifact_id"):
            note += f" (артефакт {storage['artifact_id']})"
    put_state(out, "5.13.3.5", st, ["verify/storage.json", "build/SHA256SUMS"], res, note, "rbpo-pipeline")
    return res


def repro(out: Path, a_path: Path, b_path: Path) -> dict:
    if not Path(a_path).exists() or not Path(b_path).exists():
        put_state(out, "5.13.3.6", "N", [], {}, "нет результатов повторной сборки", "rbpo-pipeline")
        return {}
    a, b = read_sums(a_path), read_sums(b_path)
    differ = sorted(n for n in set(a) | set(b) if a.get(n) != b.get(n))
    res = {"build": a, "rebuild": b, "differ": differ}
    write_json(Path(out) / "verify" / "repro.json", res)
    if not a:
        st, note = "N", "сборка не дала результатов"
    elif differ:
        st, note = "F", f"повторная сборка дала другие результаты: {', '.join(differ)}"
    else:
        st, note = "P", f"две независимые сборки дали побитово одинаковые результаты ({len(a)})"
    put_state(out, "5.13.3.6", st, ["verify/repro.json", "build/SHA256SUMS", "rebuild/SHA256SUMS"],
              {"outputs": len(a), "differ": len(differ)}, note, "rbpo-pipeline")
    return res


def attest_verify(out: Path, dist: Path, repo: str, signer_workflow: str, source_digest: str,
                  skip: str = "") -> dict:
    """Проверка аттестаций происхождения каждого результата сборки через gh attestation verify."""
    files = sorted(p for p in Path(dist).rglob("*") if p.is_file()) if Path(dist).is_dir() else []
    gh = shutil.which("gh")
    if skip or not gh or not files:
        why = skip or ("нет gh" if not gh else "нет результатов сборки")
        put_state(out, "5.20.3.4", "N", [], {}, f"проверка аттестаций не выполнялась: {why}", "gh")
        return {}
    results: List[dict] = []
    for f in files:
        cmd = [gh, "attestation", "verify", str(f), "--repo", repo, "--format", "json"]
        if signer_workflow:
            cmd += ["--signer-workflow", signer_workflow]
        if source_digest:
            cmd += ["--source-digest", source_digest]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            ok, detail = r.returncode == 0, (r.stdout if r.returncode == 0 else r.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            ok, detail = False, str(e)
        item = {"file": f.relative_to(dist).as_posix(), "sha256": sha256_file(f), "verified": ok}
        if ok:
            try:
                v = json.loads(detail)[0]["verificationResult"]
                sig = v["signature"]["certificate"]
                item.update(predicate_type=v["statement"]["predicateType"],
                            signer=sig.get("buildSignerURI", ""), source=sig.get("sourceRepositoryURI", ""),
                            source_digest=sig.get("sourceRepositoryDigest", ""),
                            runner=sig.get("runnerEnvironment", ""))
            except (ValueError, KeyError, IndexError, TypeError):
                item["raw"] = detail[:2000]
        else:
            item["error"] = detail[-2000:]
        results.append(item)
    res = {"repo": repo, "signer_workflow": signer_workflow, "source_digest": source_digest, "results": results}
    write_json(Path(out) / "verify" / "attestations.json", res)
    bad = [x["file"] for x in results if not x["verified"]]
    if bad:
        st, note = "F", f"аттестация не подтверждена для: {', '.join(bad)}"
    else:
        st, note = "P", (f"аттестации происхождения {len(results)} результатов проверены "
                         f"(gh attestation verify, подписант {signer_workflow or repo})")
    put_state(out, "5.20.3.4", st, ["verify/attestations.json", "build/SHA256SUMS"],
              {"files": len(results), "failed": len(bad)}, note, "gh")
    return res
