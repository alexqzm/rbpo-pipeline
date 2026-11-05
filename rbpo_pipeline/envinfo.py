# -*- coding: utf-8 -*-
"""Сведения о сборочной среде и её инструментах (5.12.3.2)."""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

from . import __version__, tools
from .build import RUN_VARS, RUNNER_VARS
from .states import put_state, write_json


def _os_release() -> str:
    p = Path("/etc/os-release")
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    return ""


def _pip_version() -> str:
    try:
        r = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True, text=True, timeout=60)
        return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def collect(out: Path) -> dict:
    lk = tools.lock()
    probes = tools.probe_all()
    info = {
        "pipeline": {"name": "rbpo-pipeline", "version": __version__},
        "os": {"platform": platform.platform(), "release": _os_release(), "machine": platform.machine()},
        "python": {"version": sys.version.split()[0], "implementation": platform.python_implementation(),
                   "pip": _pip_version()},
        "runner": {k: os.environ.get(k, "") for k in RUNNER_VARS},
        "run": {k: os.environ.get(k, "") for k in RUN_VARS},
        "pinned": {"binaries": lk["binaries"], "python": lk["python"], "images": lk["images"],
                   "actions": lk["actions"]},
        "probed": probes,
    }
    path = write_json(Path(out) / "env" / "environment.json", info)
    mismatched = sorted(n for n, p in probes.items() if p.get("matches") is False)
    absent = sorted(n for n, p in probes.items() if not p.get("found"))
    if mismatched:
        st = "F"
        note = f"фактические версии не совпадают с закреплёнными: {', '.join(mismatched)}"
    else:
        st = "P"
        osname = info["os"]["release"] or info["os"]["platform"]
        image = info["runner"].get("ImageOS", "")
        note = (f"{osname}" + (f", образ {image} {info['runner'].get('ImageVersion', '')}" if image else "")
                + f", Python {info['python']['version']}; версии инструментов совпадают с закреплёнными")
        if absent:
            note += f"; не запускались: {', '.join(absent)}"
    put_state(out, "5.12.3.2", st, ["env/environment.json"], {"mismatched": mismatched, "absent": absent}, note,
              "rbpo-pipeline")
    return info
