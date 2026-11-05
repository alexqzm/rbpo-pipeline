import hashlib
import io
import re
import tarfile
from pathlib import Path

import pytest
import yaml

from rbpo_pipeline import org, tools
from rbpo_pipeline.assemble import AUTOMATED
from conftest import state

ROOT = Path(__file__).resolve().parent.parent


def test_slug_like_github():
    assert org.slug("5.10.3.1 Регламент статического анализа") == "51031-регламент-статического-анализа"
    assert org.slug("Сборка `python -m build`") == "сборка-python--m-build"
    assert org.slug("[Схема](scheme.svg) среды") == "схема-среды"


def test_anchors_duplicates_ids_and_code_blocks():
    text = "# Раздел\n## Раздел\n<a id=\"scheme\"></a>\n```\n# не заголовок\n```\n"
    assert org.anchors(text) == ["раздел", "раздел-1", "scheme"]


def test_collect_presence_anchor_and_copy(out, tmp_path):
    proj = tmp_path / "proj"
    (proj / "docs").mkdir(parents=True)
    (proj / "docs" / "guide.md").write_text("# Руководство\n## Статический анализ\n", encoding="utf-8")
    items = org.collect(out, proj, {"5.10.3.1": "docs/guide.md#статический-анализ",
                                    "5.12.3.1": "docs/guide.md#сборка",
                                    "5.13.3.3": "docs/scheme.svg"}, AUTOMATED)
    by = {i["artifact"]: i for i in items}
    assert by["5.10.3.1"]["state"] == "P" and (out / "org" / "files" / "docs" / "guide.md").exists()
    assert by["5.12.3.1"]["state"] == "N" and "нет раздела" in by["5.12.3.1"]["note"]
    assert by["5.13.3.3"]["state"] == "N"
    assert state(out, "5.10.3.1")["files"] == ["org/files/docs/guide.md"]


def test_collect_rejects_automated_and_outside_paths(out, tmp_path):
    with pytest.raises(ValueError, match="формирует конвейер"):
        org.collect(out, tmp_path, {"5.10.3.4": "x.md"}, AUTOMATED)
    with pytest.raises(ValueError, match="вне каталога"):
        org.collect(out, tmp_path / "p", {"5.10.3.1": "../x.md"}, AUTOMATED)


def test_lock_is_well_formed():
    lk = tools.lock()
    for name, t in lk["binaries"].items():
        assert t["url"].startswith("https://github.com/") and re.fullmatch(r"[0-9a-f]{64}", t["sha256"]), name
        assert t["version"] in t["url"]
    for name, t in lk["python"].items():
        assert t["spec"] == f"{name}=={t['version']}"
    for name, a in lk["actions"].items():
        assert re.fullmatch(r"[0-9a-f]{40}", a["sha"]), name


def test_workflows_use_only_pinned_actions():
    """Каждый uses: в рабочих процессах — действие из tools.json, закреплённое тем же SHA, или локальный файл."""
    pins = {k: v["sha"] for k, v in tools.lock()["actions"].items()}
    seen = set()
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for uses in re.findall(r"^\s*(?:-\s*)?uses:\s*(\S+)", wf.read_text(encoding="utf-8"), re.M):
            if uses.startswith("./"):
                continue
            action, _, ref = uses.partition("@")
            assert action in pins, f"{wf.name}: {uses} не закреплено в tools.json"
            assert ref == pins[action], f"{wf.name}: {uses} — ожидался {pins[action]}"
            seen.add(action)
    assert seen == set(pins), f"в tools.json лишние действия: {set(pins) - seen}"


def test_reusable_workflow_semgrep_and_clamav_match_lock():
    text = (ROOT / ".github" / "workflows" / "rbpo.yml").read_text(encoding="utf-8")
    lk = tools.lock()
    assert lk["python"]["semgrep"]["spec"] in text
    assert lk["images"]["clamav"]["image"] in text
    wf = yaml.safe_load(text)
    assert "workflow_call" in wf[True]


def _tgz(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data, kind in members:
            ti = tarfile.TarInfo(name)
            if kind == "sym":
                ti.type, ti.linkname = tarfile.SYMTYPE, "/etc/passwd"
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_extract_member_rejects_links_and_nested(tmp_path):
    arc = tmp_path / "a.tar.gz"
    arc.write_bytes(_tgz([("tool", b"#!/bin/sh\n", "file"), ("evil", b"", "sym"), ("dir/x", b"1", "file")]))
    p = tools.extract_member(arc, "tool", tmp_path / "bin")
    assert p.read_bytes() == b"#!/bin/sh\n" and p.stat().st_mode & 0o111
    with pytest.raises(tools.ToolError):
        tools.extract_member(arc, "evil", tmp_path / "bin")
    with pytest.raises(tools.ToolError):
        tools.extract_member(arc, "dir/x", tmp_path / "bin")


def test_install_checks_sha256(tmp_path, monkeypatch):
    data = _tgz([("syft", b"bin", "file")])
    cache = tmp_path / "cache"
    cache.mkdir()
    lk = tools.lock()
    fname = lk["binaries"]["syft"]["url"].rsplit("/", 1)[1]
    (cache / fname).write_bytes(data)
    with pytest.raises(tools.ToolError, match="SHA-256"):
        tools.install(tmp_path / "bin", ["syft"], cache)
    lk["binaries"]["syft"]["sha256"] = hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(tools, "lock", lambda: lk)
    res = tools.install(tmp_path / "bin", ["syft"], cache)
    assert Path(res["syft"]).read_bytes() == b"bin"
