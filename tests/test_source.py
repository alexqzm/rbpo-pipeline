import json

from rbpo_pipeline import source
from conftest import state


def _three_commits(repo):
    a = repo.commit({"src/app.py": "a = 1\n"}, "первый")
    repo.git("tag", "v0.1.0")
    b = repo.commit({"src/app.py": "a = 2\n", "docs/guide.md": "# Руководство\n"}, "второй (#12)")
    c = repo.commit({"README.md": "readme\n"}, "третий")
    return a, b, c


def test_range_push_tag_pr_and_default(repo):
    a, b, c = _three_commits(repo)
    root = repo.path
    assert source.resolve_range(root, "push", {"before": a}, "refs/heads/main")[:2] == (a, c)
    # новая ветка: before = нули -> от последнего тега
    base, head, how = source.resolve_range(root, "push", {"before": source.ZERO}, "refs/heads/main")
    assert (base, head) == (a, c) and "тег" in how
    repo.git("tag", "v0.2.0")
    base, head, how = source.resolve_range(root, "push", {}, "refs/tags/v0.2.0")
    assert (base, head) == (a, c) and "выпуск" in how
    pr = {"pull_request": {"number": 7, "base": {"sha": b}, "head": {"sha": c}}}
    base, head, how = source.resolve_range(root, "pull_request", pr, "refs/pull/7/merge")
    assert (base, head) == (b, c) and "#7" in how


def test_range_without_tags_is_last_commit(repo):
    repo.commit({"a.txt": "1\n"}, "one")
    c = repo.commit({"a.txt": "2\n"}, "two")
    assert source.resolve_range(repo.path, "workflow_dispatch", {}, "refs/heads/main") == (None, c, "последний коммит")


def test_collect_changes_and_integrity(out, repo):
    a, b, c = _three_commits(repo)
    source.collect(out, repo.path, "", "push", {"before": a}, "refs/heads/main", "report", use_api=False)
    ch = json.loads((out / "source" / "changes.json").read_text())
    assert [x["subject"] for x in ch["commits"]] == ["третий", "второй (#12)"]
    assert {(f["path"], f["kind"]) for f in ch["files"]} == {("README.md", "documentation"),
                                                              ("docs/guide.md", "documentation"),
                                                              ("src/app.py", "software")}
    st = state(out, "5.4.3.3")
    assert st["state"] == "P" and st["summary"]["commits"] == 2
    integ = json.loads((out / "source" / "integrity.json").read_text())
    assert integ["head"] == c and integ["working_tree_clean"] and len(integ["source_archive_sha256"]) == 64
    assert integ["signature_counts"]["unsigned"] == 2
    st = state(out, "5.14.3.3")
    assert st["state"] == "P" and "без подписи 2" in st["note"]


def test_integrity_require_signatures_and_dirty_tree(out, repo):
    _three_commits(repo)
    source.collect(out, repo.path, "", "workflow_dispatch", {}, "refs/heads/main", "require", use_api=False)
    st = state(out, "5.14.3.3")
    assert st["state"] == "F" and "политика require" in st["note"]
    (repo.path / "src" / "app.py").write_text("tampered\n", encoding="utf-8")
    source.collect(out, repo.path, "", "workflow_dispatch", {}, "refs/heads/main", "report", use_api=False)
    st = state(out, "5.14.3.3")
    assert st["state"] == "F" and "рабочее дерево отличается" in st["note"]


def test_subdirectory_scope(out, repo):
    repo.commit({"app/x.py": "1\n", "app/docs/a.md": "a\n", "other/y.py": "1\n"}, "init")
    (repo.path / "other" / "y.py").write_text("changed\n", encoding="utf-8")
    source.collect(out, repo.path / "app", "", "workflow_dispatch", {}, "refs/heads/main", "report", use_api=False)
    integ = json.loads((out / "source" / "integrity.json").read_text())
    assert integ["project_dir"] == "app" and integ["working_tree_clean"]
    ch = json.loads((out / "source" / "changes.json").read_text())
    assert ch["counts"] == {"commits": 1, "files": 3, "project_files": 2, "software": 1, "documentation": 1}
    assert "в каталоге проекта 2" in state(out, "5.4.3.3")["note"]


def test_classify():
    assert source.classify("valid") == "verified"
    assert source.classify("unsigned") == "unsigned"
    assert source.classify("invalid") == "bad"
    assert source.classify("unknown_key") == "unverifiable"


def test_not_a_repository(out, tmp_path):
    (tmp_path / "plain").mkdir()
    source.collect(out, tmp_path / "plain", "", "", {}, "", "report", use_api=False)
    assert state(out, "5.4.3.3")["state"] == "N" and state(out, "5.14.3.3")["state"] == "N"
