from pathlib import Path

import pytest

from demo_app import cli, manifest


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "fw").mkdir()
    (tmp_path / "fw" / "app.bin").write_bytes(b"\x00\x01\x02")
    (tmp_path / "fw" / "README").write_text("v1\n", encoding="utf-8")
    return tmp_path / "fw"


def test_build_is_sorted_and_relative(tree):
    m = manifest.build(tree)
    assert [f["path"] for f in m["files"]] == ["README", "app.bin"]
    assert m["files"][1]["size"] == 3


def test_roundtrip_and_verify_clean(tree):
    m = manifest.load(manifest.dump(manifest.build(tree)))
    assert manifest.verify(m, tree) == []


def test_verify_detects_change_missing_and_extra(tree):
    m = manifest.build(tree)
    (tree / "app.bin").write_bytes(b"\x00\x01\x03")
    (tree / "README").unlink()
    (tree / "extra.bin").write_bytes(b"x")
    assert manifest.verify(m, tree) == ["нет файла: README", "изменён: app.bin", "лишний файл: extra.bin"]


def test_verify_rejects_parent_paths(tree):
    m = {"format": manifest.FORMAT, "files": [{"path": "../outside", "size": 0, "sha256": ""}]}
    assert manifest.verify(m, tree) == ["нет файла: ../outside", "лишний файл: README", "лишний файл: app.bin"]


def test_load_rejects_unknown_format():
    with pytest.raises(ValueError):
        manifest.load("format: other\nfiles: []\n")


def test_cli_build_and_verify(tree, tmp_path, capsys):
    out = tmp_path / "manifest.yaml"
    assert cli.main(["build", str(tree), "-o", str(out)]) == 0
    assert cli.main(["verify", str(out), str(tree)]) == 0
    (tree / "app.bin").write_bytes(b"changed")
    assert cli.main(["verify", str(out), str(tree)]) == 1
    assert "изменён: app.bin" in capsys.readouterr().out
