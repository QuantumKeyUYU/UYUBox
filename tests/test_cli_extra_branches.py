# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
# SPDX-License-Identifier: MIT

# tests/test_cli_extra_branches.py


import pytest
from click.testing import CliRunner

import zilant_prime_core.cli as cli_mod


@pytest.fixture
def runner():
    return CliRunner()


def test_pack_missing_password(tmp_path, runner):
    src = tmp_path / "file.txt"
    src.write_text("data")
    res = runner.invoke(cli_mod.cli, ["pack", str(src)])
    assert res.exit_code == 1
    assert "Missing password" in res.output


def test_pack_file_exists_no_overwrite(tmp_path, runner):
    src = tmp_path / "file.txt"
    src.write_text("x")
    dest = src.with_suffix(".zil")
    dest.write_bytes(b"old")
    res = runner.invoke(cli_mod.cli, ["pack", str(src), "-p", "pwd"], input="\n")
    assert res.exit_code == 1
    assert f"{dest.name} already exists" in res.output


def test_pack_file_exists_confirm_overwrite(tmp_path, runner):
    src = tmp_path / "file.txt"
    src.write_text("x")
    dest = src.with_suffix(".zil")
    dest.write_bytes(b"old")
    res = runner.invoke(cli_mod.cli, ["pack", str(src), "-p", "pwd"], input="y\n")
    assert res.exit_code == 0
    assert dest.read_bytes().endswith(b"x")


def test_pack_force_overwrite(tmp_path, runner):
    src = tmp_path / "file.txt"
    src.write_text("x")
    dest = src.with_suffix(".zil")
    dest.write_bytes(b"old")
    res = runner.invoke(cli_mod.cli, ["pack", str(src), "-p", "pwd", "--overwrite"])
    assert res.exit_code == 0
    assert dest.read_bytes().endswith(b"x")


def test_pack_prompt_password(monkeypatch, tmp_path, runner):
    src = tmp_path / "file.txt"
    src.write_text("x")
    dest = src.with_suffix(".zil")
    monkeypatch.setattr(cli_mod.click, "prompt", lambda *a, **k: "pwd")
    res = runner.invoke(cli_mod.cli, ["pack", str(src), "-p", "-"])
    assert res.exit_code == 0
    assert dest.exists()


def test_pack_internal_exception(monkeypatch, tmp_path, runner):
    src = tmp_path / "file.txt"
    src.write_text("x")
    monkeypatch.setattr(cli_mod, "_pack_bytes", lambda *a, **k: (_ for _ in ()).throw(Exception("boom")))
    res = runner.invoke(cli_mod.cli, ["pack", str(src), "-p", "pwd"])
    assert res.exit_code == 1
    assert "Pack error: boom" in res.output


def test_pack_cli_raises_fileexists(monkeypatch, tmp_path, runner):
    src = tmp_path / "file.txt"
    src.write_text("x")
    monkeypatch.setattr(cli_mod, "_pack_bytes", lambda *a, **k: (_ for _ in ()).throw(FileExistsError("fail")))
    res = runner.invoke(cli_mod.cli, ["pack", str(src), "-p", "pwd"])
    assert res.exit_code == 1
    assert "already exists" in res.output


def test_unpack_missing_password(tmp_path, runner):
    cont = tmp_path / "f.zil"
    cont.write_bytes(b"file\nx")
    res = runner.invoke(cli_mod.cli, ["unpack", str(cont)])
    assert res.exit_code == 1
    assert "Missing password" in res.output


def test_unpack_dest_exists(tmp_path, runner):
    cont = tmp_path / "f.zil"
    cont.write_bytes(b"file\nx")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    res = runner.invoke(cli_mod.cli, ["unpack", str(cont), "-d", str(out_dir), "-p", "pwd"])
    assert res.exit_code == 1
    assert "Destination path already exists" in res.output


def test_unpack_container_too_small(monkeypatch, tmp_path, runner):
    cont = tmp_path / "f.zil"
    cont.write_bytes(b"bad")
    monkeypatch.setattr(
        cli_mod,
        "_unpack_bytes",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("Container too small")),
    )
    res = runner.invoke(cli_mod.cli, ["unpack", str(cont), "-p", "pwd"])
    assert res.exit_code == 1
    assert "Container too small" in res.output


def test_unpack_internal_error(monkeypatch, tmp_path, runner):
    cont = tmp_path / "f.zil"
    cont.write_bytes(b"file\nx")
    monkeypatch.setattr(cli_mod, "_unpack_bytes", lambda *a, **k: (_ for _ in ()).throw(Exception("bang")))
    res = runner.invoke(cli_mod.cli, ["unpack", str(cont), "-p", "pwd"])
    assert res.exit_code == 1
    assert "Unpack error: bang" in res.output


def test_unpack_success(tmp_path, runner):
    cont = tmp_path / "f.zil"
    cont.write_bytes(b"file\ncontent")
    res = runner.invoke(cli_mod.cli, ["unpack", str(cont), "-p", "pwd"])
    assert res.exit_code == 0
    out = tmp_path / "file"
    assert out.exists()
    assert out.read_bytes() == b"content"


def test_unpack_cleans_existing_file(tmp_path, runner):
    cont = tmp_path / "file.zil"
    cont.write_bytes(b"file\nNEW")
    existing = tmp_path / "file"
    existing.write_bytes(b"OLD")
    res = runner.invoke(cli_mod.cli, ["unpack", str(cont), "-p", "pwd"])
    assert res.exit_code == 0
    assert (tmp_path / "file").read_bytes() == b"NEW"


def test_unpack_other_value_error(monkeypatch, tmp_path, runner):
    cont = tmp_path / "f.zil"
    cont.write_bytes(b"file\nx")
    monkeypatch.setattr(cli_mod, "_unpack_bytes", lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")))
    res = runner.invoke(cli_mod.cli, ["unpack", str(cont), "-p", "pwd"])
    assert res.exit_code == 1
    assert "Unpack error: boom" in res.output


# ────────────────────────────────────────────────────────────────────
def test_unpack_cli_raises_fileexists(monkeypatch, tmp_path, runner):
    """
    Покрывает ветку:
    except FileExistsError:
        _abort("Destination path already exists")
    """
    cont = tmp_path / "f.zil"
    cont.write_bytes(b"name\ncontent")
    # monkey-patch чтобы _unpack_bytes сразу упал с FileExistsError
    monkeypatch.setattr(cli_mod, "_unpack_bytes", lambda *a, **k: (_ for _ in ()).throw(FileExistsError("fail")))
    res = runner.invoke(cli_mod.cli, ["unpack", str(cont), "-p", "pwd"])
    assert res.exit_code == 1
    # убедимся, что ветка _abort("Destination path already exists") сработала
    assert "Destination path already exists" in res.output
