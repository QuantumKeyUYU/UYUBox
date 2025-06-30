# SPDX-License-Identifier: MIT
from click.testing import CliRunner

from zilant_prime_core.cli import cli

runner = CliRunner()


def make_file(tmp_path, name="f.txt", data=b"data"):
    f = tmp_path / name
    f.write_bytes(data)
    return f


def test_pack_missing_password(tmp_path):
    src = make_file(tmp_path)
    result = runner.invoke(cli, ["pack", str(src)])
    assert result.exit_code == 1
    assert "Missing password" in result.output
    assert "Aborted" in result.output


def test_pack_password_prompt_abort(monkeypatch, tmp_path):
    src = make_file(tmp_path)
    monkeypatch.setattr("click.prompt", lambda *a, **k: "")
    result = runner.invoke(cli, ["pack", str(src), "-p", "-"])
    assert result.exit_code == 1
    assert "Missing password" in result.output
    assert "Aborted" in result.output


def test_pack_file_exists_and_no_overwrite(tmp_path, monkeypatch):
    src = make_file(tmp_path)
    dest = src.with_suffix(".zil")
    dest.write_bytes(b"old")
    monkeypatch.setattr("click.confirm", lambda *a, **k: False)
    result = runner.invoke(cli, ["pack", str(src), "-p", "pw"])
    assert result.exit_code == 1
    assert "already exists" in result.output.lower()
    assert "aborted" in result.output.lower()


def test_pack_file_exists_and_yes_overwrite(tmp_path, monkeypatch):
    src = make_file(tmp_path)
    dest = src.with_suffix(".zil")
    dest.write_bytes(b"old")
    monkeypatch.setattr("click.confirm", lambda *a, **k: True)
    result = runner.invoke(cli, ["pack", str(src), "-p", "pw"])
    assert result.exit_code == 0
    assert dest.read_bytes().startswith(src.name.encode())


def test_pack_internal_error(monkeypatch, tmp_path):
    src = make_file(tmp_path)
    monkeypatch.setattr(
        "zilant_prime_core.cli._pack_bytes",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    result = runner.invoke(cli, ["pack", str(src), "-p", "pw"])
    assert result.exit_code == 1
    assert "Pack error: fail" in result.output


def test_unpack_missing_password(tmp_path):
    cont = tmp_path / "cont.zil"
    cont.write_bytes(b"hdr\npayload")
    result = runner.invoke(cli, ["unpack", str(cont)])
    assert result.exit_code == 1
    assert "Missing password" in result.output
    assert "Aborted" in result.output


def test_unpack_password_prompt_abort(monkeypatch, tmp_path):
    cont = tmp_path / "cont.zil"
    cont.write_bytes(b"hdr\npayload")
    monkeypatch.setattr("click.prompt", lambda *a, **k: "")
    result = runner.invoke(cli, ["unpack", str(cont), "-p", "-"])
    assert result.exit_code == 1
    assert "Missing password" in result.output
    assert "Aborted" in result.output


def test_unpack_dest_exists(tmp_path):
    cont = tmp_path / "c.zil"
    cont.write_bytes(b"hdr\npayload")
    outdir = tmp_path / "out"
    outdir.mkdir()
    result = runner.invoke(cli, ["unpack", str(cont), "-p", "pw", "-d", str(outdir)])
    assert result.exit_code == 1
    assert "already exists" in result.output.lower()


def test_unpack_file_exists_inside(monkeypatch, tmp_path):
    cont = tmp_path / "c.zil"
    outdir = tmp_path / "out"
    outdir.mkdir()
    fname = "collide.txt"
    (outdir / fname).write_text("exists")
    cont.write_bytes(f"{fname}\nxyz".encode())
    result = runner.invoke(cli, ["unpack", str(cont), "-p", "pw", "-d", str(outdir)])
    assert result.exit_code == 1
    assert "already exists" in result.output.lower()


def test_unpack_too_small(tmp_path):
    cont = tmp_path / "bad.zil"
    cont.write_bytes(b"abc")
    result = runner.invoke(cli, ["unpack", str(cont), "-p", "pw"])
    assert result.exit_code == 1
    assert "container too small" in result.output.lower()


def test_unpack_internal_error(monkeypatch, tmp_path):
    cont = tmp_path / "c.zil"
    cont.write_bytes(b"hdr\npayload")
    monkeypatch.setattr(
        "zilant_prime_core.cli._unpack_bytes",
        lambda *a, **k: (_ for _ in ()).throw(Exception("fail")),
    )
    result = runner.invoke(cli, ["unpack", str(cont), "-p", "pw"])
    assert result.exit_code == 1
    assert "Unpack error: fail" in result.output


def test_successful_pack_and_unpack(tmp_path):
    src = make_file(tmp_path, data=b"good")
    result = runner.invoke(cli, ["pack", str(src), "-p", "pw"])
    assert result.exit_code == 0
    out_path = src.with_suffix(".zil")
    assert out_path.exists()
    result = runner.invoke(cli, ["unpack", str(out_path), "-p", "pw"])
    assert result.exit_code == 0
    assert (tmp_path / src.name).read_bytes() == b"good"
