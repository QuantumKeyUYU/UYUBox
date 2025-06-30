# SPDX-License-Identifier: MIT
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import builtins
import os
from click.testing import CliRunner

from zilant_prime_core.cli import cli


def test_pack_write_error(tmp_path, monkeypatch):
    src = tmp_path / "foo.txt"
    src.write_text("data")

    original_open = builtins.open

    def fake_open(path, mode="r", *args, **kwargs):
        # path может быть Path или str
        p = str(path)
        if p.endswith(".tmp"):
            raise OSError("disk full")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    result = CliRunner().invoke(cli, ["pack", str(src), "-p", "pwd"])
    assert result.exit_code != 0
    assert "Write error: disk full" in result.output
    monkeypatch.setattr(builtins, "open", original_open)


def test_unpack_chmod_exception(tmp_path, monkeypatch):
    container = tmp_path / "bar.zil"
    container.write_bytes(b"hello.bin\nworld")
    runner = CliRunner()

    monkeypatch.setattr(os, "chmod", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("no permission")))
    result = runner.invoke(cli, ["unpack", str(container), "-p", "pwd"])
    out = tmp_path / "hello.bin"
    assert result.exit_code == 0
    assert str(out) in result.output
    assert out.exists()
