# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors

import base64
import sys
from click.testing import CliRunner
from pathlib import Path
from types import SimpleNamespace

from zilant_prime_core.cli_commands import derive_key_cmd, pq_genkeypair_cmd
from zilant_prime_core.crypto_core import derive_key_argon2id


def test_derive_key_cmd(tmp_path):
    salt = tmp_path / "salt.bin"
    salt_bytes = b"abcdefghABCDEFGH"  # 16 байт для KDF
    salt.write_bytes(salt_bytes)
    runner = CliRunner()
    result = runner.invoke(derive_key_cmd, ["--mem", "8", "--time", "1", "pw", str(salt)])
    assert result.exit_code == 0
    expected = base64.b64encode(derive_key_argon2id(b"pw", salt_bytes, 8, 1)).decode()
    assert result.output.strip() == expected


def test_pq_genkeypair_cmd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    dummy = SimpleNamespace(generate_keypair=lambda: (b"p", b"s"))
    fake = SimpleNamespace(kyber768=dummy, dilithium2=dummy)
    monkeypatch.setitem(sys.modules, "pqclean", fake)
    runner = CliRunner()
    res1 = runner.invoke(pq_genkeypair_cmd, ["kyber768"])
    assert res1.exit_code == 0
    assert Path("kyber768_pk.bin").exists()
    res2 = runner.invoke(pq_genkeypair_cmd, ["dilithium2"])
    assert res2.exit_code == 0
    assert Path("dilithium2_sk.bin").exists()
