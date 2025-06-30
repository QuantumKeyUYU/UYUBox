import json
from click.testing import CliRunner
from pathlib import Path

from zilant_prime_core.cli import cli

KEY = b"\x01" * 16


def _export(runner: CliRunner, key_file: Path, shares: int, threshold: int, out: Path) -> None:
    args = [
        "key",
        "shard",
        "export",
        "--master-key",
        str(key_file),
        "--shares",
        str(shares),
        "--threshold",
        str(threshold),
        "--output-dir",
        str(out),
    ]
    res = runner.invoke(cli, args)
    assert res.exit_code == 0, res.output


def _import(runner: CliRunner, directory: Path, out_file: Path) -> CliRunner:
    return runner.invoke(
        cli,
        ["key", "shard", "import", "--input-dir", str(directory), "--output-file", str(out_file)],
    )


def test_roundtrip_corrupt_share(tmp_path: Path) -> None:
    runner = CliRunner()
    key_file = tmp_path / "master.bin"
    key_file.write_bytes(KEY)
    out_dir = tmp_path / "shares"
    _export(runner, key_file, 3, 2, out_dir)

    files = sorted(out_dir.glob("share*.hex"))
    assert len(files) == 3
    files[0].write_text("zz")  # corrupt one
    files[0].unlink()  # use remaining valid shares
    result = _import(runner, out_dir, tmp_path / "recovered.bin")
    assert result.exit_code == 0, result.output
    assert (tmp_path / "recovered.bin").read_bytes() == KEY


def test_invalid_threshold(tmp_path: Path) -> None:
    runner = CliRunner()
    key_file = tmp_path / "k"
    key_file.write_bytes(KEY)
    res = runner.invoke(
        cli,
        [
            "key",
            "shard",
            "export",
            "--master-key",
            str(key_file),
            "--shares",
            "3",
            "--threshold",
            "5",
            "--output-dir",
            str(tmp_path / "d"),
        ],
    )
    assert res.exit_code != 0


def test_import_too_few(tmp_path: Path) -> None:
    runner = CliRunner()
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(KEY)
    out_dir = tmp_path / "out"
    _export(runner, key_file, 3, 2, out_dir)
    for f in [out_dir / "share2.hex", out_dir / "share3.hex"]:
        if f.exists():
            f.unlink()
    result = _import(runner, out_dir, tmp_path / "bad.bin")
    assert result.exit_code != 0


def test_import_bad_length(tmp_path: Path) -> None:
    runner = CliRunner()
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(KEY)
    out_dir = tmp_path / "shares"
    _export(runner, key_file, 2, 2, out_dir)
    files = sorted(out_dir.glob("share*.hex"))
    files[1].write_text("00")  # too short
    result = _import(runner, out_dir, tmp_path / "rec.bin")
    assert result.exit_code != 0


def test_import_non_hex(tmp_path: Path) -> None:
    runner = CliRunner()
    key_file = tmp_path / "k.bin"
    key_file.write_bytes(KEY)
    out_dir = tmp_path / "sh"
    _export(runner, key_file, 2, 2, out_dir)
    files = sorted(out_dir.glob("share*.hex"))
    files[0].write_text("zz")  # not hex
    result = _import(runner, out_dir, tmp_path / "r.bin")
    assert result.exit_code != 0


def test_checksum_mismatch(tmp_path: Path) -> None:
    runner = CliRunner()
    key_file = tmp_path / "mk.bin"
    key_file.write_bytes(KEY)
    out_dir = tmp_path / "sss"
    _export(runner, key_file, 2, 2, out_dir)
    meta_path = out_dir / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta["checksum"] = "00"
    meta_path.write_text(json.dumps(meta))
    result = _import(runner, out_dir, tmp_path / "o.bin")
    assert result.exit_code != 0
