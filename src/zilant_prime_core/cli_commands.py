# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
from __future__ import annotations

import base64
import click
import hashlib
import json
import os
import sys
import yaml  # type: ignore
from pathlib import Path
from typing import Final

from key_lifecycle import recover_secret, shard_secret
from zilant_prime_core.crypto.kdf import derive_key_dynamic
from zilant_prime_core.crypto.password_hash import hash_password, verify_password
from zilant_prime_core.metrics import metrics

__all__: Final = [
    "derive_key_cmd",
    "pw_hash_cmd",
    "pw_verify_cmd",
    "pq_genkeypair_cmd",
    "shard_cmd",
    "stream_cmd",
    "hpke_cmd",
]


def _emit(ctx: click.Context, data: dict[str, str | list[str]], fmt: str | None = None) -> None:
    """Print ``data`` using optional or global format."""
    fmt = fmt or (ctx.obj.get("output") if ctx.obj else "text")
    if fmt == "json":
        click.echo(json.dumps(data, indent=2))
    elif fmt == "yaml":
        click.echo(yaml.safe_dump(data))
    else:
        if isinstance(data, dict):
            click.echo(next(iter(data.values())))


# ─────────────────── derive‑key ───────────────────
@click.command("derive-key")
@click.option("--mem", "mem_cost", type=int, default=512 * 1024, show_default=True)
@click.option("--time", "time_cost", type=int, default=4, show_default=True)
@click.argument("password")
@click.argument("salt", type=click.Path(exists=True, dir_okay=False, path_type=str))
def derive_key_cmd(mem_cost: int, time_cost: int, password: str, salt: str) -> None:
    """Generate a 32‑byte Argon2id key and print it as Base64."""
    key = derive_key_dynamic(
        password=password.encode(),
        salt=Path(salt).read_bytes(),
        profile=0.5,
        key_length=32,
        time_max=time_cost,
        mem_min=mem_cost,
        mem_max=mem_cost,
    )
    click.echo(base64.b64encode(key).decode())


# ─────────────────── pw‑hash ───────────────────
@click.command("pw-hash")
@click.argument("password")
def pw_hash_cmd(password: str) -> None:  # pragma: no cover
    """Print Argon2id hash of *password*."""
    click.echo(hash_password(password))  # pragma: no cover


# ─────────────────── pw‑verify ───────────────────
@click.command("pw-verify")
@click.argument("password")
@click.argument("hash")
def pw_verify_cmd(password: str, hash: str) -> None:  # pragma: no cover
    """Exit 0 if *password* matches *hash*, else exit 1."""
    ok = verify_password(hash, password)  # pragma: no cover
    click.echo("ok" if ok else "fail", err=not ok)  # pragma: no cover
    if not ok:  # pragma: no cover
        sys.exit(1)  # pragma: no cover


# ─────────────────── pq-genkeypair (stub) ───────────────────
@click.command("pq-genkeypair")
@click.argument("kem", type=click.Choice(["kyber768", "dilithium2"], case_sensitive=False))
def pq_genkeypair_cmd(kem: str) -> None:  # pragma: no cover
    """Temporary stub that writes dummy PQ keypair files."""
    pk_path = Path(f"{kem.lower()}_pk.bin")
    sk_path = Path(f"{kem.lower()}_sk.bin")
    pk_path.write_bytes(b"p")  # pragma: no cover
    sk_path.write_bytes(b"s")  # pragma: no cover
    click.echo(f"Generated PQ keypair: {pk_path}, {sk_path}")  # pragma: no cover


# ────────────────────────── key shard ──────────────────────────
@click.group("shard")
def shard_cmd() -> None:
    """Split and recover master keys."""


@shard_cmd.command("export")
@click.option("--master-key", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--threshold", type=int, required=True, metavar="N", help="Minimum shares needed to recover")
@click.option("--shares", type=int, required=True, metavar="M", help="Total number of shares")
@click.option("--output-dir", type=click.Path(file_okay=False, path_type=Path), required=True)
@click.pass_context
@metrics.record_cli("shard_export")
def shard_export_cmd(
    ctx: click.Context,
    master_key: Path | None,
    threshold: int,
    shares: int,
    output_dir: Path,
) -> None:
    """Write HEX shares as OUTPUT-DIR/share#.hex and meta.json."""
    if shares < threshold or threshold < 2:
        raise click.UsageError("shares must be >= threshold >= 2")
    secret = Path(master_key).read_bytes() if master_key else sys.stdin.buffer.read()
    pieces = shard_secret(secret, shares, threshold)
    output_dir.mkdir(parents=True, exist_ok=True)
    share_paths: list[str] = []
    for i, sh in enumerate(pieces, 1):
        path = output_dir / f"share{i}.hex"
        path.write_text(sh.hex())
        share_paths.append(str(path))
    meta = {
        "threshold": threshold,
        "shares": shares,
        "checksum": hashlib.sha256(secret).hexdigest(),
    }
    meta_path = output_dir / "meta.json"
    meta_path.write_text(json.dumps(meta))
    _emit(ctx, {"shares": share_paths, "meta": str(meta_path)})


@shard_cmd.command("import")
@click.option("--input-dir", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
@click.option("--output-file", type=click.Path(dir_okay=False, path_type=Path), required=True)
@click.pass_context
@metrics.record_cli("shard_import")
def shard_import_cmd(ctx: click.Context, input_dir: Path, output_file: Path) -> None:
    """Recover secret from INPUT-DIR and write to OUTPUT-FILE."""
    meta_path = input_dir / "meta.json"
    if not meta_path.exists():
        raise click.UsageError("meta.json missing in input directory")
    meta = json.loads(meta_path.read_text())
    threshold = int(meta.get("threshold", 0))
    share_paths = sorted(input_dir.glob("share*.hex"))
    if len(share_paths) < threshold:
        raise click.UsageError("not enough share files")
    shards = []
    for path in share_paths:
        try:
            data = bytes.fromhex(path.read_text().strip())
        except Exception as exc:
            raise click.UsageError(f"malformed share file: {path}") from exc
        if len(data) < 17:
            raise click.UsageError(f"malformed share file: {path}")
        shards.append(data)
    secret = recover_secret(shards[:threshold])
    if hashlib.sha256(secret).hexdigest() != meta.get("checksum"):
        raise click.ClickException("checksum mismatch")
    output_file.write_bytes(secret)
    _emit(ctx, {"path": str(output_file)})


# ────────────────────────── stream ──────────────────────────
@click.group("stream")
def stream_cmd() -> None:
    """Stream-based container operations."""


@stream_cmd.command("pack")
@click.argument("src", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("dst", type=click.Path(dir_okay=False, path_type=Path))
@click.option("--key", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--threads", type=int, default=0, show_default=True)
@click.option("--progress/--no-progress", default=False, show_default=True)
@click.pass_context
@metrics.record_cli("stream_pack")
def stream_pack_cmd(ctx: click.Context, src: Path, dst: Path, key: Path, threads: int, progress: bool) -> None:
    """Pack SRC into DST using streaming AEAD."""
    from streaming_aead import pack_stream

    pack_stream(src, dst, key.read_bytes(), threads=threads, progress=progress)
    _emit(ctx, {"path": str(dst)})


@stream_cmd.command("unpack")
@click.argument("src", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out-dir", type=click.Path(file_okay=False, path_type=Path), default=".")
@click.option("--key", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--threads", type=int, default=0, show_default=True)
@click.option("--progress/--no-progress", default=False, show_default=True)
@click.option("--verify-only", is_flag=True, default=False)
@click.option("--offset", type=int, default=0, show_default=True, help="Skip first OFFSET bytes of ciphertext")
@click.pass_context
@metrics.record_cli("stream_unpack")
def stream_unpack_cmd(
    ctx: click.Context,
    src: Path,
    out_dir: Path,
    key: Path,
    threads: int,
    progress: bool,
    verify_only: bool,
    offset: int,
) -> None:
    """Unpack SRC into OUT-DIR.

    ``offset`` allows resuming from the given ciphertext byte offset.
    """
    from streaming_aead import unpack_stream

    out = out_dir / Path(src).stem
    unpack_stream(
        src,
        out,
        key.read_bytes(),
        verify_only=verify_only,
        progress=progress,
        offset=offset,
    )
    if not verify_only:
        _emit(ctx, {"path": str(out)})


@stream_cmd.command("verify")
@click.argument("src", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--key", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.pass_context
@metrics.record_cli("stream_verify")
def stream_verify_cmd(ctx: click.Context, src: Path, key: Path) -> None:
    """Verify stream container integrity and exit."""
    from streaming_aead import unpack_stream

    try:
        unpack_stream(src, Path(os.devnull), key.read_bytes(), verify_only=True)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
    _emit(ctx, {"status": "verified"})


# ────────────────────────── hpke ──────────────────────────
@click.group("hpke")
def hpke_cmd() -> None:
    """Hybrid public key encryption operations."""


@hpke_cmd.command("encrypt")
@click.argument("src", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("dst", type=click.Path(dir_okay=False, path_type=Path))
@click.option("--pq-pub", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--x-pub", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.pass_context
@metrics.record_cli("hpke_encrypt")
def hpke_encrypt_cmd(
    ctx: click.Context,
    src: Path,
    dst: Path,
    pq_pub: Path,
    x_pub: Path,
) -> None:
    """Encrypt SRC for recipient public keys and write DST."""
    import pqcrypto as pq

    plaintext = src.read_bytes()
    hdr, ct = pq.hybrid_encrypt((pq_pub.read_bytes(), x_pub.read_bytes()), plaintext)
    dst.write_bytes(len(hdr).to_bytes(2, "big") + hdr + ct)
    _emit(ctx, {"path": str(dst)})


@hpke_cmd.command("decrypt")
@click.argument("src", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("dst", type=click.Path(dir_okay=False, path_type=Path))
@click.option("--pq-sk", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--x-sk", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.pass_context
@metrics.record_cli("hpke_decrypt")
def hpke_decrypt_cmd(
    ctx: click.Context,
    src: Path,
    dst: Path,
    pq_sk: Path,
    x_sk: Path,
) -> None:
    """Decrypt SRC using private keys and write DST."""
    import pqcrypto as pq

    blob = src.read_bytes()
    hdr_len = int.from_bytes(blob[:2], "big")
    hdr = blob[2 : 2 + hdr_len]
    ct = blob[2 + hdr_len :]
    plain = pq.hybrid_decrypt((pq_sk.read_bytes(), x_sk.read_bytes()), hdr, ct)
    dst.write_bytes(plain)
    _emit(ctx, {"path": str(dst)})
