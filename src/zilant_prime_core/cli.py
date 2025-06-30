# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Zilant Prime Core contributors
from __future__ import annotations

import binascii
import click
import json
import os
import sys
import time
import yaml  # type: ignore
from pathlib import Path
from typing import Any, NoReturn, cast

from container import pack_file, unpack_file
from crypto_core import hash_sha3
from zilant_prime_core.crypto.password_hash import hash_password, verify_password
from zilant_prime_core.metrics import metrics
from zilant_prime_core.utils import VaultClient
from zilant_prime_core.utils.anti_snapshot import detect_snapshot
from zilant_prime_core.utils.counter import increment_counter, read_counter


def add_complete_flag() -> None:
    """Attach ``--install-completion`` option that prints the shell script."""

    def _callback(ctx: click.Context, param: click.Parameter, value: bool) -> None:
        if not value or ctx.resilient_parsing:
            return
        import subprocess

        shell = os.environ.get("SHELL", "bash").split("/")[-1]
        env = os.environ.copy()
        cmd_name = ctx.info_name or "zilant"
        env[f"{cmd_name.upper()}_COMPLETE"] = f"{shell}_source"
        out = subprocess.run([cmd_name], env=env, capture_output=True, text=True)
        click.echo(out.stdout)
        ctx.exit()

    cli.params.append(
        click.Option(
            ["--install-completion"],
            is_flag=True,
            expose_value=False,
            is_eager=True,
            help="Output shell completion script and exit",
            callback=_callback,
        )
    )


from zilant_prime_core.utils.device_fp import SALT_CONST, collect_hw_factors, compute_fp
from zilant_prime_core.utils.pq_crypto import Dilithium2Signature, Kyber768KEM
from zilant_prime_core.utils.recovery import DESTRUCTION_KEY_BUFFER, self_destruct
from zilant_prime_core.utils.screen_guard import ScreenGuardError, guard
from zilant_prime_core.zilfs import diff_snapshots, mount_fs, snapshot_container, umount_fs


# ────────────────────────── helpers ──────────────────────────
def _abort(msg: str, code: int = 1) -> NoReturn:  # ← NoReturn → mypy happy
    click.echo(msg)
    click.echo("Aborted")
    sys.exit(code)


def _emit(ctx: click.Context, data: dict[str, Any], fmt: str | None = None) -> None:
    """Print ``data`` using given or global format."""
    fmt = fmt or (ctx.obj.get("output") if ctx.obj else "text")
    if fmt == "json":
        click.echo(json.dumps(data, indent=2))
    elif fmt == "yaml":
        click.echo(yaml.safe_dump(data))
    else:
        click.echo(next(iter(data.values())))


def _ask_pwd(*, confirm: bool = False) -> str:
    pwd = cast(str, click.prompt("Password", hide_input=True, confirmation_prompt=confirm))
    if not pwd:
        _abort("Missing password")
    return pwd


def _pack_bytes(src: Path, pwd: str, dest: Path, overwrite: bool) -> bytes:
    if dest.exists() and not overwrite:
        raise FileExistsError(f"{dest} already exists")
    return src.name.encode() + b"\n" + src.read_bytes()


def _unpack_bytes(cont: Path, dest_dir: Path, pwd: str) -> Path:
    blob = cont.read_bytes()
    try:
        name_raw, payload = blob.split(b"\n", 1)
    except ValueError:
        raise ValueError("Container too small")
    fname = name_raw.decode()
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / fname
    if out.exists():
        raise FileExistsError(f"{out} already exists")
    out.write_bytes(payload)
    return out


def _cleanup_old_file(container: Path) -> None:
    try:
        raw = container.read_bytes()
        name_raw, _ = raw.split(b"\n", 1)
        old_file = container.parent / name_raw.decode()
        if old_file.exists():
            old_file.unlink()
    except Exception:
        pass


# ──────────────────────────────── CLI root ────────────────────────────────
@click.group(context_settings={"help_option_names": ["-h", "--help"]}, invoke_without_command=True)
@click.option("--metrics-port", type=int, metavar="PORT", help="Expose metrics on PORT")
@click.option("--vault-key", type=binascii.unhexlify, metavar="HEX", help="AES key for Vault")
@click.option(
    "--output",
    type=click.Choice(["text", "json", "yaml"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format",
)
@click.option("--decoy-sweep", is_flag=True, help="Remove expired decoys and exit")
@click.option("--paranoid", is_flag=True, help="Report decoy cleanup count")
@click.pass_context
def cli(
    ctx: click.Context,
    metrics_port: int | None,
    vault_key: bytes | None,
    output: str,
    decoy_sweep: bool,
    paranoid: bool,
) -> None:
    """Zilant Prime command‑line interface.

    Use ``zilant install-completion bash`` to enable shell autocompletion.
    """
    try:
        guard.assert_secure()
    except ScreenGuardError as exc:
        click.echo(f"Security check failed: {exc}", err=True)
        raise SystemExit(90)

    if metrics_port:
        from zilant_prime_core.health import start_server

        start_server(metrics_port)

    from zilant_prime_core.utils.decoy import sweep_expired_decoys

    removed = sweep_expired_decoys(Path.cwd())
    if paranoid and removed:
        click.echo(f"purged {removed} decoy files", err=True)
    if decoy_sweep:
        click.echo(f"removed {removed} expired decoy files")
        ctx.exit()

    ctx.obj = {"vault_key": vault_key, "output": output}


@cli.group()
def key() -> None:
    """Key management commands."""


@key.command("rotate")
@click.option("--days", type=int, required=True, metavar="DAYS", help="Rotation interval in days")
@click.option("--in-key", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--out-key", type=click.Path(dir_okay=False, path_type=Path), required=True)
@click.pass_context
@metrics.record_cli("key_rotate")
def cmd_key_rotate(ctx: click.Context, days: int, in_key: Path, out_key: Path) -> None:
    """Rotate master key and save the result."""
    from key_lifecycle import KeyLifecycle

    new_key = KeyLifecycle.rotate_master_key(in_key.read_bytes(), days)
    out_key.write_bytes(new_key)
    _emit(ctx, {"path": str(out_key)})


# ────────────────────────────── pack ──────────────────────────────
@cli.command("pack")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", metavar="OUT", type=click.Path(dir_okay=False, path_type=Path))
@click.option("-p", "--password", metavar="PWD|-", help='Password or "-" to prompt')
@click.option("--vault-path", metavar="VAULT_PATH", help="Path in HashiCorp Vault")
@click.option("--pq-pub", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--fake-metadata", is_flag=True, help="Include dummy metadata")
@click.option("--decoy", type=int, default=0, metavar="N", help="Generate N decoy files")
@click.option(
    "--decoy-expire",
    type=int,
    metavar="SEC",
    default=0,
    help="Auto remove decoys after SEC seconds",
)
@click.option("--overwrite/--no-overwrite", default=False, show_default=True)
@click.pass_context
@metrics.record_cli("pack")
def cmd_pack(  # noqa: C901  (covered by extensive tests)
    ctx: click.Context,
    source: Path,
    output: Path | None,
    password: str | None,
    vault_path: str | None,
    pq_pub: Path | None,
    fake_metadata: bool,
    decoy: int,
    decoy_expire: int,
    overwrite: bool,
) -> None:
    from zilant_prime_core.metrics import metrics

    dest = output or source.with_suffix(".zil")
    if dest.exists() and not overwrite:
        if not click.confirm(f"{dest.name} already exists — overwrite?", default=False):
            _abort(f"{dest.name} already exists")
        overwrite = True

    # password handling
    if password == "-":
        pwd = _ask_pwd(confirm=True)
    elif password:
        pwd = password
    elif vault_path:
        try:
            vc = VaultClient(key=ctx.obj.get("vault_key") if ctx.obj else None)
            pwd = vc.get_secret(vault_path, key="password")
        except Exception as exc:
            click.echo(f"Vault error: {exc}", err=True)
            click.echo("Requesting password…", err=True)
            pwd = _ask_pwd(confirm=True)
    else:
        _abort("Missing password")

    # pack
    try:
        start = time.perf_counter()
        with metrics.track("pack"):
            extras = (
                {"owner": "anonymous", "timestamp": "1970-01-01T00:00:00Z", "origin": "N/A"} if fake_metadata else None
            )
            if pq_pub or fake_metadata:
                pack_file(
                    source,
                    dest,
                    pwd.encode(),
                    pq_public_key=pq_pub.read_bytes() if pq_pub else None,
                    extra_meta=extras,
                )
                blob: bytes | None = None
            else:
                blob = _pack_bytes(source, pwd, dest, overwrite)
        metrics.encryption_duration_seconds.observe(time.perf_counter() - start)
    except FileExistsError:
        _abort(f"{dest.name} already exists")
    except Exception as exc:  # pragma: no cover
        _abort(f"Pack error: {exc}")

    # write container (non‑PQ branch)
    if blob is not None:
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        try:
            with open(tmp, "wb") as fh:  # noqa: PTH123
                fh.write(blob)
            os.replace(tmp, dest)
            os.chmod(dest, 0o600)
        except Exception as exc:
            click.echo(f"Write error: {exc}", err=True)
            sys.exit(1)

    metrics.files_processed_total.inc()
    _emit(ctx, {"path": str(dest)})
    if decoy > 0:
        from audit_ledger import record_action
        from zilant_prime_core.utils.decoy import generate_decoy_files

        files = generate_decoy_files(dest.parent, decoy, expire_seconds=decoy_expire or None)
        record_action("decoy_created", {"count": decoy, "files": [f.name for f in files]})


# ────────────────────────────── unpack ──────────────────────────────
@cli.command("unpack")
@click.argument("container", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-d", "--dest", metavar="DIR", type=click.Path(file_okay=False, path_type=Path))
@click.option("-p", "--password", metavar="PWD|-", help='Password or "-" to prompt')
@click.option("--pq-sk", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--honeypot-test", is_flag=True, help="Return decoy on failure")
@click.option(
    "--decoy-expire",
    type=int,
    metavar="SEC",
    default=0,
    help="Auto remove decoys after SEC seconds",
)
@click.pass_context
@metrics.record_cli("unpack")
def cmd_unpack(
    ctx: click.Context,
    container: Path,
    dest: Path | None,
    password: str | None,
    pq_sk: Path | None,
    honeypot_test: bool,
    decoy_expire: int,
) -> None:
    from zilant_prime_core.metrics import metrics

    pwd = _ask_pwd() if password == "-" else password or _abort("Missing password")
    out_dir = dest or container.parent
    if dest and out_dir.exists():
        _abort("Destination path already exists")
    if dest is None:
        _cleanup_old_file(container)

    try:
        start = time.perf_counter()
        with metrics.track("unpack"):
            if pq_sk:
                out_path = out_dir / container.stem
                unpack_file(container, out_path, pwd.encode(), pq_private_key=pq_sk.read_bytes())
                out = out_path
            else:
                out = _unpack_bytes(container, out_dir, pwd)
        metrics.encryption_duration_seconds.observe(time.perf_counter() - start)
    except FileExistsError:
        _abort("Destination path already exists")
    except Exception as exc:
        if honeypot_test:
            from audit_ledger import record_decoy_event
            from zilant_prime_core.utils.decoy import generate_decoy_files

            decoy_file = generate_decoy_files(out_dir, 1, expire_seconds=decoy_expire or None)[0]
            record_decoy_event({"honeypot": str(decoy_file)})
            click.echo(str(decoy_file))
            return
        _abort(
            "Container too small"
            if isinstance(exc, ValueError) and "too small" in str(exc).lower()
            else f"Unpack error: {exc}"
        )

    try:
        os.chmod(out, 0o600)
    except Exception:
        pass

    metrics.files_processed_total.inc()
    _emit(ctx, {"path": str(out)})


# ─────────────────────── misc utility commands ───────────────────────
@cli.command("fingerprint")
def cmd_fingerprint() -> None:
    try:
        hw = collect_hw_factors()
        fp = compute_fp(hw, SALT_CONST)
        click.echo(fp.hex())
    except Exception as exc:  # pragma: no cover
        click.echo(f"Error computing fingerprint: {exc}", err=True)
        raise click.Abort()


@cli.command("check_counter")
def cmd_check_counter() -> None:
    click.echo(f"Current counter value: {read_counter()}")


@cli.command("incr_counter")
def cmd_incr_counter() -> None:
    increment_counter()
    click.echo(f"Counter incremented, new value: {read_counter()}")


@cli.command("sbom")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), default="sbom.json")
@click.argument("target", type=click.Path(exists=True, path_type=Path), default=".")
@click.pass_context
def cmd_sbom(ctx: click.Context, output: Path, target: Path) -> None:
    """Generate SBOM for TARGET into OUTPUT."""
    import subprocess

    subprocess.run(["syft", "packages", str(target), "-o", f"cyclonedx-json={output}"], check=True)
    _emit(ctx, {"sbom": str(output)})


@cli.command("check_snapshot")
def cmd_check_snapshot() -> None:
    try:
        if detect_snapshot():
            click.echo("Snapshot/rollback suspected!", err=True)
            raise click.Abort()
        click.echo("No snapshot detected.")
    except Exception as exc:
        click.echo(f"Error checking snapshot: {exc}", err=True)
        raise click.Abort()


@cli.command("self_destruct")
@click.argument("reason")
def cmd_self_destruct_cli(reason: str) -> None:
    self_destruct(reason, DESTRUCTION_KEY_BUFFER)
    click.echo("Self‑destruct completed. Decoy file generated.")


@cli.command("gen_kem_keys")
@click.option("--out-pk", type=click.Path(dir_okay=False, path_type=Path), required=True)
@click.option("--out-sk", type=click.Path(dir_okay=False, path_type=Path), required=True)
def cmd_gen_kem_keys(out_pk: Path, out_sk: Path) -> None:
    pk, sk = Kyber768KEM().generate_keypair()
    out_pk.write_bytes(pk)
    out_sk.write_bytes(sk)
    click.echo("KEM keypair generated.")


@cli.command("gen_sig_keys")
@click.option("--out-pk", type=click.Path(dir_okay=False, path_type=Path), required=True)
@click.option("--out-sk", type=click.Path(dir_okay=False, path_type=Path), required=True)
def cmd_gen_sig_keys(out_pk: Path, out_sk: Path) -> None:
    pk, sk = Dilithium2Signature().generate_keypair()
    out_pk.write_bytes(pk)
    out_sk.write_bytes(sk)
    click.echo("Signature keypair generated.")


@cli.command("mount")
@click.argument("container", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("mountpoint", type=click.Path(file_okay=False, path_type=Path))
@click.option("-p", "--password", metavar="PWD|-", help='Password or "-" to prompt')
@click.option("--decoy-profile", type=str, help="Mount predefined decoy profile")
@click.option("--remote", type=str, help="Remote path user@host:/path/container")
@click.option("--force", is_flag=True, help="Ignore anti-rollback check")
def cmd_mount(
    container: Path,
    mountpoint: Path,
    password: str | None,
    decoy_profile: str | None,
    remote: str | None,
    force: bool,
) -> None:
    """Mount CONTAINER at MOUNTPOINT via FUSE."""
    pwd = _ask_pwd() if password == "-" else password or _ask_pwd()
    try:
        mount_fs(
            container,
            mountpoint,
            pwd,
            decoy_profile=decoy_profile,
            remote=remote,
            force=force,
        )
    except Exception as exc:  # pragma: no cover - runtime errors
        click.echo(f"Mount error: {exc}", err=True)
        raise click.Abort()


@cli.command("umount")
@click.argument("mountpoint", type=click.Path(file_okay=False, path_type=Path))
def cmd_umount_cli(mountpoint: Path) -> None:
    """Unmount previously mounted ZilantFS."""
    try:
        umount_fs(mountpoint)
    except Exception as exc:  # pragma: no cover - runtime errors
        click.echo(f"Umount error: {exc}", err=True)
        raise click.Abort()


@cli.command("bench")
@click.option("--fs", "bench_fs", is_flag=True, help="Benchmark ZilantFS")
def cmd_bench(bench_fs: bool) -> None:
    """Run benchmarks."""
    if bench_fs:
        from zilant_prime_core.bench_zfs import bench_fs as run

        mb_s = run()
        click.echo(f"{mb_s:.2f} MB/s")


@cli.command("snapshot")
@click.argument("container", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--label", required=True, type=str)
@click.password_option("--password", prompt=True, confirmation_prompt=False)
def cmd_snapshot(container: Path, label: str, password: str) -> None:
    """Create snapshot of container."""
    out = snapshot_container(container, password.encode(), label)
    click.echo(str(out))


@cli.command("diff")
@click.argument("snap_a", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("snap_b", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.password_option("--password", prompt=True, confirmation_prompt=False)
def cmd_diff(snap_a: Path, snap_b: Path, password: str) -> None:
    """Show diff between snapshots."""
    diff = diff_snapshots(snap_a, snap_b, password.encode())
    for name, pair in diff.items():
        click.echo(f"{name}: {pair[0]} -> {pair[1]}")


@cli.command("tray")
def cmd_tray() -> None:
    """Launch system tray helper."""
    from zilant_prime_core.tray import run_tray

    run_tray()


# ───────── secure register / login (Argon2id) ─────────
@cli.command("register")
@click.argument("username")
@click.password_option(prompt=True, confirmation_prompt=True)
def cmd_register(username: str, password: str) -> None:
    store = Path(".opaque_store")
    store.mkdir(exist_ok=True)
    (store / f"{username}.pwd").write_text(hash_password(password))
    click.echo("registered")


@cli.command("login")
@click.argument("username")
@click.password_option(prompt=True)
def cmd_login(username: str, password: str) -> None:
    store_file = Path(".opaque_store") / f"{username}.pwd"
    ok = store_file.exists() and verify_password(store_file.read_text(), password)
    if not ok:
        click.echo("login failed", err=True)
        raise click.Abort()
    click.echo("login ok")


@cli.command("update")
def cmd_update() -> None:  # pragma: no cover
    click.echo("No updates available")


@cli.group()
def audit() -> None:
    """Audit log commands."""


@audit.command("verify")
@click.pass_context
def cmd_audit_verify(ctx: click.Context) -> None:
    """Verify the integrity of the audit log."""
    from key_lifecycle import AuditLog

    log = AuditLog()
    ok = log.verify_log()
    if not ok:
        _emit(ctx, {"valid": False})
        if (ctx.obj or {}).get("output") == "text":
            click.echo("Audit log corrupted", err=True)
        raise click.Abort()
    _emit(ctx, {"valid": True})


@cli.group()
def timelock() -> None:
    """Time‑lock encryption helpers."""


@timelock.command("lock")
@click.option("--delay", type=int, required=True, metavar="SECONDS")
@click.option("--in-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--out-file", type=click.Path(dir_okay=False, path_type=Path), required=True)
def cmd_timelock_lock(delay: int, in_file: Path, out_file: Path) -> None:
    """Lock IN_FILE for the given DELAY."""
    from timelock import lock_file

    lock_file(str(in_file), str(out_file), delay)
    click.echo(str(out_file))


@timelock.command("unlock")
@click.option("--in-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.option("--out-file", type=click.Path(dir_okay=False, path_type=Path), required=True)
def cmd_timelock_unlock(in_file: Path, out_file: Path) -> None:
    """Unlock IN_FILE previously locked via :func:`lock`."""
    from timelock import unlock_file

    unlock_file(str(in_file), str(out_file))
    click.echo(str(out_file))


@cli.group()
def ledger() -> None:
    """Audit ledger commands."""


@ledger.command("show")
@click.option("--last", "last_n", type=int, default=10, show_default=True, metavar="N")
def cmd_ledger_show(last_n: int) -> None:
    """Display last N ledger entries."""
    path = Path("audit-ledger.jsonl")
    if not path.exists():
        return
    lines = path.read_text(encoding="utf-8").splitlines()[-last_n:]
    for line in lines:
        click.echo(line)


@cli.group()
def attest() -> None:
    """TPM attestation helpers."""


@attest.command("simulate")
@click.option("--in-file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=True)
@click.pass_context
def cmd_attest_simulate(ctx: click.Context, in_file: Path) -> None:
    """Simulate TPM attestation of IN_FILE."""
    from attestation import simulate_tpm_attestation

    info = simulate_tpm_attestation(in_file.read_bytes())
    _emit(ctx, info, "json")


@cli.group(name="uyi")
def uyi_group() -> None:
    """Utility verification commands."""


@uyi_group.command("verify-integrity")
@click.argument("container", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def cmd_verify_integrity(container: Path) -> None:
    from container import verify_integrity

    ok = verify_integrity(container)
    click.echo("valid" if ok else "invalid")


@uyi_group.command("show-metadata")
@click.argument("container", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def cmd_show_metadata(container: Path) -> None:
    from container import get_metadata

    click.echo(json.dumps(get_metadata(container)))


# ───────────────────────── heal commands ─────────────────────────
@cli.command("heal-scan")
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--auto", is_flag=True, help="Attempt to heal automatically")
@click.option("--recursive", is_flag=True, help="Scan directories recursively")
@click.option("--report", type=click.Choice(["json", "table"]), default="table")
def cmd_heal_scan(path: Path, auto: bool, recursive: bool, report: str) -> None:
    from tabulate import tabulate  # type: ignore

    from container import get_metadata, verify_integrity
    from zilant_prime_core.self_heal import heal_container

    paths: list[Path] = []
    if path.is_dir():
        paths.extend(path.rglob("*.zil") if recursive else path.glob("*.zil"))
    else:
        paths.append(path)

    rows = []
    healed = False
    failed = False
    for p in paths:
        status = "ok" if verify_integrity(p) else "broken"
        if auto and status == "broken":
            seed = cast(bytes, hash_sha3(p.read_bytes()))
            if heal_container(p, b"k" * 32, rng_seed=seed):
                meta = get_metadata(p)
                click.echo(f"new-key saved to {p.name}: {meta.get('recovery_key_hex')}")
                status = "healed"
                healed = True
            else:
                failed = True
        rows.append({"file": p.name, "status": status})

    if report == "json":
        click.echo(json.dumps(rows))
    else:
        click.echo(tabulate([[r["file"], r["status"]] for r in rows], headers=["file", "status"]))

    if failed:
        raise SystemExit(4)
    if healed:
        raise SystemExit(3)


@cli.command("heal-verify")
@click.argument("container", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def cmd_heal_verify(container: Path) -> None:
    from container import get_metadata
    from zilant_prime_core.zkp import verify_intact

    meta = get_metadata(container)
    history = meta.get("heal_history", [])
    if not history:
        click.echo("no history", err=True)
        raise SystemExit(1)
    proof_path = container.with_suffix(container.suffix + ".proof")
    if not proof_path.exists():
        click.echo("proof missing", err=True)
        raise SystemExit(1)
    event_hash = bytes.fromhex(history[-1])
    ok = verify_intact(event_hash, proof_path.read_bytes())
    if ok:
        click.echo("proof ok")
        raise SystemExit(0)
    click.echo("proof invalid", err=True)
    raise SystemExit(2)


@cli.command("install-completion")
@click.argument("shell", type=click.Choice(["bash", "zsh", "fish"]))
@click.pass_context
def install_completion(ctx: click.Context, shell: str) -> None:
    import subprocess

    env = os.environ.copy()
    cmd_name = ctx.info_name or "zilant"
    env[f"{cmd_name.upper()}_COMPLETE"] = f"{shell}_source"
    res = subprocess.run([cmd_name], env=env, capture_output=True, text=True)
    click.echo(res.stdout)


# ───────── external sub‑commands (kdf, pw‑hash, …) ─────────
from zilant_prime_core.cli_commands import (
    derive_key_cmd,
    hpke_cmd,
    pq_genkeypair_cmd,
    pw_hash_cmd,
    pw_verify_cmd,
    shard_cmd,
    stream_cmd,
)

cli.add_command(derive_key_cmd)
cli.add_command(pw_hash_cmd)
cli.add_command(pw_verify_cmd)
cli.add_command(pq_genkeypair_cmd)
key.add_command(shard_cmd)
cli.add_command(stream_cmd)
cli.add_command(hpke_cmd)

add_complete_flag()

main = cli

if __name__ == "__main__":  # pragma: no cover
    cli()
