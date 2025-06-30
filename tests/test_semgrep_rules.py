import json
import os
import subprocess
from pathlib import Path

RULE_DIR = Path(__file__).resolve().parents[1] / ".semgrep" / "custom"


def _run_semgrep(rule: str, source: str, tmp_path: Path, autofix: bool = False):
    p = tmp_path / "code.py"
    p.write_text(source)
    cmd = [
        "semgrep",
        "--metrics=off",
        "--timeout",
        "1",
        "--config",
        str(RULE_DIR / rule),
        str(p),
        "--json",
    ]
    if autofix:
        cmd.insert(-1, "--autofix")
    env = dict(
        **os.environ,
        SEMGREP_SEND_METRICS="0",
        SEMGREP_CONFIG="",
        SEMGREP_DISABLE_VERSION_CHECK="1",
    )
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return p.read_text(), json.loads(result.stdout or "{}")


def test_insecure_hash(tmp_path):
    src = "import hashlib\nhashlib.md5(b'pwd')\n"
    fixed, out = _run_semgrep("insecure-hash.yml", src, tmp_path, autofix=True)
    assert "sha256" in fixed
    assert out.get("results")


def test_container_same_path(tmp_path):
    src = "from container import pack_file\npack_file(Path('a'), Path('a'), b'x'*32)\n"
    _, out = _run_semgrep("container-same-path.yml", src, tmp_path)
    assert out.get("results")


def test_pq_key_none(tmp_path):
    src = "from aead import PQAEAD\nPQAEAD.encrypt(None, b'd')\n"
    _, out = _run_semgrep("pq-key-none.yml", src, tmp_path)
    assert out.get("results")


def test_vdf_invalid_steps(tmp_path):
    src = "from zilant_prime_core.vdf import generate_posw_sha256\ngenerate_posw_sha256(b'd', 0)\n"
    fixed, out = _run_semgrep("vdf-invalid-steps.yml", src, tmp_path, autofix=True)
    assert "generate_posw_sha256(b'd', 1)" in fixed
    assert out.get("results")


def test_click_prompt_insecure(tmp_path):
    src = "import click\nclick.prompt('Password')\n"
    fixed, out = _run_semgrep("click-prompt-insecure.yml", src, tmp_path, autofix=True)
    assert "hide_input=True" in fixed
    assert out.get("results")
