import glob
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PQ_DIR = ROOT / "third_party" / "pqclean"
OUT = ROOT / "dist"
OUT.mkdir(exist_ok=True)

for setup_py in glob.glob(str(PQ_DIR / "**" / "setup.py"), recursive=True):
    pkg_dir = Path(setup_py).parent
    subprocess.run(
        [
            "python",
            "setup.py",
            "bdist_wheel",
            "--plat-name",
            "manylinux_x86_64",
            "--dist-dir",
            str(OUT),
        ],
        cwd=pkg_dir,
        check=True,
    )
