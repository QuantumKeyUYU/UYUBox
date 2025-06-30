from pathlib import Path

from zilant_prime_core.zilfs import unpack_dir

if __name__ == "__main__":
    import sys

    src, dst = sys.argv[1], sys.argv[2]
    key = bytes.fromhex(sys.argv[3]) if len(sys.argv) > 3 else b"\0" * 32
    unpack_dir(Path(src), Path(dst), key)
