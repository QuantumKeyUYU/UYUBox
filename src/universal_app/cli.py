"""Command line interface for the universal app."""

from __future__ import annotations

import argparse
import os
from getpass import getpass

from . import decrypt_file, encrypt_file


def main() -> None:
    parser = argparse.ArgumentParser(prog="pc-app", description="Universal PC encryption tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_pack = sub.add_parser("pack", help="Encrypt a file")
    p_pack.add_argument("input")
    p_pack.add_argument("output")
    p_pack.add_argument("--max-tries", type=int, default=3)
    p_pack.add_argument("--one-time", action="store_true")

    p_unpack = sub.add_parser("unpack", help="Decrypt a file")
    p_unpack.add_argument("input")
    p_unpack.add_argument("output")

    args = parser.parse_args()
    key = getpass("Enter key: ").encode()

    if args.cmd == "pack":
        encrypt_file(args.input, args.output, key, max_tries=args.max_tries, one_time=args.one_time)
    else:
        decrypt_file(args.input, args.output, key)


if __name__ == "__main__":
    main()
