# -*- coding: utf-8 -*-
"""demo-manifest build DIR [-o FILE] | demo-manifest verify FILE DIR"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="demo-manifest", description="Манифест файлов обновления ПО")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="построить манифест каталога")
    b.add_argument("root")
    b.add_argument("-o", "--output")
    v = sub.add_parser("verify", help="проверить каталог по манифесту")
    v.add_argument("manifest")
    v.add_argument("root")
    args = ap.parse_args(argv)
    if args.cmd == "build":
        text = manifest.dump(manifest.build(Path(args.root)))
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
        else:
            sys.stdout.write(text)
        return 0
    problems = manifest.verify(manifest.load(Path(args.manifest).read_text(encoding="utf-8")), Path(args.root))
    for p in problems:
        print(p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
