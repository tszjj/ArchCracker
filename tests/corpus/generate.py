#!/usr/bin/env python3
"""Generate W2-008 dictionaries and a hash manifest. No binary is committed.

Usage:
  python tests/corpus/generate.py --out tests/corpus/out --count 1000000
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_lines(path: Path, lines: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("tests/corpus/out"))
    parser.add_argument("--count", type=int, default=1_000_000)
    parser.add_argument("--password", default="P@ssw0rd123")
    args = parser.parse_args()

    out = args.out
    dictionaries = out / "dictionaries"
    dictionaries.mkdir(parents=True, exist_ok=True)

    write_lines(dictionaries / "dict_small.txt", ["wrong-one", "wrong-two", args.password])
    write_lines(dictionaries / "dict_unicode.txt", ["wrong-one", "中文密码"])
    write_lines(dictionaries / "dict_hybrid.txt", ["base"])
    write_lines(
        dictionaries / "dict_hybrid_1k.txt",
        [f"w{index:04d}" for index in range(1_000)],
    )
    write_lines(
        dictionaries / "dict_1m.txt",
        [f"wrong-{index:07d}" for index in range(args.count)] + [args.password],
    )

    manifest: dict[str, object] = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "generator": "tests/corpus/generate.py",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "count": args.count,
        "dictionaries": {},
        "fixtures": {},
    }
    for path in sorted(dictionaries.iterdir()):
        if path.is_file():
            manifest["dictionaries"][path.name] = {
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }

    fixtures = out / "fixtures"
    if fixtures.is_dir():
        for path in sorted(fixtures.rglob("*")):
            if path.is_file():
                manifest["fixtures"][str(path.relative_to(out).as_posix())] = {
                    "bytes": path.stat().st_size,
                    "sha256": sha256(path),
                }

    manifest_path = out / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"manifest: {manifest_path}")
    print(f"1M dictionary: {dictionaries / 'dict_1m.txt'}")


if __name__ == "__main__":
    main()
