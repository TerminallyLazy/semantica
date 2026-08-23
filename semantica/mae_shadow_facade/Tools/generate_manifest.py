#!/usr/bin/env python3
"""Regenerate the deterministic source manifest for this isolated facade."""

from __future__ import annotations

import hashlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "MANIFEST.sha256"
EXCLUDED = {OUTPUT, ROOT / "__pycache__"}


def included_files() -> list[Path]:
    result = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts or path == OUTPUT:
            continue
        result.append(path)
    return sorted(result, key=lambda path: path.relative_to(ROOT).as_posix())


def render() -> str:
    lines = []
    for path in included_files():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(ROOT).as_posix()}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    OUTPUT.write_text(render(), encoding="utf-8", newline="\n")
