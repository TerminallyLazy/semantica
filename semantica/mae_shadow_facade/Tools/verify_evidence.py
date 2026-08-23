#!/usr/bin/env python3
"""Verify the façade's manifest, dependency lock, SBOM, and provenance record."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

from generate_manifest import ROOT, OUTPUT, render


def main() -> int:
    errors = []
    if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != render():
        errors.append("MANIFEST.sha256 is stale")

    sbom = json.loads((ROOT / "SBOM.cdx.json").read_text(encoding="utf-8"))
    provenance = json.loads((ROOT / "PROVENANCE.lock.json").read_text(encoding="utf-8"))
    lock = (ROOT / "requirements.lock").read_text(encoding="utf-8")
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("components") != []:
        errors.append("SBOM must declare zero third-party runtime components")
    if provenance.get("baseRevision") != "8b9749eb2e3035eb9f504ec561f760d17db4309e":
        errors.append("provenance base revision mismatch")
    if provenance.get("build", {}).get("runtimeDependencies") != []:
        errors.append("provenance must declare zero runtime dependencies")
    if provenance.get("build", {}).get("mutationCommit") != (
        "async-transactional-deadline-fence-required"
    ):
        errors.append("provenance mutation fence declaration mismatch")
    sbom_properties = {
        item.get("name"): item.get("value")
        for item in sbom.get("metadata", {})
        .get("component", {})
        .get("properties", [])
    }
    if sbom_properties.get("mae:production-limiter") != (
        "injected-distributed-account-attempts"
    ):
        errors.append("SBOM production limiter declaration mismatch")
    if "Third-party runtime dependencies: none" not in lock:
        errors.append("dependency lock is not the expected zero-dependency lock")

    runtime_files = [
        path
        for path in ROOT.glob("*.py")
        if path.name not in {"__main__.py"}
    ]
    external_imports = set()
    for path in runtime_files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                external_imports.update(
                    alias.name.split(".", 1)[0]
                    for alias in node.names
                    if alias.name.split(".", 1)[0] not in sys.stdlib_module_names
                )
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                root = node.module.split(".", 1)[0]
                if root not in sys.stdlib_module_names:
                    external_imports.add(root)
    if external_imports:
        errors.append(
            "unlocked third-party runtime imports: " + ", ".join(sorted(external_imports))
        )

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"verified {len(list(ROOT.rglob('*.py')))} Python files; "
        "zero third-party runtime dependencies"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
