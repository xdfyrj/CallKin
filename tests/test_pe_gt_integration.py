import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    linked = os.environ.get("CALLKIN_PE_LINKED")
    stripped = os.environ.get("CALLKIN_PE_STRIPPED")
    pdb = os.environ.get("CALLKIN_PE_PDB")
    root_namespace = os.environ.get("CALLKIN_PE_ROOT_NAMESPACE")
    if not all((linked, stripped, pdb, root_namespace)):
        print(
            "test_pe_gt_integration: SKIP "
            "(set CALLKIN_PE_LINKED, CALLKIN_PE_STRIPPED, "
            "CALLKIN_PE_PDB, CALLKIN_PE_ROOT_NAMESPACE)"
        )
        return 0

    with tempfile.TemporaryDirectory(prefix="callkin-pe-gt-") as directory:
        output_dir = Path(directory)
        command = [
            sys.executable,
            str(ROOT / "pe_gt_extractor.py"),
            stripped,
            "--linked-binary",
            linked,
            "--pdb",
            pdb,
            "--case",
            "integration",
            "--candidate-scope",
            "rust-nonstd",
            "--root-namespace",
            root_namespace,
            "--output-dir",
            str(output_dir),
        ]
        subprocess.run(command, cwd=ROOT, check=True)

        functions = json.loads((output_dir / "functions.json").read_text())
        groups = json.loads((output_dir / "gt_groups.json").read_text())
        assert "case" not in functions
        assert "case" not in groups
        assert all("symbol_names" not in item for item in functions["functions"])
        assert all("origin" not in item for item in functions["functions"])
        assert all(len(group["members"]) >= 2 for group in groups["groups"])
    print("test_pe_gt_integration: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
