import os
import sys
import tempfile
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from build_manifest import (
    BUILD_MANIFEST_SCHEMA_VERSION,
    BUILD_TARGET,
    load_and_verify_manifest,
    sha256_file,
    write_manifest,
)
from compile import (
    BUILD_FLAGS,
    PROFILE_FLAGS,
    RUSTC_EDITION,
    RUSTC_TARGET,
    STRIP_FLAGS,
    compile_flags,
    compile_case,
    derive_fixture_binary,
    rustc_command,
)
from paths import build_manifest_for


# Canonical CallKin compiler profiles.
EXPECTED_PLAIN_FLAGS = (
    "-C opt-level=3 -C debuginfo=0 -C debug-assertions=off "
    "-C overflow-checks=off -C codegen-units=16 -C lto=false -C panic=unwind"
)
EXPECTED_MIN_FLAGS = (
    "-C opt-level=3 -C debuginfo=0 -C debug-assertions=off "
    "-C overflow-checks=off -C codegen-units=1 -C lto=true -C panic=abort"
)


def main() -> int:
    if " ".join(PROFILE_FLAGS["plain"]) != EXPECTED_PLAIN_FLAGS:
        print(
            f"FAIL plain flags: {' '.join(PROFILE_FLAGS['plain'])}"
        )
        return 1

    if " ".join(PROFILE_FLAGS["min"]) != EXPECTED_MIN_FLAGS:
        print(
            f"FAIL min flags: {' '.join(PROFILE_FLAGS['min'])}"
        )
        return 1

    if RUSTC_EDITION != "2024":
        print(f"FAIL edition diverged from rust-loss: {RUSTC_EDITION}")
        return 1

    if RUSTC_TARGET != "x86_64-unknown-linux-gnu":
        print(f"FAIL compilation target is not fixed: {RUSTC_TARGET}")
        return 1

    if STRIP_FLAGS != ["--strip-all"]:
        print(f"FAIL strip flags diverged from rust-loss: {STRIP_FLAGS}")
        return 1

    if BUILD_FLAGS != {"O3S": [], "O3KS": ["--cfg", "keep"]}:
        print(f"FAIL build flags: {BUILD_FLAGS}")
        return 1

    if " ".join(compile_flags("plain", "O3KS")) != EXPECTED_PLAIN_FLAGS + " --cfg keep":
        print("FAIL O3KS did not add --cfg keep to plain")
        return 1
    if " ".join(compile_flags("min", "O3S")) != EXPECTED_MIN_FLAGS:
        print("FAIL O3S changed min profile flags")
        return 1

    try:
        compile_flags("plain", "O0")
    except ValueError as exc:
        if "unsupported build" not in str(exc):
            print(f"FAIL unexpected unsupported-build error: {exc}")
            return 1
    else:
        print("FAIL O0 has no stripped evaluation pair and must be rejected")
        return 1

    command = rustc_command(
        source="src/family_graph_03.rs",
        case="family_graph_03",
        profile="min",
        build="O3KS",
        output="gt_bin/min/family_graph_03.O3KS.gt.bin",
    )
    expected_command = [
        "rustc",
        "src/family_graph_03.rs",
        *compile_flags("min", "O3KS"),
        "--crate-type", "bin",
        "--crate-name", "family_graph_03",
        "--edition", "2024",
        "--target", "x86_64-unknown-linux-gnu",
        "--emit=link",
        "-o", "gt_bin/min/family_graph_03.O3KS.gt.bin",
    ]
    if command != expected_command:
        print(f"FAIL expected rustc command {expected_command}, got {command}")
        return 1

    expected_manifest = Path("build_info") / "min" / "family_graph_03.O3KS.json"
    actual_manifest = Path(build_manifest_for("family_graph_03", "O3KS", "min"))
    if actual_manifest != expected_manifest:
        print("FAIL canonical build manifest path")
        return 1

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        gt_binary = root / "case.gt.bin"
        fixture_binary = root / "case.fixture.bin"
        source = root / "case.rs"
        source.write_text("fn main() {}\n", encoding="utf-8")
        gt_binary.write_bytes(b"symbol-bearing binary")
        gt_binary.chmod(0o755)
        fixture_binary.write_bytes(b"previous fixture")
        manifest_path = root / "case.build.json"
        manifest_path.write_text("previous manifest\n", encoding="utf-8")

        with patch("compile._run_tool", side_effect=RuntimeError("strip failed")):
            try:
                derive_fixture_binary(
                    gt_binary=str(gt_binary),
                    output=str(fixture_binary),
                    strip_tool="strip",
                )
            except RuntimeError:
                pass
            else:
                print("FAIL strip failure was not propagated")
                return 1

        if fixture_binary.read_bytes() != b"previous fixture":
            print("FAIL strip failure replaced the previous fixture")
            return 1

        with patch("compile._run_tool"):
            derive_fixture_binary(
                gt_binary=str(gt_binary),
                output=str(fixture_binary),
                strip_tool="strip",
            )

        if fixture_binary.read_bytes() != b"symbol-bearing binary":
            print("FAIL successful fixture derivation produced wrong contents")
            return 1
        if (
            sys.platform.startswith("linux")
            and fixture_binary.stat().st_mode & 0o777 != 0o755
        ):
            print("FAIL fixture derivation did not preserve executable mode")
            return 1

        fixture_binary.write_bytes(b"previous fixture")

        args = Namespace(
            source=str(source),
            case="case",
            build="O3S",
            profile="plain",
            gt_binary=str(gt_binary),
            fixture_binary=str(fixture_binary),
            manifest=str(manifest_path),
            rustc_tool=sys.executable,
            strip_tool="definitely-missing-strip-for-test",
        )
        try:
            compile_case(args)
        except RuntimeError as exc:
            if "definitely-missing-strip-for-test" not in str(exc):
                print(f"FAIL unexpected missing-tool error: {exc}")
                return 1
        else:
            print("FAIL missing strip tool was not rejected")
            return 1

        if gt_binary.read_bytes() != b"symbol-bearing binary":
            print("FAIL tool preflight modified the GT binary")
            return 1
        if fixture_binary.read_bytes() != b"previous fixture":
            print("FAIL tool preflight modified the fixture binary")
            return 1

        def fake_compile_gt_binary(**kwargs):
            Path(kwargs["output"]).write_bytes(b"new non-stripped binary")
            return ["fake-rustc", "--target", BUILD_TARGET]

        with (
            patch("compile._require_tool"),
            patch("compile.compile_gt_binary", side_effect=fake_compile_gt_binary),
            patch(
                "compile.derive_fixture_binary",
                side_effect=RuntimeError("strip failed"),
            ),
        ):
            try:
                compile_case(args)
            except RuntimeError as exc:
                if "strip failed" not in str(exc):
                    print(f"FAIL unexpected staged strip error: {exc}")
                    return 1
            else:
                print("FAIL staged strip failure was not propagated")
                return 1

        if gt_binary.read_bytes() != b"symbol-bearing binary":
            print("FAIL staged strip failure replaced the GT binary")
            return 1
        if fixture_binary.read_bytes() != b"previous fixture":
            print("FAIL staged strip failure replaced the fixture binary")
            return 1
        if manifest_path.read_text(encoding="utf-8") != "previous manifest\n":
            print("FAIL staged strip failure replaced the manifest")
            return 1

        with (
            patch("compile._require_tool"),
            patch(
                "compile.compile_gt_binary",
                side_effect=RuntimeError("compile failed"),
            ),
        ):
            try:
                compile_case(args)
            except RuntimeError as exc:
                if "compile failed" not in str(exc):
                    print(f"FAIL unexpected staged compile error: {exc}")
                    return 1
            else:
                print("FAIL staged compile failure was not propagated")
                return 1

        if gt_binary.read_bytes() != b"symbol-bearing binary":
            print("FAIL staged compile failure replaced the GT binary")
            return 1
        if fixture_binary.read_bytes() != b"previous fixture":
            print("FAIL staged compile failure replaced the fixture binary")
            return 1
        if manifest_path.read_text(encoding="utf-8") != "previous manifest\n":
            print("FAIL staged compile failure replaced the manifest")
            return 1

        fixture_binary.write_bytes(b"stripped binary")
        build_manifest = {
            "schema_version": BUILD_MANIFEST_SCHEMA_VERSION,
            "build_id": "test-build-id",
            "case": "case",
            "build": "O3S",
            "profile": "plain",
            "target": BUILD_TARGET,
            "edition": "2024",
            "crate_name": "case",
            "source": {
                "path": str(source),
                "sha256": sha256_file(source),
            },
            "compiler": {
                "invoked_path": "/tools/rustc",
                "resolved_path": "/toolchains/rustc",
                "sysroot": "/toolchains/stable",
                "compiler_binary_path": "/toolchains/stable/bin/rustc",
                "verbose_version": "rustc test\nhost: x86_64-unknown-linux-gnu",
                "flags": compile_flags("plain", "O3S"),
                "command": ["rustc", str(source)],
            },
            "strip": {
                "invoked_path": "/tools/strip",
                "resolved_path": "/bin/strip",
                "version": "GNU strip test",
                "flags": ["--strip-all"],
                "command": ["strip", "--strip-all", str(fixture_binary)],
            },
            "artifacts": {
                "non_stripped": {
                    "path": str(gt_binary),
                    "sha256": sha256_file(gt_binary),
                },
                "stripped": {
                    "path": str(fixture_binary),
                    "sha256": sha256_file(fixture_binary),
                    "stripped_from_sha256": sha256_file(gt_binary),
                },
            },
        }
        write_manifest(build_manifest, manifest_path)
        verified = load_and_verify_manifest(
            manifest_path,
            expected_case="case",
            expected_build="O3S",
            expected_profile="plain",
        )
        if verified.build_id != "test-build-id":
            print(f"FAIL unexpected verified build id: {verified.build_id}")
            return 1

        try:
            load_and_verify_manifest(
                manifest_path,
                expected_case="case",
                expected_build="O3S",
                expected_profile="min",
            )
        except ValueError as exc:
            if "profile mismatch" not in str(exc):
                print(f"FAIL unexpected profile mismatch error: {exc}")
                return 1
        else:
            print("FAIL manifest from another profile passed verification")
            return 1

        fixture_binary.write_bytes(b"tampered binary")
        try:
            load_and_verify_manifest(
                manifest_path,
                expected_case="case",
                expected_build="O3S",
                expected_profile="plain",
            )
        except ValueError as exc:
            if "stripped binary hash mismatch" not in str(exc):
                print(f"FAIL unexpected tamper error: {exc}")
                return 1
        else:
            print("FAIL tampered fixture binary passed manifest verification")
            return 1

        fixture_binary.write_bytes(b"stripped binary")
        source.write_text("fn main() { println!(\"changed\"); }\n", encoding="utf-8")
        try:
            load_and_verify_manifest(
                manifest_path,
                expected_case="case",
                expected_build="O3S",
                expected_profile="plain",
            )
        except ValueError as exc:
            if "source hash mismatch" not in str(exc):
                print(f"FAIL unexpected source tamper error: {exc}")
                return 1
        else:
            print("FAIL modified source passed manifest verification")
            return 1

    print("compile target, staging, manifest, and tamper verification PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
