from __future__ import annotations

from paths import normalize_profile


BUILD_TARGET = "x86_64-unknown-linux-gnu"
RUSTC_EDITION = "2024"
STRIP_FLAGS = ["--strip-all"]

_COMMON_FLAGS = [
    "-C", "opt-level=3",
    "-C", "debuginfo=0",
    "-C", "debug-assertions=off",
    "-C", "overflow-checks=off",
]

PROFILE_FLAGS: dict[str, list[str]] = {
    "plain": [
        *_COMMON_FLAGS,
        "-C", "codegen-units=16",
        "-C", "lto=false",
        "-C", "panic=unwind",
    ],
    "min": [
        *_COMMON_FLAGS,
        "-C", "codegen-units=1",
        "-C", "lto=true",
        "-C", "panic=abort",
    ],
}

BUILD_FLAGS: dict[str, list[str]] = {
    "O3S": [],
    "O3KS": ["--cfg", "keep"],
}


def compile_flags(profile: str, build: str) -> list[str]:
    profile = normalize_profile(profile)
    build = build.upper()
    if build not in BUILD_FLAGS:
        raise ValueError(
            f"unsupported build for compilation: {build}. "
            f"Supported builds: {sorted(BUILD_FLAGS)}"
        )
    return [*PROFILE_FLAGS[profile], *BUILD_FLAGS[build]]
