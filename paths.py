from __future__ import annotations

import re
from pathlib import Path


DEFAULT_BUILD = "O3S"
DEFAULT_PROFILE = "plain"
BUILD_PROFILES = ("plain", "min")
DIRECT_V0_TRACK = "direct-v0"
DIRECT_IN_V1_TRACK = "direct-in-v1"
DEFAULT_ANALYSIS_TRACK = DIRECT_V0_TRACK
ANALYSIS_TRACKS = (DIRECT_V0_TRACK, DIRECT_IN_V1_TRACK)


def normalize_build(build: str | None) -> str:
    return (build or DEFAULT_BUILD).upper()


def normalize_profile(profile: str | None) -> str:
    normalized = (profile or DEFAULT_PROFILE).lower()
    if normalized not in BUILD_PROFILES:
        raise ValueError(
            f"unknown build profile: {profile!r}. "
            f"expected one of {', '.join(BUILD_PROFILES)}"
        )
    return normalized


def normalize_track(track: str | None) -> str:
    normalized = (track or DEFAULT_ANALYSIS_TRACK).lower()
    if normalized not in ANALYSIS_TRACKS:
        raise ValueError(
            f"unknown analysis track: {track!r}. "
            f"expected one of {', '.join(ANALYSIS_TRACKS)}"
        )
    return normalized


def strip_known_suffix(value: str, suffixes: tuple[str, ...]) -> str:
    name = Path(value).name
    for suffix in suffixes:
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def split_case_build(
    value: str,
    build: str | None = None,
    *,
    suffixes: tuple[str, ...] = (
        ".fixture.bin",
        ".gt.bin",
        ".fixture.json",
        ".gt.json",
        ".users.json",
        ".bin",
        ".json",
        ".rs",
    ),
) -> tuple[str, str]:
    stem = strip_known_suffix(value, suffixes)

    if build is None and "." in stem:
        maybe_case, maybe_build = stem.rsplit(".", 1)
        if re.fullmatch(r"O\d+[A-Z]*", maybe_build.upper()):
            return maybe_case, maybe_build.upper()

    return stem, normalize_build(build)


def output_stem(case: str, build: str) -> str:
    return f"{case}.{normalize_build(build)}"


def source_rs_for(case: str) -> str:
    return f"src/{case}.rs"


def fixture_binary_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return f"bin/{normalize_profile(profile)}/{output_stem(case, build)}.fixture.bin"


def gt_binary_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return f"gt_bin/{normalize_profile(profile)}/{output_stem(case, build)}.gt.bin"


def build_manifest_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return f"build_info/{normalize_profile(profile)}/{output_stem(case, build)}.json"


def resolve_fixture_binary(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return fixture_binary_for(case, build, profile)


def resolve_gt_binary(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return gt_binary_for(case, build, profile)


def fixture_json_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    track: str = DEFAULT_ANALYSIS_TRACK,
) -> str:
    normalized_track = normalize_track(track)
    profile = normalize_profile(profile)
    stem = output_stem(case, build)
    if normalized_track == DIRECT_V0_TRACK:
        return f"fixtures/{profile}/{stem}.fixture.json"
    return f"fixtures/{normalized_track}/{profile}/{stem}.fixture.json"


def raw_graph_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return (
        f"extractions/{normalize_profile(profile)}/"
        f"{output_stem(case, build)}.raw.json"
    )


def gt_json_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return f"ground_truth/{normalize_profile(profile)}/{output_stem(case, build)}.gt.json"


def users_json_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return f"users/{normalize_profile(profile)}/{output_stem(case, build)}.users.json"


def resolve_fixture_json(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    track: str = DEFAULT_ANALYSIS_TRACK,
) -> str:
    return fixture_json_for(case, build, profile, track)


def resolve_gt_json(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return gt_json_for(case, build, profile)


def resolve_users_json(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return users_json_for(case, build, profile)


def baseline_result_for(profile: str = DEFAULT_PROFILE) -> str:
    return f"results/{normalize_profile(profile)}/v0_baseline.json"
