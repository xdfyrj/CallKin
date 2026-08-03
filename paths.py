from __future__ import annotations

import re
from pathlib import Path


DEFAULT_BUILD = "O3S"
DEFAULT_PROFILE = "plain"
BUILD_PROFILES = ("plain", "min")
SUBJECT_CANDIDATE_SCOPE = "subject"
RUST_NONSTD_CANDIDATE_SCOPE = "rust-nonstd"
DEFAULT_CANDIDATE_SCOPE = RUST_NONSTD_CANDIDATE_SCOPE
CANDIDATE_SCOPES = (SUBJECT_CANDIDATE_SCOPE, RUST_NONSTD_CANDIDATE_SCOPE)
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


def normalize_candidate_scope(scope: str | None) -> str:
    normalized = (scope or DEFAULT_CANDIDATE_SCOPE).lower()
    if normalized not in CANDIDATE_SCOPES:
        raise ValueError(
            f"unknown candidate scope: {scope!r}. "
            f"expected one of {', '.join(CANDIDATE_SCOPES)}"
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
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    normalized_track = normalize_track(track)
    candidate_scope = normalize_candidate_scope(candidate_scope)
    profile = normalize_profile(profile)
    stem = output_stem(case, build)
    parts = ["fixtures"]
    if normalized_track != DIRECT_V0_TRACK:
        parts.append(normalized_track)
    if candidate_scope != SUBJECT_CANDIDATE_SCOPE:
        parts.append(candidate_scope)
    parts.extend((profile, f"{stem}.fixture.json"))
    return "/".join(parts)


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
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    return _scoped_artifact_path(
        "ground_truth", case, build, profile, candidate_scope, ".gt.json"
    )


def users_json_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    return _scoped_artifact_path(
        "users", case, build, profile, candidate_scope, ".users.json"
    )


def boundaries_json_for(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
) -> str:
    return (
        f"boundaries/{normalize_profile(profile)}/"
        f"{output_stem(case, build)}.boundaries.json"
    )


def resolve_fixture_json(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    track: str = DEFAULT_ANALYSIS_TRACK,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    return fixture_json_for(case, build, profile, track, candidate_scope)


def resolve_gt_json(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    return gt_json_for(case, build, profile, candidate_scope)


def resolve_users_json(
    case: str,
    build: str,
    profile: str = DEFAULT_PROFILE,
    candidate_scope: str = DEFAULT_CANDIDATE_SCOPE,
) -> str:
    return users_json_for(case, build, profile, candidate_scope)


def _scoped_artifact_path(
    root: str,
    case: str,
    build: str,
    profile: str,
    candidate_scope: str,
    suffix: str,
) -> str:
    parts = [root]
    scope = normalize_candidate_scope(candidate_scope)
    if scope != SUBJECT_CANDIDATE_SCOPE:
        parts.append(scope)
    parts.extend((normalize_profile(profile), f"{output_stem(case, build)}{suffix}"))
    return "/".join(parts)


def baseline_result_for(profile: str = DEFAULT_PROFILE) -> str:
    return f"results/{normalize_profile(profile)}/v0_baseline.json"
