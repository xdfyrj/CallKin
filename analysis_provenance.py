from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from paths import normalize_candidate_scope, normalize_track

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
ANALYSIS_PROVENANCE_KEYS = {
    "track",
    "candidate_scope",
    "backend",
    "extractor_version",
    "raw_graph_sha256",
    "candidate_selection_sha256",
    "projection_config_sha256",
    "anchor_policy",
    "edge_policy",
    "oracle_level",
}


@dataclass(frozen=True)
class AnalysisProvenance:
    track: str
    candidate_scope: str
    backend: str
    extractor_version: str
    raw_graph_sha256: str
    candidate_selection_sha256: str
    projection_config_sha256: str
    anchor_policy: str
    edge_policy: tuple[str, ...]
    oracle_level: str

    def to_dict(self) -> dict[str, object]:
        return {
            "track": self.track,
            "candidate_scope": self.candidate_scope,
            "backend": self.backend,
            "extractor_version": self.extractor_version,
            "raw_graph_sha256": self.raw_graph_sha256,
            "candidate_selection_sha256": self.candidate_selection_sha256,
            "projection_config_sha256": self.projection_config_sha256,
            "anchor_policy": self.anchor_policy,
            "edge_policy": list(self.edge_policy),
            "oracle_level": self.oracle_level,
        }


def parse_analysis_provenance(value: Any, *, where: str) -> AnalysisProvenance:
    if not isinstance(value, dict) or set(value) != ANALYSIS_PROVENANCE_KEYS:
        raise ValueError(
            f"{where} must contain exactly {sorted(ANALYSIS_PROVENANCE_KEYS)}"
        )

    strings = {}
    for key in (
        "track",
        "candidate_scope",
        "backend",
        "extractor_version",
        "anchor_policy",
        "oracle_level",
    ):
        item = value[key]
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{where}.{key} must be a non-empty string")
        strings[key] = item
    normalize_track(strings["track"])
    normalize_candidate_scope(strings["candidate_scope"])

    hashes = {}
    for key in (
        "raw_graph_sha256",
        "candidate_selection_sha256",
        "projection_config_sha256",
    ):
        digest = value[key]
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise ValueError(f"{where}.{key} must be a SHA-256 digest")
        hashes[key] = digest

    edge_policy = value["edge_policy"]
    if (
        not isinstance(edge_policy, list)
        or not edge_policy
        or any(not isinstance(item, str) or not item for item in edge_policy)
        or len(set(edge_policy)) != len(edge_policy)
    ):
        raise ValueError(
            f"{where}.edge_policy must be a non-empty list of unique strings"
        )

    return AnalysisProvenance(
        **strings,
        **hashes,
        edge_policy=tuple(edge_policy),
    )
