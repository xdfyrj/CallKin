from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


_SHA256_RE = re.compile(r"[0-9a-f]{64}")
PROVENANCE_KEYS = {
    "build_id",
    "source_sha256",
    "non_stripped_sha256",
    "stripped_sha256",
}


@dataclass(frozen=True)
class BuildProvenance:
    build_id: str
    source_sha256: str
    non_stripped_sha256: str
    stripped_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "build_id": self.build_id,
            "source_sha256": self.source_sha256,
            "non_stripped_sha256": self.non_stripped_sha256,
            "stripped_sha256": self.stripped_sha256,
        }


def parse_provenance(value: Any, *, where: str) -> BuildProvenance:
    if not isinstance(value, dict) or set(value) != PROVENANCE_KEYS:
        raise ValueError(
            f"{where} must contain exactly {sorted(PROVENANCE_KEYS)}"
        )

    build_id = value["build_id"]
    if not isinstance(build_id, str) or not build_id:
        raise ValueError(f"{where}.build_id must be a non-empty string")

    hashes = {}
    for key in PROVENANCE_KEYS - {"build_id"}:
        digest = value[key]
        if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
            raise ValueError(f"{where}.{key} must be a SHA-256 digest")
        hashes[key] = digest

    return BuildProvenance(build_id=build_id, **hashes)
