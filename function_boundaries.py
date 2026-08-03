from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from paths import normalize_profile
from provenance import BuildProvenance, parse_provenance


BOUNDARY_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FunctionBoundaries:
    bounds: dict[int, int]
    provenance: BuildProvenance
    sha256: str


def load_function_boundaries(
    path: str,
    *,
    expected_case: str,
    expected_build: str,
    expected_profile: str,
) -> FunctionBoundaries:
    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)
    return parse_function_boundaries(
        data,
        expected_case=expected_case,
        expected_build=expected_build,
        expected_profile=expected_profile,
    )


def parse_function_boundaries(
    data: Any,
    *,
    expected_case: str,
    expected_build: str,
    expected_profile: str,
) -> FunctionBoundaries:
    required = {
        "case", "build", "profile", "schema_version", "provenance",
        "source", "function_bounds",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError(
            f"function boundaries must contain exactly {sorted(required)}"
        )
    if data["schema_version"] != BOUNDARY_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported function boundary schema: {data['schema_version']!r}"
        )
    for key, expected in (
        ("case", expected_case),
        ("build", expected_build),
        ("profile", expected_profile),
    ):
        if data[key] != expected:
            raise ValueError(
                f"function boundary {key} mismatch: expected {expected!r}, "
                f"got {data[key]!r}"
            )
    normalize_profile(data["profile"])
    if not isinstance(data["source"], str) or not data["source"]:
        raise ValueError("function boundary source must be a non-empty string")

    bounds: dict[int, int] = {}
    values = data["function_bounds"]
    if not isinstance(values, list) or not values:
        raise ValueError("function_bounds must be a non-empty list")
    for index, item in enumerate(values):
        where = f"function_bounds[{index}]"
        if not isinstance(item, dict) or set(item) != {"address", "size"}:
            raise ValueError(f"{where} must contain exactly address/size")
        address = _address(item["address"], f"{where}.address")
        size = item["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError(f"{where}.size must be a positive integer")
        if address in bounds:
            raise ValueError(f"duplicate function boundary: 0x{address:x}")
        bounds[address] = size

    return FunctionBoundaries(
        bounds=dict(sorted(bounds.items())),
        provenance=parse_provenance(
            data["provenance"], where="function boundaries.provenance"
        ),
        sha256=function_boundaries_sha256(data),
    )


def function_boundaries_sha256(data: dict[str, Any]) -> str:
    encoded = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _address(value: Any, where: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ValueError(f"invalid {where}: {value!r}") from exc
    raise ValueError(f"invalid {where}: {value!r}")
