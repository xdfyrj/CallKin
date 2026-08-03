from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from paths import normalize_profile
from provenance import BuildProvenance, parse_provenance


SUPPORTED_SELECTION_SCHEMAS = {4, 5}


@dataclass(frozen=True)
class CandidateSelection:
    addresses: frozenset[int]
    function_bounds: dict[int, int]
    provenance: BuildProvenance
    sha256: str
    data: dict[str, Any]


def load_candidate_selection(
    path: str,
    *,
    expected_case: str,
    expected_build: str,
    expected_profile: str,
) -> CandidateSelection:
    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)
    return parse_candidate_selection(
        data,
        expected_case=expected_case,
        expected_build=expected_build,
        expected_profile=expected_profile,
    )


def parse_candidate_selection(
    data: Any,
    *,
    expected_case: str,
    expected_build: str,
    expected_profile: str,
) -> CandidateSelection:
    if not isinstance(data, dict):
        raise ValueError("candidate selection must be a JSON object")
    required = {
        "case", "build", "profile", "schema_version", "provenance",
        "source", "addresses", "function_bounds",
    }
    namespace_keys = set(data) & {"prefix", "namespaces"}
    if set(data) - {"prefix", "namespaces"} != required or len(namespace_keys) != 1:
        raise ValueError(
            "candidate selection must contain the common fields plus exactly "
            "one of prefix/namespaces"
        )
    if data["schema_version"] not in SUPPORTED_SELECTION_SCHEMAS:
        raise ValueError(
            "unsupported candidate selection schema_version: "
            f"{data['schema_version']!r}"
        )
    for key, expected in (
        ("case", expected_case),
        ("build", expected_build),
        ("profile", expected_profile),
    ):
        if data[key] != expected:
            raise ValueError(
                f"candidate selection {key} mismatch: expected {expected!r}, "
                f"got {data[key]!r}"
            )
    normalize_profile(data["profile"])
    if not isinstance(data["source"], str) or not data["source"]:
        raise ValueError("candidate selection source must be a non-empty string")
    if "prefix" in data:
        if not isinstance(data["prefix"], str) or not data["prefix"]:
            raise ValueError("candidate selection prefix must be a non-empty string")
    else:
        namespaces = data["namespaces"]
        if (
            not isinstance(namespaces, list)
            or not namespaces
            or any(not isinstance(item, str) or not item for item in namespaces)
        ):
            raise ValueError(
                "candidate selection namespaces must be non-empty strings"
            )

    addresses = _address_set(data["addresses"])
    function_bounds = _function_bounds(data["function_bounds"])
    missing_bounds = addresses - set(function_bounds)
    if missing_bounds:
        missing = ", ".join(f"0x{addr:x}" for addr in sorted(missing_bounds))
        raise ValueError(f"candidate address(es) have no symbol extent: {missing}")

    return CandidateSelection(
        addresses=frozenset(addresses),
        function_bounds=function_bounds,
        provenance=parse_provenance(
            data["provenance"], where="candidate selection.provenance"
        ),
        sha256=candidate_selection_sha256(data),
        data=data,
    )


def candidate_selection_sha256(data: dict[str, Any]) -> str:
    encoded = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _address_set(values: Any) -> set[int]:
    if not isinstance(values, list):
        raise ValueError("candidate selection addresses must be a list")
    addresses = {_address(value, "candidate address") for value in values}
    if len(addresses) != len(values):
        raise ValueError("candidate selection contains duplicate addresses")
    if not addresses:
        raise ValueError("candidate selection must not be empty")
    return addresses


def _function_bounds(values: Any) -> dict[int, int]:
    if not isinstance(values, list):
        raise ValueError("candidate selection function_bounds must be a list")
    bounds: dict[int, int] = {}
    for index, item in enumerate(values):
        where = f"candidate selection function_bounds[{index}]"
        if not isinstance(item, dict) or set(item) != {"address", "size"}:
            raise ValueError(f"{where} must contain exactly address/size")
        address = _address(item["address"], f"{where}.address")
        size = item["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise ValueError(f"{where}.size must be a positive integer")
        if address in bounds:
            raise ValueError(f"duplicate function bound address: 0x{address:x}")
        bounds[address] = size
    return dict(sorted(bounds.items()))


def _address(value: Any, where: str) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ValueError(f"invalid {where}: {value!r}") from exc
    raise ValueError(f"invalid {where}: {value!r}")
