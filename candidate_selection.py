from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from paths import (
    DEFAULT_CANDIDATE_SCOPE,
    RUST_NONSTD_CANDIDATE_SCOPE,
    SUBJECT_CANDIDATE_SCOPE,
    normalize_candidate_scope,
    normalize_profile,
)
from provenance import BuildProvenance, parse_provenance


SUPPORTED_SELECTION_SCHEMAS = {4, 5, 6}


@dataclass(frozen=True)
class CandidateSelection:
    scope: str
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
    schema_version = data.get("schema_version")
    if schema_version not in SUPPORTED_SELECTION_SCHEMAS:
        raise ValueError(
            "unsupported candidate selection schema_version: "
            f"{data['schema_version']!r}"
        )
    if schema_version == 6:
        policy_keys = {"scope", "root_namespace", "namespaces", "excluded_namespaces"}
        if set(data) != required | policy_keys:
            raise ValueError(
                "schema v6 candidate selection has an invalid field set"
            )
        scope = normalize_candidate_scope(data["scope"])
        _string(data["root_namespace"], "candidate selection root_namespace")
        namespaces = _string_list(
            data["namespaces"],
            "candidate selection namespaces",
            allow_empty=scope == RUST_NONSTD_CANDIDATE_SCOPE,
        )
        excluded = _string_list(
            data["excluded_namespaces"],
            "candidate selection excluded_namespaces",
            allow_empty=scope != RUST_NONSTD_CANDIDATE_SCOPE,
        )
        if scope == RUST_NONSTD_CANDIDATE_SCOPE and set(excluded) != {
            "core", "alloc", "std"
        }:
            raise ValueError(
                "rust-nonstd selection must exclude exactly core/alloc/std"
            )
    else:
        namespace_keys = set(data) & {"prefix", "namespaces"}
        if (
            set(data) - {"prefix", "namespaces"} != required
            or len(namespace_keys) != 1
        ):
            raise ValueError(
                "legacy candidate selection must contain the common fields plus "
                "exactly one of prefix/namespaces"
            )
        # Schemas 4/5 predate candidate scopes and always mean the original
        # subject-owned selection, regardless of the current CLI default.
        scope = SUBJECT_CANDIDATE_SCOPE
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
    if schema_version != 6:
        if "prefix" in data:
            if not isinstance(data["prefix"], str) or not data["prefix"]:
                raise ValueError(
                    "candidate selection prefix must be a non-empty string"
                )
        else:
            _string_list(
                data["namespaces"],
                "candidate selection namespaces",
                allow_empty=False,
            )

    addresses = _address_set(data["addresses"])
    function_bounds = _function_bounds(data["function_bounds"])
    missing_bounds = addresses - set(function_bounds)
    if missing_bounds:
        missing = ", ".join(f"0x{addr:x}" for addr in sorted(missing_bounds))
        raise ValueError(f"candidate address(es) have no symbol extent: {missing}")

    return CandidateSelection(
        scope=scope,
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


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where} must be a non-empty string")
    return value


def _string_list(values: Any, where: str, *, allow_empty: bool) -> list[str]:
    if (
        not isinstance(values, list)
        or (not values and not allow_empty)
        or any(not isinstance(item, str) or not item for item in values)
        or len(set(values)) != len(values)
    ):
        qualifier = "a list of unique strings"
        if not allow_empty:
            qualifier = "a non-empty " + qualifier
        raise ValueError(f"{where} must be {qualifier}")
    return values
