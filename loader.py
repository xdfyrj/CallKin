import json
from model import Call, Node, Case
from paths import normalize_profile
from provenance import parse_provenance


FIXTURE_SCHEMA_VERSION = 4

REQUIRED_TOP_LEVEL_KEYS = {
    "case", "build", "profile", "schema_version", "provenance", "extraction", "nodes"
}
ALLOWED_TOP_LEVEL_KEYS = REQUIRED_TOP_LEVEL_KEYS | {"note"}

REQUIRED_NODE_KEYS = {"id", "type", "scored", "calls"}
ALLOWED_NODE_KEYS = REQUIRED_NODE_KEYS

REQUIRED_CALL_KEYS = {"target", "count"}
ALLOWED_CALL_KEYS = REQUIRED_CALL_KEYS

ALLOWED_NODE_TYPES = {"user", "anchor"}


def load_case(file_name: str) -> Case:
    with open(file_name, "r", encoding="utf-8") as f:
        data = json.load(f)

    validate_raw_fixture(data)

    return Case(
        case=data["case"],
        build=data["build"],
        schema_version=data["schema_version"],
        nodes=[_parse_node(node) for node in data["nodes"]],
        profile=data["profile"],
        provenance=parse_provenance(data["provenance"], where="fixture.provenance"),
    )


def _parse_node(node: dict) -> Node:
    return Node(
        id=node["id"],
        type=node["type"],
        scored=node["scored"],
        calls=[_parse_call(call) for call in node["calls"]],
    )


def _parse_call(call: dict) -> Call:
    return Call(
        target=call["target"],
        count=call["count"],
    )


def validate_raw_fixture(data) -> None:
    if not isinstance(data, dict):
        raise ValueError("fixture root must be a JSON object")

    _validate_top_level(data)
    _validate_nodes(data["nodes"])


def _validate_top_level(data: dict) -> None:
    _check_keys(
        data,
        required=REQUIRED_TOP_LEVEL_KEYS,
        allowed=ALLOWED_TOP_LEVEL_KEYS,
        where="fixture root",
    )

    _require_nonempty_str(data["case"], "case")
    _require_nonempty_str(data["build"], "build")
    _require_nonempty_str(data["profile"], "profile")
    normalize_profile(data["profile"])
    _require_exact_type(data["schema_version"], int, "schema_version")
    parse_provenance(data["provenance"], where="fixture.provenance")

    if data["schema_version"] != FIXTURE_SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version: {data['schema_version']}")

    if "note" in data and not isinstance(data["note"], str):
        raise ValueError("note must be a string when present")

    _validate_extraction(data["extraction"])

    if not isinstance(data["nodes"], list):
        raise ValueError("nodes must be a list")

    if not data["nodes"]:
        raise ValueError("nodes must not be empty")


def _validate_extraction(extraction) -> None:
    if not isinstance(extraction, dict) or set(extraction) != {
        "boundary_mode", "boundary_mismatches"
    }:
        raise ValueError(
            "extraction must contain exactly boundary_mode/boundary_mismatches"
        )
    if extraction["boundary_mode"] not in {"radare2", "symbol-extent"}:
        raise ValueError("invalid extraction.boundary_mode")
    mismatches = extraction["boundary_mismatches"]
    if not isinstance(mismatches, list):
        raise ValueError("extraction.boundary_mismatches must be a list")
    required = {"id", "address", "symbol_size", "radare2_size"}
    for index, mismatch in enumerate(mismatches):
        if not isinstance(mismatch, dict) or set(mismatch) != required:
            raise ValueError(
                f"boundary_mismatches[{index}] must contain exactly {sorted(required)}"
            )
        _require_nonempty_str(mismatch["id"], f"boundary_mismatches[{index}].id")
        _require_nonempty_str(
            mismatch["address"], f"boundary_mismatches[{index}].address"
        )
        for key in ("symbol_size", "radare2_size"):
            _require_exact_type(
                mismatch[key], int, f"boundary_mismatches[{index}].{key}"
            )
            if mismatch[key] < 0:
                raise ValueError(f"boundary_mismatches[{index}].{key} must be non-negative")


def _validate_nodes(nodes: list) -> None:
    ids = []

    for index, node in enumerate(nodes):
        where = f"nodes[{index}]"

        if not isinstance(node, dict):
            raise ValueError(f"{where} must be an object")

        _check_keys(
            node,
            required=REQUIRED_NODE_KEYS,
            allowed=ALLOWED_NODE_KEYS,
            where=where,
        )

        node_id = node["id"]

        _require_nonempty_str(node_id, f"{where}.id")
        _require_nonempty_str(node["type"], f"{node_id}.type")
        _require_exact_type(node["scored"], bool, f"{node_id}.scored")

        if node["type"] not in ALLOWED_NODE_TYPES:
            raise ValueError(f"invalid node type for {node_id}: {node['type']}")

        if node["type"] == "anchor" and node["scored"]:
            raise ValueError(f"anchor node cannot be scored: {node_id}")

        if node["scored"] and node["type"] != "user":
            raise ValueError(f"scored node must have type='user': {node_id}")

        if not isinstance(node["calls"], list):
            raise ValueError(f"calls must be a list for node {node_id}")

        ids.append(node_id)

    duplicated_ids = _find_duplicates(ids)
    if duplicated_ids:
        raise ValueError(f"duplicate node id(s): {duplicated_ids}")

    id_set = set(ids)

    for node in nodes:
        _validate_calls(node, id_set)

    if not any(node["scored"] for node in nodes):
        raise ValueError("at least one node must have scored=true")


def _validate_calls(node: dict, id_set: set[str]) -> None:
    source = node["id"]
    targets = []

    for index, call in enumerate(node["calls"]):
        where = f"{source}.calls[{index}]"

        if not isinstance(call, dict):
            raise ValueError(f"{where} must be an object")

        _check_keys(
            call,
            required=REQUIRED_CALL_KEYS,
            allowed=ALLOWED_CALL_KEYS,
            where=where,
        )

        target = call["target"]
        count = call["count"]

        _require_nonempty_str(target, f"{where}.target")
        _require_exact_type(count, int, f"{source} -> {target}.count")

        if target not in id_set:
            raise ValueError(f"unknown call target: {source} -> {target}")

        if count <= 0:
            raise ValueError(f"call count must be positive: {source} -> {target}")

        targets.append(target)

    duplicated_targets = _find_duplicates(targets)
    if duplicated_targets:
        raise ValueError(
            f"duplicate call target(s) from {source}: {duplicated_targets}. "
            "Use one edge per target and aggregate count."
        )


def _check_keys(
    obj: dict,
    *,
    required: set[str],
    allowed: set[str],
    where: str,
) -> None:
    keys = set(obj)

    missing = required - keys
    if missing:
        raise ValueError(f"missing field(s) in {where}: {sorted(missing)}")

    unknown = keys - allowed
    if unknown:
        raise ValueError(f"unknown field(s) in {where}: {sorted(unknown)}")


def _require_nonempty_str(value, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _require_exact_type(value, expected_type: type, name: str) -> None:
    if type(value) is not expected_type:
        raise ValueError(f"{name} must be {expected_type.__name__}")


def _find_duplicates(values: list[str]) -> list[str]:
    seen = set()
    duplicates = set()

    for value in values:
        if value in seen:
            duplicates.add(value)
        else:
            seen.add(value)

    return sorted(duplicates)
