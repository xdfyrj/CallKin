import json
from analysis_provenance import parse_analysis_provenance
from model import Abstention, Call, Case, Node, Observability
from paths import normalize_profile
from provenance import parse_provenance


FIXTURE_SCHEMA_V4 = 4
FIXTURE_SCHEMA_V5 = 5
FIXTURE_SCHEMA_V6 = 6
FIXTURE_SCHEMA_VERSION = FIXTURE_SCHEMA_V6
SUPPORTED_FIXTURE_SCHEMAS = {
    FIXTURE_SCHEMA_V4,
    FIXTURE_SCHEMA_V5,
    FIXTURE_SCHEMA_V6,
}

V4_REQUIRED_TOP_LEVEL_KEYS = {
    "case", "build", "profile", "schema_version", "provenance", "extraction", "nodes"
}
V5_REQUIRED_TOP_LEVEL_KEYS = V4_REQUIRED_TOP_LEVEL_KEYS | {"analysis"}
V6_REQUIRED_TOP_LEVEL_KEYS = V5_REQUIRED_TOP_LEVEL_KEYS | {"abstentions"}

V4_REQUIRED_NODE_KEYS = {"id", "type", "scored", "calls"}
V5_REQUIRED_NODE_KEYS = V4_REQUIRED_NODE_KEYS | {
    "anchor_kind", "color_class", "observability"
}

REQUIRED_CALL_KEYS = {"target", "count"}
ALLOWED_CALL_KEYS = REQUIRED_CALL_KEYS

ALLOWED_NODE_TYPES = {"user", "anchor"}
ALLOWED_ANCHOR_KINDS = {"root", "incoming", "outgoing", "both", "context"}
OBSERVABILITY_KEYS = {
    "resolved_out_calls",
    "unresolved_indirect_out_callsites",
    "address_taken_references",
    "resolved_in_callers",
}


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
        analysis=(
            parse_analysis_provenance(data["analysis"], where="fixture.analysis")
            if data["schema_version"] >= FIXTURE_SCHEMA_V5
            else None
        ),
        abstentions=tuple(
            Abstention(id=item["id"], reason=item["reason"])
            for item in data.get("abstentions", [])
        ),
    )


def _parse_node(node: dict) -> Node:
    return Node(
        id=node["id"],
        type=node["type"],
        scored=node["scored"],
        calls=[_parse_call(call) for call in node["calls"]],
        anchor_kind=node.get("anchor_kind"),
        color_class=node.get("color_class"),
        observability=(
            Observability(**node["observability"])
            if "observability" in node
            else None
        ),
    )


def _parse_call(call: dict) -> Call:
    return Call(
        target=call["target"],
        count=call["count"],
    )


def validate_raw_fixture(data) -> None:
    if not isinstance(data, dict):
        raise ValueError("fixture root must be a JSON object")

    schema_version = _validate_top_level(data)
    node_ids = _validate_nodes(data["nodes"], schema_version=schema_version)
    if schema_version == FIXTURE_SCHEMA_V6:
        _validate_abstentions(data["abstentions"], node_ids)


def _validate_top_level(data: dict) -> int:
    _require_exact_type(data.get("schema_version"), int, "schema_version")
    schema_version = data["schema_version"]
    if schema_version not in SUPPORTED_FIXTURE_SCHEMAS:
        raise ValueError(f"unsupported schema_version: {schema_version}")
    required = (
        V6_REQUIRED_TOP_LEVEL_KEYS
        if schema_version == FIXTURE_SCHEMA_V6
        else V5_REQUIRED_TOP_LEVEL_KEYS
        if schema_version == FIXTURE_SCHEMA_V5
        else V4_REQUIRED_TOP_LEVEL_KEYS
    )
    _check_keys(
        data,
        required=required,
        allowed=required | {"note"},
        where="fixture root",
    )

    _require_nonempty_str(data["case"], "case")
    _require_nonempty_str(data["build"], "build")
    _require_nonempty_str(data["profile"], "profile")
    normalize_profile(data["profile"])
    parse_provenance(data["provenance"], where="fixture.provenance")
    if schema_version >= FIXTURE_SCHEMA_V5:
        parse_analysis_provenance(data["analysis"], where="fixture.analysis")

    if "note" in data and not isinstance(data["note"], str):
        raise ValueError("note must be a string when present")

    _validate_extraction(data["extraction"])

    if not isinstance(data["nodes"], list):
        raise ValueError("nodes must be a list")

    if not data["nodes"]:
        raise ValueError("nodes must not be empty")
    return schema_version


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


def _validate_nodes(nodes: list, *, schema_version: int) -> set[str]:
    ids = []
    required_keys = (
        V5_REQUIRED_NODE_KEYS
        if schema_version >= FIXTURE_SCHEMA_V5
        else V4_REQUIRED_NODE_KEYS
    )

    for index, node in enumerate(nodes):
        where = f"nodes[{index}]"

        if not isinstance(node, dict):
            raise ValueError(f"{where} must be an object")

        _check_keys(
            node,
            required=required_keys,
            allowed=required_keys,
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

        if schema_version >= FIXTURE_SCHEMA_V5:
            _validate_v5_node_metadata(node)

        if not isinstance(node["calls"], list):
            raise ValueError(f"calls must be a list for node {node_id}")

        ids.append(node_id)

    duplicated_ids = _find_duplicates(ids)
    if duplicated_ids:
        raise ValueError(f"duplicate node id(s): {duplicated_ids}")

    id_set = set(ids)

    for node in nodes:
        _validate_calls(node, id_set)

    if schema_version < FIXTURE_SCHEMA_V6 and not any(node["scored"] for node in nodes):
        raise ValueError("at least one node must have scored=true")
    return id_set


def _validate_abstentions(abstentions: object, node_ids: set[str]) -> None:
    if not isinstance(abstentions, list):
        raise ValueError("abstentions must be a list")
    abstained_ids = []
    for index, item in enumerate(abstentions):
        where = f"abstentions[{index}]"
        if not isinstance(item, dict) or set(item) != {"id", "status", "reason"}:
            raise ValueError(f"{where} must contain exactly id/status/reason")
        _require_nonempty_str(item["id"], f"{where}.id")
        if item["status"] != "abstain":
            raise ValueError(f"{where}.status must be 'abstain'")
        if item["reason"] != "no_resolved_nonself_in_or_out_edge":
            raise ValueError(f"invalid abstention reason for {item['id']}")
        abstained_ids.append(item["id"])
    duplicated = _find_duplicates(abstained_ids)
    if duplicated:
        raise ValueError(f"duplicate abstention id(s): {duplicated}")
    overlap = set(abstained_ids) & node_ids
    if overlap:
        raise ValueError(f"abstention(s) also emitted as nodes: {sorted(overlap)}")


def _validate_v5_node_metadata(node: dict) -> None:
    node_id = node["id"]
    if node["type"] == "user":
        if node["anchor_kind"] is not None or node["color_class"] is not None:
            raise ValueError(
                f"user node cannot have anchor_kind/color_class: {node_id}"
            )
    else:
        if node["anchor_kind"] not in ALLOWED_ANCHOR_KINDS:
            raise ValueError(f"invalid anchor_kind for {node_id}")
        _require_nonempty_str(node["color_class"], f"{node_id}.color_class")

    observability = node["observability"]
    if not isinstance(observability, dict) or set(observability) != OBSERVABILITY_KEYS:
        raise ValueError(
            f"{node_id}.observability must contain exactly "
            f"{sorted(OBSERVABILITY_KEYS)}"
        )
    for key in OBSERVABILITY_KEYS - {"address_taken_references"}:
        _require_nonnegative_int(observability[key], f"{node_id}.{key}")
    address_taken = observability["address_taken_references"]
    if address_taken is not None:
        _require_nonnegative_int(address_taken, f"{node_id}.address_taken_references")


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


def _require_nonnegative_int(value, name: str) -> None:
    _require_exact_type(value, int, name)
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def _find_duplicates(values: list[str]) -> list[str]:
    seen = set()
    duplicates = set()

    for value in values:
        if value in seen:
            duplicates.add(value)
        else:
            seen.add(value)

    return sorted(duplicates)
