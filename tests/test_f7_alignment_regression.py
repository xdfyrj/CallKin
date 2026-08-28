"""Pin every F4 score so F7.0 cannot move one.

The fixture holds 219 real ripgrep bodies and the 13 numeric fields the
feasibility stage records for its 556 pair sample, captured before
instruction-level alignment existed. Values are compared as `float.hex()`, so
a single least-significant bit of drift fails.
"""

from __future__ import annotations

import gzip
import json
import os
import sys
from pathlib import Path


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from body_similarity import parse_body  # noqa: E402
from tests.fixtures.f7_alignment.make_fixture import score_pair  # noqa: E402


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "f7_alignment"
BODIES_PATH = FIXTURE_DIR / "ripgrep_219_bodies.json.gz"
SCORES_PATH = FIXTURE_DIR / "ripgrep_556_scores.json"

EXPECTED_METRICS = (
    "aligned_block_ratio",
    "aligned_instruction_ratio",
    "call_slot_shape_consistency",
    "constant_slot_consistency",
    "edge_consistency",
    "evidence_slot_consistency",
    "instruction_count_ratio",
    "mnemonic_multiset_jaccard",
    "mnemonic_ngram_jaccard",
    "opaque_cfg_penalty",
    "sequence_ratio",
    "size_ratio",
    "slot_adjusted_aligned_instruction_ratio",
)
EXPECTED_QUALITY = (
    "both_complete",
    "candidate_block_pair_count",
    "matched_block_count",
    "opaque_indirect_jumps",
)


def _load():
    with gzip.open(BODIES_PATH, "rt", encoding="utf-8") as handle:
        bodies_fixture = json.load(handle)
    scores = json.loads(SCORES_PATH.read_text(encoding="utf-8"))
    bodies = {item["id"]: parse_body(item) for item in bodies_fixture["functions"]}
    return bodies, bodies_fixture, scores


def test_fixture_shape_is_what_the_golden_claims():
    bodies, bodies_fixture, scores = _load()
    assert len(bodies) == 219, len(bodies)
    assert len(scores["pairs"]) == 556, len(scores["pairs"])
    assert tuple(scores["metric_names"]) == EXPECTED_METRICS
    assert bodies_fixture["provenance"] == scores["provenance"]
    labels = [entry["label"] for entry in scores["pairs"]]
    assert labels.count("positive") == 460, labels.count("positive")
    assert labels.count("negative") == 96, labels.count("negative")


def test_every_pair_reproduces_its_golden_scores_exactly():
    bodies, _, scores = _load()
    mismatches: list[str] = []

    for entry in scores["pairs"]:
        first_id, second_id = entry["pair"]
        metrics, quality = score_pair(bodies[first_id], bodies[second_id])

        if sorted(metrics) != list(EXPECTED_METRICS):
            raise AssertionError(
                f"metric set changed: {sorted(set(metrics) ^ set(EXPECTED_METRICS))}"
            )
        for name in EXPECTED_METRICS:
            actual = float(metrics[name]).hex()
            expected = entry["metrics"][name]
            if actual != expected:
                mismatches.append(
                    f"{first_id}/{second_id} {name}: {expected} != {actual}"
                )

        if sorted(quality) != list(EXPECTED_QUALITY):
            raise AssertionError(f"quality set changed: {sorted(quality)}")
        for name in EXPECTED_QUALITY:
            if quality[name] != entry["quality"][name]:
                mismatches.append(
                    f"{first_id}/{second_id} quality.{name}: "
                    f"{entry['quality'][name]} != {quality[name]}"
                )

    if mismatches:
        raise AssertionError(
            f"{len(mismatches)} F4 values changed, first 5:\n  "
            + "\n  ".join(mismatches[:5])
        )


def main() -> int:
    test_fixture_shape_is_what_the_golden_claims()
    test_every_pair_reproduces_its_golden_scores_exactly()
    print("F7.0 F4 regression PASS (556 pairs x 13 metrics + 4 quality fields)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
