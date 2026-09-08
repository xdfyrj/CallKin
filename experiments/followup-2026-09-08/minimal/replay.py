#!/usr/bin/env python3.12
"""Replay two k=16 multiview-consensus arms from cached observations."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = HERE / "out"

INITIAL_INPUT_HASHES = {
    "body.json": "3413c522ffe652c3af9874641b588d8bfa44bba73a4dfa830c3fbbdc89feb4f0",
    "fixture.json": "5a98273a266f285a3c193f619c162440c06d713be8a50669e107af764a0ad567",
    "policy.json": "77f394244c67b6633698e80af5265da4544c8ad5033aff7d0474a5ff8f1eebfa",
}
POST_PREDICTION_INPUT_HASHES = {
    "source.rs": "22ef7aa42dc8d5b784bee9d60bf142225253fec9ff044c53ee5bb1ecf44b0221",
    "build.json": "c4b47bf4dfec609fc2cc134a6606604ca011b47c066beabf76ddae59bcf7a025",
    "ground-truth.json": "c8611d94ff28b8eddbc7fb977594944dfc0487a472319d48dd4350dd26b3801e",
    "linkage.json": "f91e8f8d98e224cf19fb48260231653a8599a0a287ddfd5dc9ff65bde1b1f633",
    "LICENSE": "7ce87f09e6213feb0846af3b492b180f51171b43d1bb1c3c0f101795e471998b",
}
ARMS = {
    "body2": ("token", "cfg"),
    "combined3": ("token", "cfg", "relation"),
}
OUTPUT_HASHES = {
    "body2-multiview-union.json": "b557f97f200a9e7ac12d3020015b1ecb3ec1902c1ca3df29bf06840e1a37a203",
    "body2-f5.json": "580342283f9b66fb10248b6878d6ee3f3bea6fca28bc0895c51c8713b3074465",
    "body2-f6.json": "44a00ed256176866405bc68a7f91bb75da63208d7e3c0bfee89a844b06bed684",
    "body2-evaluation.json": "e80ad92084421ee8dc7dc3f92c98858a967acd201bb26e0d9db22918269acbff",
    "combined3-multiview-union.json": "3f8fa0e62e806a0ae1011ccb5774b3d0609f2f42a2c047400dfc543629da4d17",
    "combined3-f5.json": "8e8dec1f232c90a447eacd8641ccfe30445394e95d6ba9a13cb23c9ff6b62983",
    "combined3-f6.json": "3bf8d015e96408f7ae46ccfd8bd4bcb3f447e145ddda44800e5d5f648f5d05d1",
    "combined3-evaluation.json": "b99bfb44edcbb479a5334f5f6125d588125973a476b6121f7b72ab088bafd170",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_json(path: Path, document: dict[str, Any]) -> None:
    path.write_text(encode(document), encoding="utf-8")


def verify_hashes(root: Path, expected: dict[str, str]) -> None:
    for name, wanted in expected.items():
        path = root / name
        actual = sha256(path)
        if actual != wanted:
            raise ValueError(f"SHA-256 mismatch for {path}: {actual} != {wanted}")


def verify_runtime() -> None:
    if platform.system() != "Linux":
        raise ValueError(f"Linux required, found {platform.system()}")
    if sys.version_info[:2] != (3, 12):
        raise ValueError(f"Python 3.12 required, found {platform.python_version()}")


def predict_arm(
    name: str,
    views: tuple[str, ...],
    body_document: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run one GT-free multiview-consensus F5 arm and its F6 consumer."""
    from analysis.v1_consensus_candidates import build_consensus_artifact
    from body_similarity import load_body_evidence
    from v1_candidates import (
        build_multiview_candidate_artifact_from_files,
        validate_candidate_artifact,
        write_candidate_artifact,
    )
    from v1_engine import (
        PairPolicyConfig,
        build_family_artifact,
        write_family_artifact,
    )

    union = build_multiview_candidate_artifact_from_files(
        body_path=HERE / "body.json",
        fixture_path=HERE / "fixture.json",
        top_k=16,
        mode="out-in",
        views=views,
        track="angr",
        candidate_scope="subject",
        anchor_policy="role",
    )
    union_path = OUT / f"{name}-multiview-union.json"
    write_candidate_artifact(union_path, union)

    candidate = build_consensus_artifact(
        union,
        source_sha256=sha256(union_path),
    )
    validate_candidate_artifact(candidate)
    candidate_path = OUT / f"{name}-f5.json"
    write_candidate_artifact(candidate_path, candidate)

    family = build_family_artifact(
        candidate_artifact=candidate,
        bodies=load_body_evidence(body_document),
        config=PairPolicyConfig.from_file(HERE / "policy.json"),
        body_sha256=sha256(HERE / "body.json"),
        body_provenance=body_document.get("provenance"),
        candidate_sha256=sha256(candidate_path),
    )
    write_family_artifact(OUT / f"{name}-f6.json", family)
    return candidate, family


def evaluate_arm(name: str, family: dict[str, Any]) -> dict[str, Any]:
    """Load labels only after both prediction arms have been written."""
    from analysis.v1_pair_eval import evaluate_family_artifact

    family_path = OUT / f"{name}-f6.json"
    truth_path = HERE / "ground-truth.json"
    linkage_path = HERE / "linkage.json"
    evaluation = evaluate_family_artifact(
        family,
        json.loads(truth_path.read_text(encoding="utf-8")),
        json.loads(linkage_path.read_text(encoding="utf-8")),
        family_artifact_sha256=sha256(family_path),
        provenance={
            "family_artifact_sha256": sha256(family_path),
            "ground_truth_sha256": sha256(truth_path),
            "linkage_audit_sha256": sha256(linkage_path),
        },
    )
    write_json(OUT / f"{name}-evaluation.json", evaluation)
    return evaluation


def main() -> int:
    try:
        verify_runtime()
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        verify_hashes(HERE, INITIAL_INPUT_HASHES)
        body_document = json.loads((HERE / "body.json").read_text(encoding="utf-8"))
        OUT.mkdir(exist_ok=True)

        predictions = {
            name: predict_arm(name, views, body_document)
            for name, views in ARMS.items()
        }
        body2_pairs = {tuple(pair["pair"]) for pair in predictions["body2"][0]["pairs"]}
        combined3_pairs = {
            tuple(pair["pair"]) for pair in predictions["combined3"][0]["pairs"]
        }
        if not combined3_pairs <= body2_pairs:
            raise ValueError("combined3 consensus is not a subset of body2 consensus")

        verify_hashes(HERE, POST_PREDICTION_INPUT_HASHES)
        evaluations = {
            name: evaluate_arm(name, family)
            for name, (_candidate, family) in predictions.items()
        }

        verify_hashes(OUT, OUTPUT_HASHES)
    except Exception as exc:
        print(f"replay failed: {exc}", file=sys.stderr)
        return 1

    print(f"cached-observation multiview replay PASS ({platform.system()}, Python {platform.python_version()})")
    for name in ARMS:
        candidate, family = predictions[name]
        metrics = evaluations[name]["metrics"]
        print(
            f"{name}: candidates={len(candidate['pairs'])} "
            f"comparisons={family['metrics']['total_detailed_comparisons']} "
            f"cells={family['metrics']['total_alignment_cells']} "
            f"TP={metrics['TP']} FP={metrics['FP']} FN={metrics['FN']} "
            f"TN={metrics['TN']} F1={metrics['F1']} "
            f"exact_families={metrics['exact_family_recovered_count']}"
        )
    for path in sorted(OUT.glob("body2-*.json")) + sorted(OUT.glob("combined3-*.json")):
        print(f"sha256 {path.name} {sha256(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
