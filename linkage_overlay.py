"""Address-to-identity overlay on top of the source-origin ground truth.

The ground truth answers "which source function did this come from". Scoring
generic-family recovery needs a second question answered first: which
*monomorphized* item does an address stand for. Three things get in the way.

    duplicated   one mono item emitted at several addresses
    folded       several mono items sharing one address
    ambiguous    one address standing for several source origins

None of them is the algorithm's fault, and none is a distinction it can make
from the binary. So pairs touching them are scored as neutral: excluded from
the counts entirely, rather than charged as a miss or credited as a hit.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping


# Rust keeps the mono item's disambiguator in `...17h<16 hex>E`. A `.llvm.N`
# tail is added afterwards when a copy is cloned, so it is the only part that
# may be stripped: removing the disambiguator would merge distinct mono items.
_LLVM_CLONE_SUFFIX = re.compile(r"\.llvm\.\d+$")

CLEAN = "clean"
DUPLICATED = "duplicated"
FOLDED = "folded"
MIXED = "mixed"
UNRESOLVED = "unresolved"
SHAPES = (CLEAN, DUPLICATED, FOLDED, MIXED, UNRESOLVED)

POSITIVE = "positive"
NEGATIVE = "negative"
DUPLICATE_NEUTRAL = "duplicate-neutral"
AMBIGUOUS_NEUTRAL = "ambiguous-neutral"
UNRESOLVED_NEUTRAL = "unresolved-neutral"
PAIR_LABELS = (
    POSITIVE, NEGATIVE, DUPLICATE_NEUTRAL, AMBIGUOUS_NEUTRAL, UNRESOLVED_NEUTRAL,
)
NEUTRAL_LABELS = (DUPLICATE_NEUTRAL, AMBIGUOUS_NEUTRAL, UNRESOLVED_NEUTRAL)


def canonical_identity(symbol: str) -> str:
    """Drop a `.llvm.N` clone tail, keeping the Rust disambiguator hash."""
    return _LLVM_CLONE_SUFFIX.sub("", symbol)


@dataclass(frozen=True)
class OriginLinkage:
    origin: str
    identities_by_address: dict[str, tuple[str, ...]]
    addresses_by_identity: dict[str, tuple[str, ...]]

    @property
    def has_duplication(self) -> bool:
        return any(len(value) > 1 for value in self.addresses_by_identity.values())

    @property
    def has_folding(self) -> bool:
        return any(len(value) > 1 for value in self.identities_by_address.values())

    @property
    def shape(self) -> str:
        if any(not value for value in self.identities_by_address.values()):
            return UNRESOLVED
        if self.has_duplication and self.has_folding:
            return MIXED
        if self.has_duplication:
            return DUPLICATED
        if self.has_folding:
            return FOLDED
        return CLEAN

    @property
    def unobservable_identity_pairs(self) -> int:
        """Identity pairs no address-level method could ever separate."""
        return sum(
            len(value) * (len(value) - 1) // 2
            for value in self.identities_by_address.values()
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "shape": self.shape,
            "address_count": len(self.identities_by_address),
            "identity_count": len(self.addresses_by_identity),
            "has_duplication": self.has_duplication,
            "has_folding": self.has_folding,
            "unobservable_identity_pairs": self.unobservable_identity_pairs,
            "identities_by_address": {
                address: list(identities)
                for address, identities in sorted(self.identities_by_address.items())
            },
            "addresses_by_identity": {
                identity: list(addresses)
                for identity, addresses in sorted(self.addresses_by_identity.items())
            },
        }


def build_origin_linkage(
    origin: str,
    members: Iterable[str],
    identities_by_address: Mapping[str, Iterable[str]],
) -> OriginLinkage:
    by_address = {
        member: tuple(sorted(identities_by_address.get(member, ())))
        for member in sorted(members)
    }
    by_identity: dict[str, set[str]] = defaultdict(set)
    for address, identities in by_address.items():
        for identity in identities:
            by_identity[identity].add(address)
    return OriginLinkage(
        origin=origin,
        identities_by_address=by_address,
        addresses_by_identity={
            identity: tuple(sorted(addresses))
            for identity, addresses in sorted(by_identity.items())
        },
    )


def label_pair(
    left: str,
    right: str,
    *,
    origins_by_address: Mapping[str, Iterable[str]],
    identities_by_address: Mapping[str, Iterable[str]],
) -> str:
    """Decide what one address pair is worth to a generic-family scorer."""
    left_ids = set(identities_by_address.get(left, ()))
    right_ids = set(identities_by_address.get(right, ()))
    if not left_ids or not right_ids:
        return UNRESOLVED_NEUTRAL

    left_origins = set(origins_by_address.get(left, ()))
    right_origins = set(origins_by_address.get(right, ()))
    if not left_origins or not right_origins:
        return UNRESOLVED_NEUTRAL
    # One address standing for several source origins cannot be judged: two
    # different answers would both be defensible.
    if len(left_origins) > 1 or len(right_origins) > 1:
        return AMBIGUOUS_NEUTRAL

    if left_origins != right_origins:
        return NEGATIVE
    # Same origin. Sharing a mono identity means this pair is one item emitted
    # twice, which is not evidence of recovering a generic family.
    if left_ids & right_ids:
        return DUPLICATE_NEUTRAL
    return POSITIVE


def load_overlay(
    audit: Mapping[str, Any],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Read `origins_by_address` and `identities_by_address` from an audit."""
    addresses = audit.get("addresses")
    if not isinstance(addresses, Mapping):
        raise ValueError("audit artifact has no addresses overlay")
    return (
        {address: list(record["origins"]) for address, record in addresses.items()},
        {address: list(record["identities"]) for address, record in addresses.items()},
    )


def _counts(labels: Mapping[Any, str], predicted: Iterable[Any]) -> dict[str, Any]:
    predicted = set(predicted)
    positives = {pair for pair, label in labels.items() if label == POSITIVE}
    negatives = {pair for pair, label in labels.items() if label == NEGATIVE}
    scored = positives | negatives
    hit = predicted & scored
    tp = len(hit & positives)
    fp = len(hit & negatives)
    fn = len(positives - predicted)
    tn = len(negatives - predicted)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision and recall
        else None
    )
    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": precision, "recall": recall, "F1": f1,
        "scored_pair_count": len(scored),
        "positive_pair_count": len(positives),
    }


def score_labeled_pairs(
    all_pairs: Iterable[tuple[str, str]],
    predicted_pairs: Iterable[tuple[str, str]],
    *,
    origins_by_address: Mapping[str, Iterable[str]],
    identities_by_address: Mapping[str, Iterable[str]],
) -> dict[str, Any]:
    """Score the same predictions under both questions CallKin can answer.

    `primary` asks whether distinct monomorphizations of one source origin were
    recovered, and sets aside every pair the binary cannot decide.
    `source_origin` asks the weaker question an analyst cares about, where two
    copies of one mono item grouped together still counts.
    """
    all_pairs = [tuple(pair) for pair in all_pairs]
    predicted = {tuple(pair) for pair in predicted_pairs}

    primary = {
        pair: label_pair(
            pair[0], pair[1],
            origins_by_address=origins_by_address,
            identities_by_address=identities_by_address,
        )
        for pair in all_pairs
    }
    secondary = {
        pair: source_origin_label(
            pair[0], pair[1], origins_by_address=origins_by_address
        )
        for pair in all_pairs
    }

    label_counts: dict[str, int] = {name: 0 for name in PAIR_LABELS}
    for label in primary.values():
        label_counts[label] += 1
    neutral = sum(label_counts[name] for name in NEUTRAL_LABELS)
    return {
        "pair_count": len(all_pairs),
        "label_counts": label_counts,
        "neutral_pair_count": neutral,
        "neutral_fraction": neutral / len(all_pairs) if all_pairs else 0.0,
        "primary": _counts(primary, predicted),
        "source_origin": _counts(secondary, predicted),
    }


def source_origin_label(
    left: str,
    right: str,
    *,
    origins_by_address: Mapping[str, Iterable[str]],
) -> str:
    """The secondary question: same source function, duplicates included.

    Grouping two copies of one mono item still helps an analyst read the
    binary, so here it counts as a hit rather than being set aside.
    """
    left_origins = set(origins_by_address.get(left, ()))
    right_origins = set(origins_by_address.get(right, ()))
    if not left_origins or not right_origins:
        return UNRESOLVED_NEUTRAL
    if len(left_origins) > 1 or len(right_origins) > 1:
        return AMBIGUOUS_NEUTRAL
    return POSITIVE if left_origins == right_origins else NEGATIVE
