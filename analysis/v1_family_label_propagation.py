"""Build a GT-free F10 direct-FLIRT family-label propagation artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from family_label_propagation import (  # noqa: E402
    DEFAULT_ID_BIAS,
    build_propagation_files,
)


def _int(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family-artifact", required=True)
    parser.add_argument(
        "--oxidizer-labels", dest="labels", required=True,
        help="Oxidizer label artifact; only matches/evidence=direct-flirt is used",
    )
    parser.add_argument(
        "--rescue-artifact", help="optional F7 rescue artifact whose final partition replaces strict accepted families",
    )
    parser.add_argument(
        "--id-bias", type=_int, default=DEFAULT_ID_BIAS,
        help=f"CallKin function-ID bias (default: 0x{DEFAULT_ID_BIAS:x})",
    )
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        report = build_propagation_files(
            args.family_artifact,
            args.labels,
            args.rescue_artifact,
            id_bias=args.id_bias,
        )
        if args.output:
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    if args.output:
        print(f"wrote {args.output}", file=sys.stderr)
    opportunity = report["opportunity"]
    print(
        f"method={report['method']} direct={opportunity['direct_seed_count']} "
        f"eligible={opportunity['eligible_family_count']} "
        f"propagated={opportunity['propagated_member_count']} "
        f"conflicts={opportunity['conflict_family_count']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
