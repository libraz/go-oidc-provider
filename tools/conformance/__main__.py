from __future__ import annotations

import argparse
import sys

from . import baseline, drive, runner, seed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m tools.conformance",
        description="OFCS test driver — Python half of scripts/conformance.sh",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("seed-plans", help="Seed OFCS plans from conformance/plans/*.json")
    sp = sub.add_parser("drive", help="Walk a single OFCS authorize URL")
    sp.add_argument("url")

    sp = sub.add_parser("batch", help="Drive a list of modules under one plan")
    sp.add_argument("plan")
    sp.add_argument("modules", nargs="+")

    sp = sub.add_parser("baseline", help="Snapshot every module's result for every seeded plan")
    sp.add_argument("label", nargs="?", default="snapshot")

    sp = sub.add_parser("baseline-diff", help="Compare two baseline JSON snapshots")
    sp.add_argument("old")
    sp.add_argument("new")

    sp = sub.add_parser(
        "release-verify",
        help="Strictly verify a release snapshot against an approved catalog",
    )
    sp.add_argument("reference")
    sp.add_argument("candidate")
    sp.add_argument(
        "--exclusions",
        help=(
            "checked-in exclusion manifest "
            "(default: conformance/release-exclusions.json)"
        ),
    )

    args = parser.parse_args(argv)
    if args.cmd == "seed-plans":
        return seed.cmd_seed_plans()
    if args.cmd == "drive":
        return drive.cmd_drive(args.url)
    if args.cmd == "batch":
        return runner.cmd_batch(args.plan, args.modules)
    if args.cmd == "baseline":
        return baseline.cmd_baseline(args.label)
    if args.cmd == "baseline-diff":
        return baseline.cmd_baseline_diff(args.old, args.new)
    if args.cmd == "release-verify":
        return baseline.cmd_release_verify(
            args.reference,
            args.candidate,
            args.exclusions,
        )
    parser.error(f"unknown cmd: {args.cmd}")
    return 2  # unreachable


if __name__ == "__main__":
    sys.exit(main())
