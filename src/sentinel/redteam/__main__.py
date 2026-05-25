"""CLI entry point: ``python -m sentinel.redteam``."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from sentinel.bootstrap import build_default_interceptor
from sentinel.redteam.harness import RedTeamHarness, default_scenarios


def main() -> int:
    p = argparse.ArgumentParser(prog="sentinel-redteam")
    p.add_argument("--emit-json", action="store_true")
    p.add_argument("--fail-on-allow", action="store_true")
    args = p.parse_args()

    interceptor = build_default_interceptor()
    harness = RedTeamHarness(interceptor=interceptor)
    scenarios = default_scenarios()
    report = asyncio.run(harness.run(scenarios))

    summary = {
        "total": report.total,
        "passed": report.passed,
        "pass_rate": round(report.pass_rate, 4),
        "false_negatives": list(report.false_negatives),
        "false_positives": list(report.false_positives),
    }
    print(json.dumps(summary, indent=2))
    if args.fail_on_allow and report.false_negatives:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
