#!/usr/bin/env python3

import argparse
import sys

from utils.permissions import check_root
from core.scanner import run_scan
from core.scorer import calculate_score
from core.reporter import generate_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="TracexClean - Post-Exploitation Footprint Analysis Tool (Linux)"
    )

    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze system for post-exploitation footprints"
    )

    parser.add_argument(
        "--simulate-cleanup",
        action="store_true",
        help="Simulate cleanup actions (no files are modified)"
    )

    parser.add_argument(
        "--report",
        choices=["terminal", "markdown"],
        default="terminal",
        help="Report output format (default: terminal)"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    if not args.analyze:
        print("[!] No action specified. Use --analyze")
        sys.exit(1)

    check_root()

    print("\n[+] Starting TracexClean analysis...\n")

    findings = run_scan()

    score_summary = calculate_score(findings)

    generate_report(
        findings=findings,
        score_summary=score_summary,
        output_format=args.report,
        simulate_cleanup=args.simulate_cleanup
    )

    print("\n[+] Analysis complete.\n")


if __name__ == "__main__":
    main()
