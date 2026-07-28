"""YARA feedback loop — learn from analyst verdicts.

When an analyst reviews L1 findings and marks them as:
  - TRUE POSITIVE: rule is working, log the confirmation
  - FALSE POSITIVE: rule fired incorrectly, log for tuning
  - MISSED DETECTION: analyst found something L1 missed, generate rule stub

Usage:
    python yara_feedback.py tp <sha256> <rule_name>           # confirm hit
    python yara_feedback.py fp <sha256> <rule_name> --reason   # mark FP
    python yara_feedback.py missed <sha256> --category --evidence  # new detection needed
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

L1_DIR = Path(__file__).resolve().parent
FEEDBACK_LOG = L1_DIR / "yara_feedback_log.jsonl"


@dataclass
class FeedbackEntry:
    timestamp: str
    sha256: str
    verdict: str
    rule_name: str | None
    category: str | None
    evidence: str | None
    reason: str | None
    analyst: str | None


def log_feedback(entry: FeedbackEntry) -> None:
    """Append to feedback log (JSONL for easy batch analysis)."""
    with FEEDBACK_LOG.open("a") as fh:
        fh.write(json.dumps(asdict(entry)) + "\n")
    print(f"Logged {entry.verdict.upper()} for {entry.sha256}")


def generate_rule_stub(category: str, evidence: str, strings: list[str]) -> str:
    """Generate a YARA rule stub from analyst-provided evidence."""
    safe_name = f"Android_Analyst_{category}_{int(time.time())}"
    string_defs = "\n".join(
        f'        $s{i} = "{s}" ascii wide'
        for i, s in enumerate(strings, 1)
    )
    return f"""
rule {safe_name} {{
    meta:
        description = "Analyst-generated rule: {evidence[:100]}"
        severity = "medium"
        scope = "source"
        author = "analyst_feedback"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        needs_review = "true"

    strings:
{string_defs}

    condition:
        {len(strings) // 2 + 1} of them
}}
"""


def summarize_feedback() -> None:
    if not FEEDBACK_LOG.exists():
        print("No feedback logged yet.")
        return

    counts = {"tp": 0, "fp": 0, "missed": 0}
    rule_stats = {}

    with FEEDBACK_LOG.open() as fh:
        for line in fh:
            data = json.loads(line)
            v = data.get("verdict")
            counts[v] = counts.get(v, 0) + 1

            rule = data.get("rule_name")
            if rule:
                stats = rule_stats.setdefault(rule, {"tp": 0, "fp": 0})
                if v in stats:
                    stats[v] += 1

    print(f"=== Feedback Summary ===")
    print(f"Total Feedback: {sum(counts.values())}")
    print(f"True Positives: {counts['tp']}")
    print(f"False Positives: {counts['fp']}")
    print(f"Missed Detections: {counts['missed']}\n")

    print("=== Rule Performance (Candidates for tuning) ===")
    for rule, stats in sorted(rule_stats.items(), key=lambda item: item[1]["fp"], reverse=True):
        if stats["fp"] > 0 or stats["tp"] > 0:
            print(f"  {rule:40s} TP: {stats['tp']:3d} | FP: {stats['fp']:3d}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="YARA Analyst Feedback Loop")
    sub = parser.add_subparsers(dest="command")

    tp = sub.add_parser("tp", help="Log a True Positive (rule fired correctly)")
    tp.add_argument("sha256", help="APK SHA256")
    tp.add_argument("rule", help="Rule name that fired")

    fp = sub.add_parser("fp", help="Log a False Positive (rule fired incorrectly)")
    fp.add_argument("sha256", help="APK SHA256")
    fp.add_argument("rule", help="Rule name that fired")
    fp.add_argument("--reason", default="", help="Why this was a false positive")

    missed = sub.add_parser("missed", help="Log a missed detection and generate a rule stub")
    missed.add_argument("sha256", help="APK SHA256")
    missed.add_argument("--category", required=True, help="Category of threat")
    missed.add_argument("--evidence", required=True, help="What behavior was missed")
    missed.add_argument("--strings", nargs="+", default=[], help="Strings found by analyst to generate a rule stub")

    sub.add_parser("summary", help="Show summary of feedback")

    args = parser.parse_args(argv[1:])

    if args.command in ("tp", "fp"):
        entry = FeedbackEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            sha256=args.sha256,
            verdict=args.command,
            rule_name=args.rule,
            category=None,
            evidence=None,
            reason=getattr(args, "reason", None),
            analyst="local_analyst"
        )
        log_feedback(entry)
    elif args.command == "missed":
        entry = FeedbackEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            sha256=args.sha256,
            verdict="missed",
            rule_name=None,
            category=args.category,
            evidence=args.evidence,
            reason=None,
            analyst="local_analyst"
        )
        log_feedback(entry)
        if args.strings:
            print("\nGenerated Rule Stub (save to L1/yara_templates/analyst/):")
            print(generate_rule_stub(args.category, args.evidence, args.strings))
    elif args.command == "summary":
        summarize_feedback()
    else:
        parser.print_help()
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
