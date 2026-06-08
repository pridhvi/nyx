#!/usr/bin/env python3
"""Generate an aggregate index for a benchmark artifact directory."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


STATUS_FIELDS = ("confirmed", "detected", "partial", "missed", "skipped")


def load_summaries(artifact_root: Path) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for path in sorted(artifact_root.glob("*/summary.json")):
        with path.open("r", encoding="utf-8") as handle:
            summary = json.load(handle)
        summary["summary_path"] = str(path.relative_to(artifact_root))
        summary["summary_markdown_path"] = str(path.with_suffix(".md").relative_to(artifact_root))
        summaries.append(summary)
    return summaries


def build_index(artifact_root: Path) -> dict[str, Any]:
    summaries = load_summaries(artifact_root)
    totals = {
        "expected": 0,
        "covered": 0,
        "findings": 0,
        "tool_runs": 0,
        "failed_tool_runs": 0,
        **{field: 0 for field in STATUS_FIELDS},
    }
    targets = []
    for summary in summaries:
        gate = summary.get("gate") or {}
        failed_tool_runs = summary.get("failed_tool_runs") or []
        target = {
            "benchmark": summary.get("benchmark", ""),
            "target_url": summary.get("target_url", ""),
            "session_id": (summary.get("session") or {}).get("id", ""),
            "covered_count": int(summary.get("covered_count") or 0),
            "expected_count": int(summary.get("expected_count") or 0),
            "coverage_percent": float(summary.get("coverage_percent") or 0),
            "confirmed_count": int(summary.get("confirmed_count") or 0),
            "detected_count": int(summary.get("detected_count") or 0),
            "partial_count": int(summary.get("partial_count") or 0),
            "missed_count": int(summary.get("missed_count") or 0),
            "skipped_count": int(summary.get("skipped_count") or 0),
            "finding_count": int(summary.get("finding_count") or 0),
            "tool_run_count": int(summary.get("tool_run_count") or 0),
            "failed_tool_run_count": len(failed_tool_runs),
            "gate_passed": bool(gate.get("passed")),
            "summary_path": summary.get("summary_path", ""),
            "summary_markdown_path": summary.get("summary_markdown_path", ""),
        }
        targets.append(target)
        totals["expected"] += target["expected_count"]
        totals["covered"] += target["covered_count"]
        totals["findings"] += target["finding_count"]
        totals["tool_runs"] += target["tool_run_count"]
        totals["failed_tool_runs"] += target["failed_tool_run_count"]
        totals["confirmed"] += target["confirmed_count"]
        totals["detected"] += target["detected_count"]
        totals["partial"] += target["partial_count"]
        totals["missed"] += target["missed_count"]
        totals["skipped"] += target["skipped_count"]
    totals["coverage_percent"] = round((totals["covered"] / totals["expected"]) * 100, 2) if totals["expected"] else 0
    return {
        "artifact_root": str(artifact_root),
        "target_count": len(targets),
        "gate_passed": bool(targets) and all(target["gate_passed"] for target in targets),
        "totals": totals,
        "targets": targets,
    }


def markdown(index: dict[str, Any]) -> str:
    totals = index["totals"]
    lines = [
        "# Benchmark Run Index",
        "",
        f"- Artifact root: `{index['artifact_root']}`",
        f"- Targets: {index['target_count']}",
        f"- Overall gate: {'passed' if index['gate_passed'] else 'failed'}",
        f"- Covered: {totals['covered']}/{totals['expected']} ({totals['coverage_percent']}%)",
        f"- Confirmed / Detected / Partial / Missed: {totals['confirmed']} / {totals['detected']} / {totals['partial']} / {totals['missed']}",
        f"- Findings: {totals['findings']}",
        f"- Tool runs: {totals['tool_runs']}",
        f"- Failed tool runs: {totals['failed_tool_runs']}",
        "",
        "## Targets",
        "",
        "| Gate | Benchmark | Covered | Confirmed | Detected | Partial | Missed | Findings | Tool runs | Summary |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for target in index["targets"]:
        gate = "passed" if target["gate_passed"] else "failed"
        summary_link = target.get("summary_markdown_path") or target.get("summary_path") or ""
        lines.append(
            "| "
            + " | ".join(
                [
                    gate,
                    target["benchmark"],
                    f"{target['covered_count']}/{target['expected_count']} ({target['coverage_percent']}%)",
                    str(target["confirmed_count"]),
                    str(target["detected_count"]),
                    str(target["partial_count"]),
                    str(target["missed_count"]),
                    str(target["finding_count"]),
                    str(target["tool_run_count"]),
                    f"[{summary_link}]({summary_link})" if summary_link else "",
                ]
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", required=True, type=Path)
    args = parser.parse_args()
    index = build_index(args.artifact_root)
    if not index["targets"]:
        raise SystemExit(f"no summary.json files found under {args.artifact_root}")
    (args.artifact_root / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    (args.artifact_root / "index.md").write_text(markdown(index), encoding="utf-8")
    print(
        f"benchmark index: {index['target_count']} target(s), "
        f"covered {index['totals']['covered']}/{index['totals']['expected']} "
        f"({index['totals']['coverage_percent']}%), gate={'passed' if index['gate_passed'] else 'failed'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
