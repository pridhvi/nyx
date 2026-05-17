#!/usr/bin/env python3
"""Generate benchmark coverage summaries from a Nox session database."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rows(db_path: Path, sql: str) -> list[dict[str, Any]]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(sql).fetchall()]
    finally:
        conn.close()


def session_row(db_path: Path) -> dict[str, Any]:
    result = rows(
        db_path,
        """
        SELECT id, name, status, mode, workload_mode, target_input, finding_count,
               target_count, created_at, completed_at
        FROM sessions
        LIMIT 1
        """,
    )
    return result[0] if result else {}


def findings(db_path: Path) -> list[dict[str, Any]]:
    return rows(
        db_path,
        """
        SELECT id, severity, type, tool_id, title, description, url, parameter,
               evidence_normalized, status
        FROM findings
        ORDER BY severity, tool_id, title
        """,
    )


def tool_runs(db_path: Path) -> list[dict[str, Any]]:
    return rows(
        db_path,
        """
        SELECT tool_id, exit_code, finding_count, duration_ms, stdout_path, stderr_path
        FROM tool_runs
        ORDER BY tool_id, started_at
        """,
    )


def text(value: Any) -> str:
    return str(value or "").lower()


def contains_any(haystack: str, needles: list[str]) -> bool:
    return any(text(needle) in haystack for needle in needles)


def exact_any(value: str, expected: list[str]) -> bool:
    lowered = text(value)
    return any(lowered == text(item) for item in expected)


def finding_matches(item: dict[str, Any], finding: dict[str, Any]) -> bool:
    match = item.get("match") or {}
    checks = 0
    matched = False
    for field in ("title", "description", "url", "parameter", "evidence_normalized"):
        values = match.get(field) or []
        if values:
            checks += 1
            matched = matched or contains_any(text(finding.get(field)), values)
    for field in ("tool", "type", "severity", "status"):
        values = match.get(field) or []
        if values:
            checks += 1
            db_field = "tool_id" if field == "tool" else field
            matched = matched or exact_any(text(finding.get(db_field)), values)
    return checks > 0 and matched


def item_status(item: dict[str, Any], matches: list[dict[str, Any]]) -> str:
    if not matches:
        return "missed"
    if any(text(match.get("status")) == "confirmed" for match in matches):
        return "confirmed"
    if item.get("automation_suitable") is False:
        return "partial"
    return "detected"


def severity_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in items:
        key = text(item.get("severity")) or "unknown"
        out[key] = out.get(key, 0) + 1
    return out


def build_summary(
    benchmark: str,
    expected_path: Path,
    db_path: Path,
    target_url: str,
    artifact_dir: Path,
) -> dict[str, Any]:
    expected = load_json(expected_path)
    all_findings = findings(db_path)
    all_runs = tool_runs(db_path)
    item_results = []
    status_counts = {"confirmed": 0, "detected": 0, "partial": 0, "missed": 0, "skipped": 0}
    for item in expected.get("items", []):
        matches = [finding for finding in all_findings if finding_matches(item, finding)]
        status = item_status(item, matches)
        status_counts[status] = status_counts.get(status, 0) + 1
        item_results.append(
            {
                "id": item.get("id"),
                "class": item.get("class"),
                "label": item.get("label"),
                "route": item.get("route", ""),
                "automation_suitable": item.get("automation_suitable", True),
                "status": status,
                "finding_ids": [match["id"] for match in matches],
                "finding_titles": [match["title"] for match in matches],
                "confirmation_strategy": item.get("confirmation_strategy", ""),
            }
        )
    total = len(item_results)
    covered = status_counts.get("confirmed", 0) + status_counts.get("detected", 0) + status_counts.get("partial", 0)
    session = session_row(db_path)
    failed_tools = [run for run in all_runs if int(run.get("exit_code") or 0) != 0]
    return {
        "benchmark": benchmark,
        "target_url": target_url,
        "artifact_dir": str(artifact_dir),
        "session": session,
        "expected_count": total,
        "covered_count": covered,
        "confirmed_count": status_counts.get("confirmed", 0),
        "detected_count": status_counts.get("detected", 0),
        "partial_count": status_counts.get("partial", 0),
        "missed_count": status_counts.get("missed", 0),
        "skipped_count": status_counts.get("skipped", 0),
        "coverage_percent": round((covered / total) * 100, 2) if total else 0,
        "finding_count": len(all_findings),
        "finding_severity_counts": severity_counts(all_findings),
        "tool_run_count": len(all_runs),
        "failed_tool_runs": [
            {
                "tool_id": run.get("tool_id"),
                "exit_code": run.get("exit_code"),
                "finding_count": run.get("finding_count"),
            }
            for run in failed_tools
        ],
        "items": item_results,
    }


def markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# {summary['benchmark']} Benchmark",
        "",
        f"- Target: {summary['target_url']}",
        f"- Session: {summary.get('session', {}).get('id', '')}",
        f"- Session status: {summary.get('session', {}).get('status', '')}",
        f"- Findings: {summary['finding_count']}",
        f"- Tool runs: {summary['tool_run_count']}",
        f"- Covered: {summary['covered_count']}/{summary['expected_count']} ({summary['coverage_percent']}%)",
        f"- Confirmed: {summary['confirmed_count']}",
        f"- Detected: {summary['detected_count']}",
        f"- Partial: {summary['partial_count']}",
        f"- Missed: {summary['missed_count']}",
        f"- Skipped: {summary['skipped_count']}",
        "",
        "## Expected Coverage",
        "",
        "| Status | Class | Label | Route | Findings |",
        "|---|---|---|---|---|",
    ]
    for item in summary["items"]:
        titles = "<br>".join(item["finding_titles"]) if item["finding_titles"] else ""
        lines.append(
            f"| {item['status']} | {item['class']} | {item['label']} | {item.get('route', '')} | {titles} |"
        )
    if summary["failed_tool_runs"]:
        lines.extend(["", "## Failed Tool Runs", ""])
        for run in summary["failed_tool_runs"]:
            lines.append(f"- {run['tool_id']} exit={run['exit_code']} findings={run['finding_count']}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--expected", required=True, type=Path)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--target-url", required=True)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--markdown-output", required=True, type=Path)
    args = parser.parse_args()

    summary = build_summary(args.benchmark, args.expected, args.db, args.target_url, args.artifact_dir)
    args.json_output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    args.markdown_output.write_text(markdown(summary), encoding="utf-8")
    print(
        f"{summary['benchmark']}: covered {summary['covered_count']}/{summary['expected_count']} "
        f"({summary['coverage_percent']}%), findings={summary['finding_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
