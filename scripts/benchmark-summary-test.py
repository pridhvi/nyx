#!/usr/bin/env python3
"""Regression tests for benchmark summary gate behavior."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SUMMARY_PATH = ROOT / "scripts" / "benchmark-summary.py"
SPEC = importlib.util.spec_from_file_location("benchmark_summary", SUMMARY_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"could not load {SUMMARY_PATH}")
benchmark_summary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark_summary)

INDEX_PATH = ROOT / "scripts" / "benchmark-index.py"
INDEX_SPEC = importlib.util.spec_from_file_location("benchmark_index", INDEX_PATH)
if INDEX_SPEC is None or INDEX_SPEC.loader is None:
    raise RuntimeError(f"could not load {INDEX_PATH}")
benchmark_index = importlib.util.module_from_spec(INDEX_SPEC)
INDEX_SPEC.loader.exec_module(benchmark_index)


def write_fixture_db(path: Path, *, failed_tool_runs: int = 0) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE sessions (
              id TEXT,
              name TEXT,
              status TEXT,
              mode TEXT,
              workload_mode TEXT,
              target_input TEXT,
              finding_count INTEGER,
              target_count INTEGER,
              created_at TEXT,
              completed_at TEXT
            );
            CREATE TABLE findings (
              id TEXT,
              severity TEXT,
              type TEXT,
              tool_id TEXT,
              title TEXT,
              description TEXT,
              url TEXT,
              parameter TEXT,
              evidence_normalized TEXT,
              status TEXT
            );
            CREATE TABLE tool_runs (
              tool_id TEXT,
              exit_code INTEGER,
              finding_count INTEGER,
              duration_ms INTEGER,
              stdout_path TEXT,
              stderr_path TEXT,
              started_at TEXT
            );
            INSERT INTO sessions VALUES
              ('session-1', 'bench', 'completed', 'active', 'dynamic', 'http://target', 2, 1, 'now', 'later');
            INSERT INTO findings VALUES
              ('finding-1', 'high', 'sql_injection', 'sqli-check', 'Boolean SQL injection confirmed', '', '/sqli', '', '', 'confirmed'),
              ('finding-2', 'medium', 'xss', 'reflected-xss-check', 'Reflected XSS marker confirmed', '', '/xss', '', '', 'confirmed');
            """
        )
        conn.execute("INSERT INTO tool_runs VALUES (?, ?, ?, ?, ?, ?, ?)", ("sqli-check", 0, 1, 10, "", "", "now"))
        for index in range(failed_tool_runs):
            conn.execute(
                "INSERT INTO tool_runs VALUES (?, ?, ?, ?, ?, ?, ?)",
                (f"failed-tool-{index}", 2, 0, 20, "", "", "now"),
            )
        conn.commit()
    finally:
        conn.close()


class BenchmarkSummaryGateTest(unittest.TestCase):
    def test_gate_passes_when_coverage_meets_floor_and_tools_succeed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            expected = tmp_path / "expected.json"
            db = tmp_path / "session.db"
            expected.write_text(
                json.dumps(
                    {
                        "items": [
                            {"id": "sqli", "match": {"title": ["SQL injection confirmed"]}},
                            {"id": "xss", "match": {"title": ["XSS marker confirmed"]}},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            write_fixture_db(db)

            summary = benchmark_summary.build_summary("fixture", expected, db, "http://target", tmp_path)
            gate = benchmark_summary.benchmark_gate(summary, min_covered=2, allow_failed_tools=False)

            self.assertTrue(gate["passed"])
            self.assertEqual([], gate["failures"])

    def test_gate_fails_when_coverage_is_below_floor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            expected = tmp_path / "expected.json"
            db = tmp_path / "session.db"
            expected.write_text(
                json.dumps(
                    {
                        "items": [
                            {"id": "sqli", "match": {"title": ["SQL injection confirmed"]}},
                            {"id": "xss", "match": {"title": ["XSS marker confirmed"]}},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            write_fixture_db(db)

            summary = benchmark_summary.build_summary("fixture", expected, db, "http://target", tmp_path)
            gate = benchmark_summary.benchmark_gate(summary, min_covered=3, allow_failed_tools=False)

            self.assertFalse(gate["passed"])
            self.assertIn("coverage 2/2 is below required minimum 3", gate["failures"])

    def test_gate_rejects_failed_tools_unless_explicitly_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            expected = tmp_path / "expected.json"
            db = tmp_path / "session.db"
            expected.write_text(
                json.dumps({"items": [{"id": "sqli", "match": {"title": ["SQL injection confirmed"]}}]}),
                encoding="utf-8",
            )
            write_fixture_db(db, failed_tool_runs=1)

            summary = benchmark_summary.build_summary("fixture", expected, db, "http://target", tmp_path)

            strict_gate = benchmark_summary.benchmark_gate(summary, min_covered=1, allow_failed_tools=False)
            relaxed_gate = benchmark_summary.benchmark_gate(summary, min_covered=1, allow_failed_tools=True)

            self.assertFalse(strict_gate["passed"])
            self.assertIn("1 tool run(s) exited nonzero", strict_gate["failures"])
            self.assertTrue(relaxed_gate["passed"])


class BenchmarkIndexTest(unittest.TestCase):
    def test_index_rolls_up_target_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "dvwa"
            second = root / "dvga"
            first.mkdir()
            second.mkdir()
            (first / "summary.json").write_text(
                json.dumps(
                    {
                        "benchmark": "dvwa",
                        "target_url": "http://target-one",
                        "session": {"id": "session-one"},
                        "covered_count": 2,
                        "expected_count": 2,
                        "coverage_percent": 100,
                        "confirmed_count": 1,
                        "detected_count": 1,
                        "partial_count": 0,
                        "missed_count": 0,
                        "skipped_count": 0,
                        "finding_count": 5,
                        "tool_run_count": 3,
                        "failed_tool_runs": [],
                        "gate": {"passed": True},
                    }
                ),
                encoding="utf-8",
            )
            (second / "summary.json").write_text(
                json.dumps(
                    {
                        "benchmark": "dvga",
                        "target_url": "http://target-two",
                        "session": {"id": "session-two"},
                        "covered_count": 1,
                        "expected_count": 2,
                        "coverage_percent": 50,
                        "confirmed_count": 0,
                        "detected_count": 0,
                        "partial_count": 1,
                        "missed_count": 1,
                        "skipped_count": 0,
                        "finding_count": 2,
                        "tool_run_count": 1,
                        "failed_tool_runs": [{"tool_id": "x", "exit_code": 1}],
                        "gate": {"passed": False},
                    }
                ),
                encoding="utf-8",
            )

            index = benchmark_index.build_index(root)
            rendered = benchmark_index.markdown(index)

            self.assertFalse(index["gate_passed"])
            self.assertEqual(2, index["target_count"])
            self.assertEqual(3, index["totals"]["covered"])
            self.assertEqual(4, index["totals"]["expected"])
            self.assertEqual(1, index["totals"]["failed_tool_runs"])
            self.assertIn("dvwa/summary.md", rendered)
            self.assertIn("dvga", rendered)


if __name__ == "__main__":
    unittest.main()
