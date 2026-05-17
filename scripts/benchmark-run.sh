#!/usr/bin/env sh
set -eu

if [ "${NOX_RUN_BENCHMARKS:-}" != "1" ]; then
  echo "Benchmark scans are opt-in. Set NOX_RUN_BENCHMARKS=1 to run them."
  exit 0
fi

benchmark="${1:-all}"
timestamp="$(date +%Y%m%d-%H%M%S)"
artifact_root="${NOX_BENCHMARK_ARTIFACT_DIR:-artifacts/benchmarks/$timestamp}"
sessions_root="$artifact_root/sessions"
mkdir -p "$artifact_root" "$sessions_root"

tools_default="http-probe,security-headers,whatweb,graphql-introspection,openapi-discovery,arjun,linkfinder,js-secret-scan,cors-check,nmap,ffuf,nuclei-tech,nuclei-vuln,nikto,sqlmap,dalfox"
tools="${NOX_BENCHMARK_TOOLS:-$tools_default}"
scan_timeout="${NOX_BENCHMARK_SCAN_TIMEOUT:-20m}"
go_cmd="${NOX_GO_CMD:-go run .}"

fail() {
  echo "Benchmark failed: $*" >&2
  echo "Artifacts: $artifact_root" >&2
  exit 1
}

ensure_targets() {
  if [ "${NOX_BENCHMARK_NO_TARGET_UP:-}" = "1" ]; then
    return
  fi
  ./scripts/benchmark-targets.sh up >"$artifact_root/targets-up.log" 2>&1 || {
    sed -n '1,220p' "$artifact_root/targets-up.log" >&2 || true
    fail "benchmark targets did not start"
  }
}

session_id_from_log() {
  log="$1"
  awk '/created session/{print $3; exit}' "$log"
}

session_db_for() {
  session_id="$1"
  db_path="$sessions_root/$session_id/session.db"
  if [ ! -f "$db_path" ]; then
    fail "missing session database $db_path"
  fi
  printf '%s' "$db_path"
}

assert_session_persistence() {
  db_path="$1"
  session_id="$2"
  session_dir="$sessions_root/$session_id"
  python3 - "$db_path" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
try:
    status = conn.execute("SELECT status FROM sessions LIMIT 1").fetchone()
    if not status or status[0] != "completed":
        raise SystemExit(f"session status is not completed: {status[0] if status else 'missing'}")
    tool_runs = conn.execute("SELECT COUNT(*) FROM tool_runs").fetchone()[0]
    if tool_runs < 1:
        raise SystemExit("session has no persisted tool runs")
finally:
    conn.close()
PY
  if ! find "$session_dir/runs" -type f -name '*.log' -size +0c 2>/dev/null | grep -q .; then
    fail "missing retained sidecar logs under $session_dir/runs"
  fi
}

assert_report_artifact() {
  path="$1"
  if [ ! -s "$path" ]; then
    fail "missing or empty report artifact $path"
  fi
}

copy_profile_artifacts() {
  name="$1"
  mkdir -p "$artifact_root/$name"
  cp "benchmarks/$name/profile.json" "$artifact_root/$name/profile.json"
  cp "benchmarks/$name/expected.json" "$artifact_root/$name/expected.json"
  cp "benchmarks/$name/routes.txt" "$artifact_root/$name/routes.txt"
}

target_url_for() {
  name="$1"
  case "$name" in
    dvwa)
      printf '%s' "${NOX_BENCHMARK_DVWA_URL:-http://127.0.0.1:${NOX_BENCHMARK_DVWA_PORT:-18080}}"
      ;;
    juice-shop)
      printf '%s' "${NOX_BENCHMARK_JUICE_URL:-http://127.0.0.1:${NOX_BENCHMARK_JUICE_PORT:-13000}}"
      ;;
    *)
      fail "unknown benchmark target $name"
      ;;
  esac
}

run_one() {
  name="$1"
  target_url="$(target_url_for "$name")"
  log="$artifact_root/$name/scan.log"
  report_md="$artifact_root/$name/report.md"
  report_sarif="$artifact_root/$name/report.sarif"
  summary_json="$artifact_root/$name/summary.json"
  summary_md="$artifact_root/$name/summary.md"

  copy_profile_artifacts "$name"
  echo "Running $name benchmark against $target_url"
  if command -v timeout >/dev/null 2>&1; then
    scan_prefix="timeout $scan_timeout"
  else
    scan_prefix=""
  fi
  if ! $scan_prefix env NOX_SESSION_DIR="$sessions_root" $go_cmd scan \
    --target "$target_url" \
    --tools "$tools" \
    --no-llm \
    --config /dev/null >"$log" 2>&1; then
    sed -n '1,220p' "$log" >&2 || true
    fail "$name scan failed"
  fi

  session_id="$(session_id_from_log "$log")"
  if [ -z "$session_id" ]; then
    sed -n '1,220p' "$log" >&2 || true
    fail "$name scan did not print a session id"
  fi
  db_path="$(session_db_for "$session_id")"
  assert_session_persistence "$db_path" "$session_id"

  env NOX_SESSION_DIR="$sessions_root" $go_cmd report "$session_id" \
    --format md \
    --mode technical \
    --output "$report_md" \
    --config /dev/null >>"$log" 2>&1 || fail "$name markdown report failed"
  assert_report_artifact "$report_md"

  env NOX_SESSION_DIR="$sessions_root" $go_cmd report "$session_id" \
    --format sarif \
    --output "$report_sarif" \
    --config /dev/null >>"$log" 2>&1 || fail "$name SARIF report failed"
  assert_report_artifact "$report_sarif"

  scripts/benchmark-summary.py \
    --benchmark "$name" \
    --expected "benchmarks/$name/expected.json" \
    --db "$db_path" \
    --target-url "$target_url" \
    --artifact-dir "$artifact_root" \
    --json-output "$summary_json" \
    --markdown-output "$summary_md"

  echo "$name session: $session_id"
  echo "$name artifacts: $artifact_root/$name"
}

ensure_targets

case "$benchmark" in
  dvwa)
    run_one dvwa
    ;;
  juice|juice-shop)
    run_one juice-shop
    ;;
  all)
    run_one dvwa
    run_one juice-shop
    ;;
  *)
    echo "usage: $0 {dvwa|juice-shop|all}" >&2
    exit 2
    ;;
esac

echo "Benchmark artifacts: $artifact_root"
