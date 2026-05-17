#!/usr/bin/env sh
set -eu

if [ "${NOX_RUN_INTEGRATION:-}" != "1" ]; then
  echo "Integration smoke is opt-in. Set NOX_RUN_INTEGRATION=1 to run it."
  exit 0
fi

root_dir="$(mktemp -d)"
fixture_log="/tmp/nox-integration-fixture.log"
dynamic_log="/tmp/nox-integration-dynamic-scan.log"
lean_log="/tmp/nox-integration-lean-scan.log"
audit_log="/tmp/nox-integration-audit.log"
combined_log="/tmp/nox-integration-combined-scan.log"
dynamic_report="/tmp/nox-integration-dynamic-report.md"
audit_sarif="/tmp/nox-integration-audit.sarif"
combined_report="/tmp/nox-integration-combined-report.md"
fixture_pid=""

cleanup() {
  if [ -n "$fixture_pid" ]; then
    kill "$fixture_pid" >/dev/null 2>&1 || true
  fi
  if [ "${NOX_KEEP_INTEGRATION_ARTIFACTS:-}" != "1" ]; then
    rm -rf "$root_dir"
  else
    echo "Keeping integration sessions under $root_dir"
  fi
}
trap cleanup EXIT INT TERM

fail() {
  echo "Integration smoke failed: $*" >&2
  for artifact in "$fixture_log" "$dynamic_log" "$lean_log" "$audit_log" "$combined_log" "$dynamic_report" "$audit_sarif" "$combined_report"; do
    if [ -s "$artifact" ]; then
      echo "----- $artifact -----" >&2
      sed -n '1,220p' "$artifact" >&2 || true
    fi
  done
  exit 1
}

query() {
  sqlite3 "$1" "$2"
}

assert_count_at_least() {
  db="$1"
  sql="$2"
  min="$3"
  label="$4"
  count="$(query "$db" "$sql")"
  if [ "$count" -lt "$min" ]; then
    fail "$label: expected at least $min, got $count"
  fi
}

assert_count_equals() {
  db="$1"
  sql="$2"
  want="$3"
  label="$4"
  count="$(query "$db" "$sql")"
  if [ "$count" -ne "$want" ]; then
    fail "$label: expected $want, got $count"
  fi
}

assert_file_contains() {
  file="$1"
  pattern="$2"
  label="$3"
  if ! grep -Eq "$pattern" "$file"; then
    fail "$label: $file did not contain pattern $pattern"
  fi
}

session_id_for() {
  dir="$1"
  found=""
  for db_path in "$dir"/*/session.db; do
    if [ -f "$db_path" ]; then
      found="$(basename "$(dirname "$db_path")")"
      break
    fi
  done
  if [ -z "$found" ]; then
    fail "no directory-based session database found under $dir"
  fi
  printf '%s' "$found"
}

session_db_for() {
  dir="$1"
  session_id="$2"
  db_path="$dir/$session_id/session.db"
  if [ ! -f "$db_path" ]; then
    fail "missing session database $db_path"
  fi
  printf '%s' "$db_path"
}

assert_completed_session() {
  db="$1"
  status="$(query "$db" "SELECT status FROM sessions LIMIT 1;")"
  if [ "$status" != "completed" ]; then
    fail "session status: expected completed, got $status"
  fi
}

assert_sidecars_present() {
  session_path="$1"
  if [ ! -d "$session_path/runs" ]; then
    fail "expected sidecar runs directory at $session_path/runs"
  fi
  logs="$(find "$session_path/runs" -type f -name '*.log' | wc -l | tr -d ' ')"
  if [ "$logs" -lt 2 ]; then
    fail "expected retained sidecar logs under $session_path/runs, got $logs"
  fi
}

assert_sidecars_absent_or_empty() {
  session_path="$1"
  if [ ! -d "$session_path/runs" ]; then
    return
  fi
  logs="$(find "$session_path/runs" -type f -name '*.log' | wc -l | tr -d ' ')"
  if [ "$logs" -ne 0 ]; then
    fail "expected lean scan to remove sidecar logs, got $logs under $session_path/runs"
  fi
}

dynamic_tools="security-headers,graphql-introspection,openapi-discovery,js-secret-scan,cors-check,reflected-xss-check,sqli-check,open-redirect-check,upload-check,csrf-check,weak-session-check,xxe-fuzz"
audit_tools="audit/authmiddleware,audit/idor,audit/depconfusion"
combined_tools="$audit_tools,$dynamic_tools"
fixture_routes="/api/search?q=test,/redirect?url=/,/upload,/csrf,/weak-session,/xxe"

target="${NOX_INTEGRATION_TARGET:-}"
if [ -z "$target" ]; then
  : >"$fixture_log"
  NOX_FIXTURE_ADDR="${NOX_FIXTURE_ADDR:-127.0.0.1:18081}" go run ./scripts/vulnerable-fixture >"$fixture_log" 2>&1 &
  fixture_pid="$!"
  target="http://${NOX_FIXTURE_ADDR:-127.0.0.1:18081}"
  i=0
  until curl -fsS "$target" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 30 ]; then
      fail "fixture did not become ready at $target"
    fi
    sleep 1
  done
fi

dynamic_dir="$root_dir/dynamic"
mkdir -p "$dynamic_dir"
NOX_SESSION_DIR="$dynamic_dir" go run . scan --target "$target" --tools "$dynamic_tools" --route-seeds "$fixture_routes" --no-llm --config /dev/null >"$dynamic_log" 2>&1
dynamic_session="$(session_id_for "$dynamic_dir")"
dynamic_db="$(session_db_for "$dynamic_dir" "$dynamic_session")"
assert_completed_session "$dynamic_db"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'security-headers';" 3 "security header findings"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'graphql-introspection';" 1 "GraphQL finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'openapi-discovery';" 1 "OpenAPI finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'js-secret-scan';" 1 "JavaScript secret finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'cors-check';" 1 "CORS finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'reflected-xss-check' AND status = 'confirmed';" 1 "reflected XSS validator finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'sqli-check';" 1 "SQLi validator finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'open-redirect-check' AND status = 'confirmed';" 1 "open redirect validator finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'upload-check';" 1 "upload validator finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'csrf-check';" 1 "CSRF validator finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'weak-session-check' AND status = 'confirmed';" 1 "weak session validator finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM findings WHERE tool_id = 'xxe-fuzz' AND status = 'confirmed';" 1 "XXE validator finding"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM tool_runs;" 13 "dynamic tool runs"
assert_count_at_least "$dynamic_db" "SELECT COUNT(*) FROM tool_runs WHERE stdout_path != '';" 13 "persisted stdout paths"
assert_sidecars_present "$dynamic_dir/$dynamic_session"
NOX_SESSION_DIR="$dynamic_dir" go run . report "$dynamic_session" --format md --mode technical --config /dev/null --output "$dynamic_report" >>"$dynamic_log" 2>&1
assert_file_contains "$dynamic_report" "Executive Summary" "dynamic report"
assert_file_contains "$dynamic_report" "Tool Coverage" "dynamic report tool coverage"
assert_file_contains "$dynamic_report" "GraphQL introspection is exposed|OpenAPI or Swagger document exposed|Potential secret exposed" "dynamic report findings"

lean_dir="$root_dir/lean"
mkdir -p "$lean_dir"
NOX_SESSION_DIR="$lean_dir" go run . scan --target "$target" --tools "$dynamic_tools" --route-seeds "$fixture_routes" --lean --no-llm --config /dev/null >"$lean_log" 2>&1
lean_session="$(session_id_for "$lean_dir")"
lean_db="$(session_db_for "$lean_dir" "$lean_session")"
assert_completed_session "$lean_db"
assert_count_at_least "$lean_db" "SELECT COUNT(*) FROM findings;" 1 "lean findings"
assert_count_at_least "$lean_db" "SELECT COUNT(*) FROM tool_runs;" 11 "lean tool runs"
assert_count_equals "$lean_db" "SELECT COUNT(*) FROM tool_runs WHERE stdout_path != '' OR stderr_path != '';" 0 "lean persisted log paths"
assert_sidecars_absent_or_empty "$lean_dir/$lean_session"

audit_dir="$root_dir/audit"
mkdir -p "$audit_dir"
NOX_SESSION_DIR="$audit_dir" go run . audit ./scripts/vulnerable-fixture --tools "$audit_tools" --no-llm --format sarif --output "$audit_sarif" --config /dev/null >"$audit_log" 2>&1
audit_session="$(session_id_for "$audit_dir")"
audit_db="$(session_db_for "$audit_dir" "$audit_session")"
assert_completed_session "$audit_db"
assert_count_at_least "$audit_db" "SELECT COUNT(*) FROM source_findings WHERE kind IN ('route', 'parameter', 'secret', 'ssrf_sink', 'file_upload', 'sql_sink');" 6 "source findings"
assert_count_at_least "$audit_db" "SELECT COUNT(*) FROM findings WHERE tool_id LIKE 'audit/%';" 2 "audit findings"
assert_count_at_least "$audit_db" "SELECT COUNT(*) FROM tool_runs WHERE tool_id LIKE 'audit/%';" 3 "audit tool runs"
assert_sidecars_present "$audit_dir/$audit_session"
assert_file_contains "$audit_sarif" '"version"[[:space:]]*:[[:space:]]*"2.1.0"' "audit SARIF"
assert_file_contains "$audit_sarif" 'audit/' "audit SARIF rules"

combined_dir="$root_dir/combined"
mkdir -p "$combined_dir"
NOX_SESSION_DIR="$combined_dir" go run . scan --target "$target" --source ./scripts/vulnerable-fixture --tools "$combined_tools" --route-seeds "$fixture_routes" --no-llm --config /dev/null >"$combined_log" 2>&1
combined_session="$(session_id_for "$combined_dir")"
combined_db="$(session_db_for "$combined_dir" "$combined_session")"
assert_completed_session "$combined_db"
assert_count_at_least "$combined_db" "SELECT COUNT(*) FROM source_findings;" 6 "combined source findings"
assert_count_at_least "$combined_db" "SELECT COUNT(*) FROM findings WHERE tool_id LIKE 'audit/%';" 2 "combined audit findings"
assert_count_at_least "$combined_db" "SELECT COUNT(*) FROM findings WHERE tool_id NOT LIKE 'audit/%';" 5 "combined dynamic findings"
assert_count_at_least "$combined_db" "SELECT COUNT(*) FROM attack_graph_edges WHERE relation = 'confirms';" 1 "combined confirmation edges"
assert_count_at_least "$combined_db" "SELECT COUNT(*) FROM source_findings WHERE confirmed_by_dynamic = 1;" 1 "confirmed source findings"
assert_sidecars_present "$combined_dir/$combined_session"
NOX_SESSION_DIR="$combined_dir" go run . report "$combined_session" --format md --mode technical --config /dev/null --output "$combined_report" >>"$combined_log" 2>&1
assert_file_contains "$combined_report" "Static Source Findings" "combined report source section"
assert_file_contains "$combined_report" "Cross-Confirmed Findings" "combined report confirmation section"
assert_file_contains "$combined_report" "Tool Coverage" "combined report tool coverage"

minimal_combined_dir="$root_dir/combined-minimal"
mkdir -p "$minimal_combined_dir"
NOX_SESSION_DIR="$minimal_combined_dir" go run . scan --target "$target" --source ./scripts/vulnerable-fixture --phases recon --tools http-probe --no-llm --config /dev/null >>"$combined_log" 2>&1
minimal_combined_session="$(session_id_for "$minimal_combined_dir")"
minimal_combined_db="$(session_db_for "$minimal_combined_dir" "$minimal_combined_session")"
assert_completed_session "$minimal_combined_db"
assert_count_at_least "$minimal_combined_db" "SELECT COUNT(*) FROM source_findings;" 6 "minimal combined source findings"
assert_count_at_least "$minimal_combined_db" "SELECT COUNT(*) FROM tool_runs WHERE tool_id = 'http-probe';" 1 "minimal combined http-probe run"

echo "Integration smoke passed"
echo "dynamic session: $dynamic_session"
echo "lean session: $lean_session"
echo "audit session: $audit_session"
echo "combined session: $combined_session"
