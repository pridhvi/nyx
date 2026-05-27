#!/usr/bin/env sh
set -eu

if [ "${NYX_RUN_BENCHMARKS:-}" != "1" ]; then
  echo "Benchmark scans are opt-in. Set NYX_RUN_BENCHMARKS=1 to run them."
  exit 0
fi

benchmark="${1:-all}"
timestamp="$(date +%Y%m%d-%H%M%S)"
artifact_root="${NYX_BENCHMARK_ARTIFACT_DIR:-artifacts/benchmarks/$timestamp}"
sessions_root="$artifact_root/sessions"
mkdir -p "$artifact_root" "$sessions_root"

tools_default="http-probe,security-headers,whatweb,graphql-introspection,openapi-discovery,arjun,linkfinder,js-secret-scan,cors-check,nmap,ffuf,nuclei-tech,nuclei-vuln,nikto,sqlmap,dalfox,brute-force-check,reflected-xss-check,dom-xss-check,stored-xss-check,sqli-check,open-redirect-check,file-inclusion-check,command-injection-check,upload-check,idor-check,workflow-assist,csp-review,csrf-check,weak-session-check,xxe-fuzz"
tools="${NYX_BENCHMARK_TOOLS:-$tools_default}"
scan_timeout="${NYX_BENCHMARK_SCAN_TIMEOUT:-20m}"
go_cmd="${NYX_GO_CMD:-go run .}"
benchmark_path="$HOME/go/bin:$HOME/.local/bin:$HOME/.config/composer/vendor/bin:$PATH"

fail() {
  echo "Benchmark failed: $*" >&2
  echo "Artifacts: $artifact_root" >&2
  exit 1
}

ensure_targets() {
  if [ "${NYX_BENCHMARK_NO_TARGET_UP:-}" = "1" ]; then
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

auth_profile_for() {
  name="$1"
  output="$artifact_root/$name/auth-profile.json"
  python3 - "$name" "$output" <<'PY'
import json
import sys
from pathlib import Path

name = sys.argv[1]
output = Path(sys.argv[2])
profile = json.loads(Path(f"benchmarks/{name}/profile.json").read_text(encoding="utf-8"))
auth = profile.get("auth") or {}
if profile.get("safe_active_checks"):
    auth["safe_active_checks"] = profile["safe_active_checks"]
output.write_text(json.dumps(auth, indent=2) + "\n", encoding="utf-8")
PY
  printf '%s' "$output"
}

setup_benchmark_target() {
  name="$1"
  target_url="$2"
  setup_log="$artifact_root/$name/setup.log"
  python3 - "$name" "$target_url" "$setup_log" <<'PY'
import html
import http.cookiejar
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

name = sys.argv[1]
target_url = sys.argv[2].rstrip("/") + "/"
log_path = Path(sys.argv[3])
log_path.parent.mkdir(parents=True, exist_ok=True)


def log(message: str) -> None:
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(message.rstrip() + "\n")


def absolute(path: str) -> str:
    return urllib.parse.urljoin(target_url, path.lstrip("/"))


jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def reset_session() -> None:
    global jar, opener
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def request(method: str, path: str, *, form=None, json_body=None, headers=None) -> tuple[int, str]:
    payload = None
    req_headers = dict(headers or {})
    if form is not None:
        payload = urllib.parse.urlencode(form).encode("utf-8")
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"
    if json_body is not None:
        payload = json.dumps(json_body).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(absolute(path), data=payload, headers=req_headers, method=method)
    try:
        with opener.open(req, timeout=20) as response:
            body = response.read().decode("utf-8", errors="replace")
            return int(response.status), body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return int(exc.code), body


def csrf_token(body: str) -> str:
    match = re.search(r"name=[\"']user_token[\"'][^>]*value=[\"']([^\"']+)", body, re.I)
    if not match:
        match = re.search(r"value=[\"']([^\"']+)[\"'][^>]*name=[\"']user_token[\"']", body, re.I)
    if not match:
        raise SystemExit("DVWA CSRF token not found during benchmark setup")
    return html.unescape(match.group(1))


def cookie_value(cookie_name: str) -> str:
    for cookie in jar:
        if cookie.name == cookie_name:
            return cookie.value
    return ""


def dvwa_authenticated(body: str) -> bool:
    return "Logout" in body and "Login ::" not in body and "Setup ::" not in body


def dvwa_setup_required(body: str) -> bool:
    return "Database Setup" in body or "Setup DVWA" in body or "Setup ::" in body


def create_dvwa_database() -> None:
    status, setup_page = request("GET", "/setup.php")
    log(f"GET /setup.php status={status}")
    setup_token = csrf_token(setup_page)
    setup_status, setup_body = request(
        "POST",
        "/setup.php",
        form={
            "create_db": "Create / Reset Database",
            "user_token": setup_token,
        },
    )
    log(f"POST /setup.php create_db status={setup_status}")
    if setup_status >= 400 or "Could not" in setup_body:
        raise SystemExit(f"DVWA database setup failed with HTTP {setup_status}")


def login_dvwa(label: str) -> str:
    status, login_page = request("GET", "/login.php")
    log(f"GET /login.php {label} status={status}")
    if status >= 400:
        raise SystemExit(f"DVWA login page returned HTTP {status}")
    token = csrf_token(login_page)
    login_status, body = request(
        "POST",
        "/login.php",
        form={
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": token,
        },
    )
    log(f"POST /login.php {label} status={login_status}")
    if login_status >= 400 or "Login failed" in body:
        raise SystemExit(f"DVWA login failed with HTTP {login_status}")
    home_status, home_page = request("GET", "/index.php")
    log(
        f"GET /index.php {label} status={home_status} "
        f"authenticated={dvwa_authenticated(home_page)} setup_required={dvwa_setup_required(body) or dvwa_setup_required(home_page)}"
    )
    return body + "\n" + home_page


def setup_dvwa() -> None:
    log(f"preparing DVWA benchmark at {target_url}")
    try:
        login_body = login_dvwa("initial")
    except SystemExit as exc:
        log(f"initial DVWA login was not ready: {exc}")
        create_dvwa_database()
        reset_session()
        login_body = login_dvwa("after setup")

    if dvwa_setup_required(login_body) or not dvwa_authenticated(login_body):
        log("DVWA login reached setup or unauthenticated page; resetting database and retrying")
        create_dvwa_database()
        reset_session()
        login_body = login_dvwa("after setup")

    if not dvwa_authenticated(login_body):
        raise SystemExit("DVWA login did not reach an authenticated page")

    security_status, security_page = request("GET", "/security.php")
    log(f"GET /security.php status={security_status}")
    security_token = csrf_token(security_page)
    set_status, _ = request(
        "POST",
        "/security.php",
        form={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": security_token,
        },
    )
    log(f"POST /security.php low status={set_status}")
    verify_status, verify_page = request("GET", "/security.php")
    security_cookie = cookie_value("security")
    selected_low = bool(re.search(r"<option[^>]+value=[\"']low[\"'][^>]+selected", verify_page, re.I))
    log(f"GET /security.php verify status={verify_status} security_cookie={security_cookie or 'missing'} selected_low={selected_low}")
    if security_cookie != "low" and not selected_low:
        raise SystemExit("DVWA security level did not verify as low")


def setup_juice_shop() -> None:
    log(f"preparing Juice Shop benchmark at {target_url}")
    email = "nyx-benchmark@example.test"
    password = "NyxBenchmark!12345"
    registration = {
        "email": email,
        "password": password,
        "passwordRepeat": password,
        "securityQuestion": {
            "id": 1,
            "question": "Your eldest siblings middle name?",
            "answer": "nyx",
        },
    }
    status, body = request("POST", "/api/Users/", json_body=registration)
    log(f"POST /api/Users/ status={status}")
    if status not in (200, 201, 400, 409):
        raise SystemExit(f"Juice Shop user registration failed with HTTP {status}: {body[:240]}")
    login_status, login_body = request(
        "POST",
        "/rest/user/login",
        json_body={"email": email, "password": password},
    )
    log(f"POST /rest/user/login status={login_status}")
    if login_status >= 400:
        raise SystemExit(f"Juice Shop benchmark login failed with HTTP {login_status}: {login_body[:240]}")
    try:
        parsed = json.loads(login_body)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Juice Shop login response was not JSON: {exc}") from exc
    token = parsed.get("authentication", {}).get("token")
    if not token:
        raise SystemExit("Juice Shop benchmark login response did not contain authentication.token")


if name == "dvwa":
    setup_dvwa()
elif name == "juice-shop":
    setup_juice_shop()
else:
    log(f"no benchmark setup defined for {name}")
log("benchmark setup completed")
PY
}

target_url_for() {
  name="$1"
  case "$name" in
    dvwa)
      printf '%s' "${NYX_BENCHMARK_DVWA_URL:-http://127.0.0.1:${NYX_BENCHMARK_DVWA_PORT:-18080}}"
      ;;
    juice-shop)
      printf '%s' "${NYX_BENCHMARK_JUICE_URL:-http://127.0.0.1:${NYX_BENCHMARK_JUICE_PORT:-13000}}"
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
  auth_profile="$(auth_profile_for "$name")"
  setup_benchmark_target "$name" "$target_url" || {
    sed -n '1,220p' "$artifact_root/$name/setup.log" >&2 || true
    fail "$name benchmark setup failed"
  }
  echo "Running $name benchmark against $target_url"
  if command -v timeout >/dev/null 2>&1; then
    scan_prefix="timeout $scan_timeout"
  else
    scan_prefix=""
  fi
  if ! $scan_prefix env PATH="$benchmark_path" NYX_SESSION_DIR="$sessions_root" $go_cmd scan \
    --target "$target_url" \
    --tools "$tools" \
    --route-seed-file "benchmarks/$name/routes.txt" \
    --auth-profile "$auth_profile" \
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

  env NYX_SESSION_DIR="$sessions_root" $go_cmd report "$session_id" \
    --format md \
    --mode technical \
    --output "$report_md" \
    --config /dev/null >>"$log" 2>&1 || fail "$name markdown report failed"
  assert_report_artifact "$report_md"

  env NYX_SESSION_DIR="$sessions_root" $go_cmd report "$session_id" \
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
