#!/usr/bin/env sh
set -eu

if [ "${NYX_RUN_BROWSER_SMOKE:-}" != "1" ]; then
  echo "Browser smoke is opt-in. Set NYX_RUN_BROWSER_SMOKE=1 to run it."
  exit 0
fi

if ! command -v npx >/dev/null 2>&1; then
  echo "npx is required for browser smoke" >&2
  exit 1
fi

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
root_dir="$(mktemp -d)"
fixture_log="/tmp/nyx-browser-fixture.log"
scan_log="/tmp/nyx-browser-scan.log"
serve_log="/tmp/nyx-browser-serve.log"
script_path="$repo_root/web/.tmp-browser-smoke.mjs"
fixture_pid=""
serve_pid=""
port="${NYX_BROWSER_SMOKE_PORT:-16768}"

cleanup() {
  if [ -n "$serve_pid" ]; then
    kill "$serve_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$fixture_pid" ]; then
    kill "$fixture_pid" >/dev/null 2>&1 || true
  fi
  if [ "${NYX_KEEP_BROWSER_SMOKE_ARTIFACTS:-}" != "1" ]; then
    rm -rf "$root_dir"
  else
    echo "Keeping browser smoke sessions under $root_dir"
  fi
  rm -f "$script_path"
}
trap cleanup EXIT INT TERM

fail() {
  echo "Browser smoke failed: $*" >&2
  for artifact in "$fixture_log" "$scan_log" "$serve_log"; do
    if [ -s "$artifact" ]; then
      echo "----- $artifact -----" >&2
      sed -n '1,220p' "$artifact" >&2 || true
    fi
  done
  exit 1
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

fixture_addr="${NYX_FIXTURE_ADDR:-127.0.0.1:18083}"
target="http://$fixture_addr"
: >"$fixture_log"
NYX_FIXTURE_ADDR="$fixture_addr" go run ./scripts/vulnerable-fixture >"$fixture_log" 2>&1 &
fixture_pid="$!"
i=0
until curl -fsS "$target" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 30 ]; then
    fail "fixture did not become ready at $target"
  fi
  sleep 1
done

session_dir="$root_dir/sessions"
mkdir -p "$session_dir"
NYX_SESSION_DIR="$session_dir" go run . scan --target "$target" --tools security-headers,graphql-introspection,openapi-discovery,js-secret-scan,cors-check --no-llm --config /dev/null >"$scan_log" 2>&1
session_id="$(session_id_for "$session_dir")"
python3 - "$session_dir/$session_id/session.db" "$session_id" <<'PY'
import sqlite3
import sys
import json

db_path, session_id = sys.argv[1], sys.argv[2]
conn = sqlite3.connect(db_path)
finding_row = conn.execute("SELECT id FROM findings ORDER BY created_at ASC LIMIT 1").fetchone()
finding_id = finding_row[0] if finding_row else None
target_row = conn.execute("SELECT id FROM targets ORDER BY created_at ASC LIMIT 1").fetchone()
target_id = target_row[0] if target_row else None
conn.execute(
    """
    INSERT OR REPLACE INTO cve_matches (
        id, session_id, finding_id, technology_id, cve_id, cvss_v3_score,
        cvss_v3_vector, description, package_name, package_version,
        affected_version, fixed_version, patch_available, exploit_available,
        "references", source, confidence_score
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    (
        "browser-smoke-cve",
        session_id,
        finding_id,
        None,
        "CVE-2026-12345",
        9.8,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Browser smoke dependency CVE with a fixed version and known exploit signal.",
        "openssl",
        "3.0.1",
        "<3.0.9",
        "3.0.9",
        1,
        1,
        '["https://nvd.nist.gov/vuln/detail/CVE-2026-12345"]',
        "source-audit/grype",
        0.95,
    ),
)
messages = [
    {"role": "system", "content": "System prompt"},
    {"role": "user", "content": "Session context JSON:{\"hidden\":true}"},
    {"role": "user", "content": "Summarize the completed scan."},
    {
        "role": "assistant",
        "content": "The strongest report candidate is the missing security headers finding. Treat it as advisory until the operator confirms remediation priority.",
        "tool_calls": [{
            "id": "call-findings",
            "name": "get_session_findings",
            "arguments": "{}",
            "result": json.dumps([
                {"id": finding_id or "finding-1", "session_id": session_id, "severity": "medium", "title": "Missing security headers"}
            ]),
        }],
    },
]
conn.execute(
    """
    INSERT OR REPLACE INTO llm_analyses (
        id, session_id, model_id, prompt_summary, messages, total_tokens, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """,
    (
        "browser-smoke-llm",
        session_id,
        "fixture-model",
        "Summarize the completed scan.",
        json.dumps(messages),
        4096,
    ),
)
conn.execute(
    """
    INSERT OR REPLACE INTO payloads (
        id, finding_id, session_id, payload_type, payload, context, target_waf,
        target_db, bypass_technique, confidence, validated, validated_response,
        rank, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """,
    (
        "browser-smoke-payload",
        finding_id,
        session_id,
        "xss",
        "<script>nyx_marker()</script>",
        "reflected marker",
        "",
        "",
        "marker-only",
        0.72,
        0,
        "",
        1,
    ),
)
conn.execute(
    """
    INSERT OR REPLACE INTO credential_findings (
        id, session_id, target_id, finding_id, credential_type, username, password,
        service, url, valid, lockout_detected, evidence, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    """,
    (
        "browser-smoke-credential",
        session_id,
        target_id,
        finding_id,
        "defaults",
        "admin",
        "********",
        "web",
        "http://127.0.0.1:18083/login",
        1,
        0,
        "Default credential accepted in fixture profile.",
    ),
)
for provider, status, message in [
    ("github", "ok", "token works"),
    ("shodan", "skipped", "missing token"),
    ("securitytrails", "error", "quota exhausted"),
]:
    conn.execute(
        """
        INSERT OR REPLACE INTO provider_statuses (
            id, session_id, provider, module, status, message, metadata, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (f"browser-smoke-provider-{provider}", session_id, provider, "power-smoke", status, message, "{}"),
    )
conn.execute(
    """
    INSERT OR REPLACE INTO power_callbacks (
        id, session_id, finding_id, provider, token, url, source_ip, raw_event,
        received, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    """,
    (
        "browser-smoke-callback",
        session_id,
        finding_id,
        "builtin",
        "tok-browser-smoke",
        "http://127.0.0.1:6767/api/sessions/callbacks/tok-browser-smoke",
        "127.0.0.1",
        "GET /callback?token=secret HTTP/1.1\r\nAuthorization: Bearer hidden\r\nCookie: session=private\r\n\r\n",
        1,
    ),
)
for event_id, status_code, signal, backoff_ms, created_at in [
    ("browser-smoke-block-waf", 403, "waf block", 0, "2026-06-05T12:00:00Z"),
    ("browser-smoke-block-rate", 429, "rate limit", 5000, "2026-06-05T12:05:00Z"),
]:
    conn.execute(
        """
        INSERT OR REPLACE INTO block_events (
            id, session_id, target_id, tool_id, url, status_code, signal,
            response_snippet, backoff_ms, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (event_id, session_id, target_id, "http-probe", "http://127.0.0.1:18083/login", status_code, signal, "blocked by fixture", backoff_ms, created_at),
    )
conn.execute(
    """
    INSERT OR REPLACE INTO poc_results (
        id, session_id, finding_id, target_id, poc_type, status, payload_id,
        request_raw, response_raw, response_code, response_time_ms, evidence,
        canary_token, callback_received, impact_narrative, created_at, completed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    """,
    (
        "browser-smoke-poc",
        session_id,
        finding_id,
        target_id,
        "marker-validation",
        "recorded",
        "browser-smoke-payload",
        "",
        "",
        200,
        12,
        "Marker reflected in fixture response.",
        "",
        0,
        "Demonstrates non-destructive marker evidence.",
    ),
)
conn.commit()
conn.close()
PY

: >"$serve_log"
NYX_SESSION_DIR="$session_dir" go run . serve --host 127.0.0.1 --port "$port" --config /dev/null >"$serve_log" 2>&1 &
serve_pid="$!"
i=0
until curl -fsS "http://127.0.0.1:$port/api/health" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 40 ]; then
    fail "nyx serve did not become ready on port $port"
  fi
  sleep 1
done

python3 - "$root_dir/nyx-state.db" "$session_id" <<'PY'
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

db_path, session_id = sys.argv[1], sys.argv[2]
now = datetime.now(timezone.utc)
fmt = lambda value: value.isoformat().replace("+00:00", "Z")
conn = sqlite3.connect(db_path)
conn.execute(
    """
    INSERT OR REPLACE INTO monitor_configs (
        id, name, target_input, in_scope, out_of_scope, schedule, enabled_phases,
        enabled_tools, tool_parameters, runner_options, alert_on,
        notification_config, baseline_session_id, last_run_at, next_run_at,
        enabled, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    (
        "browser-monitor-config",
        "Fixture Monitor",
        "http://127.0.0.1:18083",
        json.dumps(["127.0.0.1"]),
        json.dumps([]),
        "@daily",
        json.dumps(["recon", "fingerprint", "vuln_scan"]),
        json.dumps(["security-headers"]),
        json.dumps({}),
        json.dumps({"per_tool_concurrency": 1}),
        json.dumps(["new_finding", "finding_severity_changed", "resolved_finding"]),
        json.dumps({}),
        "baseline-session",
        fmt(now - timedelta(hours=2)),
        fmt(now - timedelta(hours=25)),
        1,
        fmt(now - timedelta(days=3)),
        fmt(now),
    ),
)
runs = [
    ("browser-monitor-run-old", "old-session", now - timedelta(days=2), now - timedelta(days=2, minutes=-8)),
    ("browser-monitor-run-mid", "mid-session", now - timedelta(days=1), now - timedelta(days=1, minutes=-7)),
    ("browser-monitor-run-new", session_id, now - timedelta(hours=2), now - timedelta(hours=2, minutes=-6)),
]
for run_id, run_session, started, completed in runs:
    conn.execute(
        """
        INSERT OR REPLACE INTO monitor_runs (
            id, config_id, session_id, status, changes_found, error, started_at, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, "browser-monitor-config", run_session, "completed", 1, "", fmt(started), fmt(completed)),
    )
changes = [
    ("change-old-low", "browser-monitor-run-old", "new_finding", "low", "New finding: Missing security headers", "", "Missing security headers @ http://127.0.0.1:18083"),
    ("change-mid-medium", "browser-monitor-run-mid", "finding_severity_changed", "medium", "Finding severity changed: Missing security headers", "low", "medium"),
    ("change-new-finding", "browser-monitor-run-new", "new_finding", "high", "New finding: Reflected input exposure", "", "Reflected input exposure @ http://127.0.0.1:18083/search"),
    ("change-resolved-finding", "browser-monitor-run-new", "resolved_finding", "info", "Finding no longer observed: Verbose banner", "Verbose banner @ http://127.0.0.1:18083", ""),
    ("change-severity", "browser-monitor-run-new", "finding_severity_changed", "critical", "Finding severity changed: Missing security headers", "medium", "critical"),
    ("change-technology", "browser-monitor-run-new", "new_technology", "low", "New technology detected: fixture-app", "", "fixture-app 1.1.0"),
    ("change-gone", "browser-monitor-run-new", "resolved_service", "info", "Previously observed surface is no longer present: http://127.0.0.1:8080", "http://127.0.0.1:8080", ""),
]
for change_id, run_id, change_type, severity, description, previous, current in changes:
    conn.execute(
        """
        INSERT OR REPLACE INTO surface_changes (
            id, monitor_run_id, session_id, change_type, severity, description,
            previous_value, current_value, target_id, finding_id, alerted, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (change_id, run_id, session_id, change_type, severity, description, previous, current, "", "", 0, fmt(now)),
    )
conn.commit()
conn.close()
PY

cat >"$script_path" <<'JS'
import { chromium } from "playwright";
import { writeFile } from "node:fs/promises";

const baseURL = process.env.NYX_BROWSER_SMOKE_BASE_URL;
const sessionID = process.env.NYX_BROWSER_SMOKE_SESSION_ID;
const screenshotDir = process.env.NYX_BROWSER_SMOKE_SCREENSHOT_DIR || "/tmp";
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
const consoleErrors = [];
page.on("console", (message) => {
  if (message.type() === "error") {
    const text = message.text();
    if (
      text === "Failed to load resource: the server responded with a status of 404 (Not Found)" ||
      /^WebSocket connection to 'ws:\/\/[^']+\/api\/scan\/[^/]+\/events' failed: Error during WebSocket handshake: Unexpected response code: 404$/.test(text)
    ) {
      return;
    }
    const location = message.location();
    const suffix = location.url ? ` (${location.url}:${location.lineNumber || 0})` : "";
    consoleErrors.push(`${text}${suffix}`);
  }
});
page.on("pageerror", (error) => consoleErrors.push(error.message));

async function visit(name, path, expectedText) {
  await page.goto(`${baseURL}${path}`, { waitUntil: "networkidle" });
  const body = await page.locator("body").innerText();
  if (!body.includes(expectedText)) {
    throw new Error(`${name} did not render expected text: ${expectedText}`);
  }
  if (/Checking API access|Loading$/.test(body.trim())) {
    throw new Error(`${name} stayed in a loading state`);
  }
  await page.screenshot({ path: `${screenshotDir}/nyx-browser-${name}.png`, fullPage: false });
}

await visit("dashboard", `/sessions/${sessionID}`, "Command Center");
if (!(await page.locator("text=Last Completed Scan").isVisible())) {
  throw new Error("Dashboard last completed scan summary did not render");
}
await page.locator("text=Latest Phase Progress").scrollIntoViewIfNeeded();
if (!(await page.locator("text=Tool pipeline details").isVisible())) {
  throw new Error("Dashboard collapsed tool pipeline details did not render");
}
const dashboardTerminalOpen = await page.locator("details.terminal-feed").evaluate((element) => element.hasAttribute("open"));
if (dashboardTerminalOpen) {
  throw new Error("Dashboard terminal feed should be collapsed for completed sessions");
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-dashboard-progress.png`, fullPage: false });
await visit("monitor", "/monitor", "Attack Surface Monitor");
const monitorPageText = (await page.locator("body").innerText()).toLowerCase();
for (const expected of [
  "Scheduler runs only while nyx serve is active.",
  "Last Successful Run",
  "likely missed while offline",
  "Severity Trend",
  "Reset Baseline",
  "New Findings",
  "Resolved Findings",
  "Severity Changes",
  "New Technologies",
  "Disappeared Endpoints",
  "Before",
  "After",
]) {
  if (!monitorPageText.includes(expected.toLowerCase())) {
    throw new Error(`Monitor workspace did not render ${expected}`);
  }
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-monitor-workspace.png`, fullPage: false });
await page.locator(".surface-change-groups").scrollIntoViewIfNeeded();
await page.screenshot({ path: `${screenshotDir}/nyx-browser-monitor-surface-diff.png`, fullPage: false });
await visit("scan-builder", "/scan", "Scan Builder");
await page.getByLabel("Preset").selectOption({ label: "Web app active" });
await page.getByRole("button", { name: "Load Profile" }).click();
await page.locator("label:has-text('Targets') textarea").first().fill("http://127.0.0.1:18083");
await page.locator("label:has-text('Seed Routes') textarea").fill("/login\n/api/search?q=test\n/profile?id=1");
await page.locator("label:has-text('Auth Profile JSON') textarea").fill(JSON.stringify({
  type: "form",
  login_url: "/login",
  username: "demo",
  password: "demo",
  csrf_field: "csrf",
  validation_url: "/profile"
}, null, 2));
await page.locator("text=3 route seeds").scrollIntoViewIfNeeded();
if (!(await page.locator("text=Auth profile").first().isVisible())) {
  throw new Error("Scan Builder auth profile feedback did not render");
}
await page.locator("text=Active validation").scrollIntoViewIfNeeded();
const launchReviewText = await page.locator(".launch-review").innerText();
for (const expected of ["http://127.0.0.1:18083", "form login profile", "3 seeded routes", "Active validators"]) {
  if (!launchReviewText.includes(expected)) {
    throw new Error(`Scan Builder launch review missed ${expected}`);
  }
}
if (!(await page.locator(".tool-check.available").first().isVisible())) {
  throw new Error("Scan Builder did not show installed built-in tool state");
}
if (!(await page.locator(".tool-check.missing").first().isVisible())) {
  throw new Error("Scan Builder did not show missing tool state");
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-scan-builder-review.png`, fullPage: false });
await visit("power", `/sessions/${sessionID}/power`, "Power Features");
const powerPageText = await page.locator("body").innerText();
for (const expected of ["Provider status", "Payload Operations", "Credential Operations", "AD/BloodHound", "Burp Integration", "github", "shodan", "securitytrails"]) {
  if (!powerPageText.toLowerCase().includes(expected.toLowerCase())) {
    throw new Error(`Power workspace did not render ${expected}`);
  }
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-power-status-groups.png`, fullPage: false });
await page.getByRole("button", { name: "credentials" }).click();
if (!(await page.locator("text=Credential Testing").isVisible())) {
  throw new Error("Power credentials tab did not render");
}
if (!(await page.locator("text=[REDACTED]").first().isVisible())) {
  throw new Error("Power credential table did not use consistent redaction display");
}
await page.locator("input[placeholder='Login URL for confirmed checks']").fill("http://127.0.0.1:18083/login");
await page.getByRole("button", { name: "Review Run" }).click();
for (const expected of ["Credential Check Review", "Potential impact", "account lockout", "Max Attempts"]) {
  if (!(await page.locator(`text=${expected}`).first().isVisible())) {
    throw new Error(`Power active credential review did not render ${expected}`);
  }
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-power-credentials.png`, fullPage: false });
await page.getByRole("button", { name: "Cancel" }).click();
await page.getByRole("button", { name: "PoC Evidence" }).click();
await page.getByRole("button", { name: "Review PoC" }).click();
for (const expected of ["PoC Evidence Review", "outbound callback", "Callback Provider", "re-checked before the marker request"]) {
  if (!(await page.locator(`text=${expected}`).first().isVisible())) {
    throw new Error(`Power PoC review did not render ${expected}`);
  }
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-power-poc-review.png`, fullPage: false });
await page.getByRole("button", { name: "Cancel" }).click();
await page.getByRole("button", { name: "callbacks" }).click();
if (!(await page.locator("text=Callback Evidence").isVisible())) {
  throw new Error("Power callbacks tab did not render");
}
if (await page.locator("text=hidden").isVisible()) {
  throw new Error("Power callback table exposed bearer token text");
}
await page.getByRole("button", { name: "Request Behavior" }).click();
if (!(await page.locator("text=visible events").isVisible())) {
  throw new Error("Power evasion filter summary did not render");
}
await page.locator(".evasion-filter-bar label:has-text('Type') select").selectOption("rate_limit");
if (!(await page.locator("tbody", { hasText: "Rate limit" }).isVisible())) {
  throw new Error("Power evasion type filter did not show rate limit event");
}
await page.locator(".panel", { hasText: "Request Behavior" }).screenshot({ path: `${screenshotDir}/nyx-browser-power-evasion-filters.png` });
await visit("tools", `/sessions/${sessionID}/tools`, "Tools");
const toolsPageText = await page.locator("body").innerText();
for (const expected of ["Compact Table", "Tool Details", "Status", "Tool", "Phase", "Version", "Path", "Last Run"]) {
  if (!toolsPageText.toLowerCase().includes(expected.toLowerCase())) {
    throw new Error(`Tool inventory did not render ${expected}`);
  }
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-tools-table.png`, fullPage: false });
await page.getByRole("button", { name: "Cards" }).click();
if (!(await page.locator("text=Tool Cards").isVisible())) {
  throw new Error("Tool inventory card mode did not render");
}
await page.locator(".tool-card-list").screenshot({ path: `${screenshotDir}/nyx-browser-tools-cards.png` });
await visit("settings", "/settings", "System Health");
await page.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin: baseURL });
for (const expected of ["Effective Config", "Copy Sanitized Config", "Raw effective config"]) {
  if (!(await page.locator(`text=${expected}`).first().isVisible())) {
    throw new Error(`Settings did not render ${expected}`);
  }
}
await page.getByRole("button", { name: "Copy Sanitized Config" }).click();
await page.getByRole("button", { name: "Copied Config" }).waitFor({ state: "visible", timeout: 2000 });
await page.locator("summary", { hasText: "Raw effective config" }).click();
const copiedConfig = await page.evaluate(() => navigator.clipboard.readText());
if (copiedConfig.includes("secret-key") || copiedConfig.includes("session=private")) {
  throw new Error("Settings copied config exposed a secret-shaped value");
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-settings-copy-config.png`, fullPage: false });
await visit("findings", `/sessions/${sessionID}/findings`, "Findings");
for (const expected of ["Category", "Tool", "Confidence", "Suppression", "Suppress Selected", "Export Selected"]) {
  if (!(await page.locator(`text=${expected}`).first().isVisible())) {
    throw new Error(`Findings triage control did not render: ${expected}`);
  }
}
await page.keyboard.press("Escape");
if (await page.locator("aside[aria-label='Finding details']").isVisible()) {
  throw new Error("Finding detail pane did not close with Escape");
}
const firstFindingRow = page.getByRole("button", { name: /Open finding details for/ }).first();
await firstFindingRow.focus();
await page.keyboard.press("Enter");
const detailPane = page.locator("aside[aria-label='Finding details']");
await detailPane.waitFor({ state: "visible" });
const activeLabel = await page.evaluate(() => document.activeElement?.getAttribute("aria-label") || "");
if (activeLabel !== "Finding details") {
  throw new Error(`Finding detail pane did not receive focus, active label: ${activeLabel}`);
}
if (!(await detailPane.locator("text=Evidence Confidence").isVisible())) {
  throw new Error("Finding detail did not surface evidence confidence above tabs");
}
if (!(await detailPane.locator("text=Attack Path Usage").isVisible())) {
  throw new Error("Finding detail did not surface attack path usage links");
}
await detailPane.getByLabel("Status").selectOption("suppressed");
await detailPane.getByRole("button", { name: "Save Changes" }).click();
await detailPane.locator(".triage-audit-trail li", { hasText: "suppressed" }).waitFor({ state: "visible", timeout: 2500 });
await page.screenshot({ path: `${screenshotDir}/nyx-browser-findings-triage.png`, fullPage: false });
await detailPane.locator(".triage-audit-trail").scrollIntoViewIfNeeded();
await page.screenshot({ path: `${screenshotDir}/nyx-browser-findings-audit.png`, fullPage: false });
await page.getByRole("tab", { name: "Normalized" }).focus();
await page.keyboard.press("ArrowRight");
const rawSelected = await page.getByRole("tab", { name: "Raw" }).getAttribute("aria-selected");
if (rawSelected !== "true") {
  throw new Error("Evidence tab arrow navigation did not select Raw");
}
await page.getByRole("button", { name: "Copy Evidence" }).click();
try {
  await page.getByRole("button", { name: "Copied" }).waitFor({ state: "visible", timeout: 1500 });
} catch {
  throw new Error("Copy Evidence button did not enter copied state");
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-findings-keyboard.png`, fullPage: false });
await visit("graph", `/sessions/${sessionID}/graph`, "Attack Paths");
await page.locator(".attack-flow-node.finding").first().click({ force: true });
if (!(await page.getByRole("button", { name: "View Finding" }).isVisible())) {
  throw new Error("Attack graph node detail did not expose View Finding");
}
await page.getByRole("button", { name: "View Finding" }).click();
if (!page.url().includes("/findings?")) {
  throw new Error("Attack graph View Finding did not navigate to findings triage");
}
await page.locator("aside[aria-label='Finding details']").waitFor({ state: "visible" });
if (!(await page.locator("text=Back to Attack Chain").isVisible())) {
  throw new Error("Findings triage did not preserve return link to attack chain");
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-graph-to-finding.png`, fullPage: false });
await visit("cves", `/sessions/${sessionID}/cves`, "CVE Intelligence");
const cvePageText = await page.locator("body").innerText();
for (const expected of ["CVE-2026-12345", "Dependency audit", "openssl@3.0.1", "Affected <3.0.9", "3.0.9", "Known", "Vector"]) {
  if (!cvePageText.includes(expected)) {
    throw new Error(`CVE table did not render ${expected}`);
  }
}
await page.locator(".cve-filter-bar label:has-text('Package') select").selectOption("openssl@3.0.1");
await page.locator(".cve-filter-bar label:has-text('Fixability') select").selectOption("fixable");
await page.locator(".cve-filter-bar label:has-text('Exploitability') select").selectOption("exploitable");
if (!(await page.locator("tbody", { hasText: "CVE-2026-12345" }).isVisible())) {
  throw new Error("CVE table filters hid the expected fixable exploitable row");
}
await page.getByRole("button", { name: "Copy CVE-2026-12345" }).click();
try {
  await page.locator(".cve-id-cell button").first().locator("svg").waitFor({ state: "visible", timeout: 1500 });
} catch {
  throw new Error("CVE ID copy action did not remain interactive");
}
await page.getByRole("button", { name: "Vector" }).click();
await page.screenshot({ path: `${screenshotDir}/nyx-browser-cves-table.png`, fullPage: false });
await visit("llm", `/sessions/${sessionID}/llm`, "Analyst");
for (const expected of ["Suggested Prompts", "Context Summary", "Approx. usage", "Fetched 1 findings from session", "Pin to Report"]) {
  if (!(await page.locator(`text=${expected}`).first().isVisible())) {
    throw new Error(`LLM Analyst did not render ${expected}`);
  }
}
await page.getByRole("button", { name: "Pin to Report" }).click();
if (!(await page.getByRole("button", { name: "Pinned" }).isVisible())) {
  throw new Error("LLM Analyst pin action did not enter pinned state");
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-llm-analyst.png`, fullPage: false });
await page.getByRole("button", { name: "New Analysis" }).click();
if (!(await page.locator("text=prior messages kept in audit history").isVisible())) {
  throw new Error("LLM Analyst new analysis did not preserve prior audit history");
}
if (!(await page.locator("text=Fresh Analysis Context").isVisible())) {
  throw new Error("LLM Analyst reset state did not show fresh context copy");
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-llm-context-reset.png`, fullPage: false });
await visit("reports", `/sessions/${sessionID}/report`, "Reports");
if (!(await page.locator("text=Pinned Analyst Notes").isVisible())) {
  throw new Error("Report Composer did not surface pinned analyst notes");
}
for (const expected of ["Custom Executive Summary Intro", "Findings Section Preview", "HTML previews in browser", "Include suppressed/dismissed appendix"]) {
  if (!(await page.locator(`text=${expected}`).first().isVisible())) {
    throw new Error(`Report Composer did not render ${expected}`);
  }
}
await page.locator("label:has-text('Custom Executive Summary Intro') textarea").fill("Operator-written executive intro for the client report.");
await page.frameLocator("iframe[title='Report preview']").locator("text=Operator-written executive intro for the client report.").waitFor({ state: "visible", timeout: 5000 });
await page.screenshot({ path: `${screenshotDir}/nyx-browser-report-composer.png`, fullPage: false });
await page.locator(".report-preview").scrollIntoViewIfNeeded();
await page.locator("iframe[title='Report preview']").screenshot({ path: `${screenshotDir}/nyx-browser-report-html-preview.png` });
await page.locator(".report-config-panel").scrollIntoViewIfNeeded();
await page.locator("label:has-text('Format') select").selectOption("md");
await page.locator(".report-preview pre", { hasText: "Operator-written executive intro for the client report." }).waitFor({ state: "visible", timeout: 5000 });
await page.locator(".report-preview").scrollIntoViewIfNeeded();
await page.screenshot({ path: `${screenshotDir}/nyx-browser-report-markdown-preview.png`, fullPage: false });
await page.locator("label:has-text('Format') select").selectOption("sarif");
if ((await page.locator("text=SARIF is designed for CI/CD and code-scanning import, not human reading.").count()) < 1) {
  throw new Error("Report Composer did not explain SARIF as machine-readable output");
}
await page.locator(".report-config-panel").scrollIntoViewIfNeeded();
await page.screenshot({ path: `${screenshotDir}/nyx-browser-report-sarif-note.png`, fullPage: false });
await page.screenshot({ path: `${screenshotDir}/nyx-browser-report-pins.png`, fullPage: false });

await page.setViewportSize({ width: 390, height: 844 });
await visit("mobile-power", `/sessions/${sessionID}/power`, "Power Features");
await page.getByRole("button", { name: "Open page actions" }).click();
if (!(await page.getByRole("button", { name: "Refresh session list" }).isVisible())) {
  throw new Error("Mobile page actions did not open");
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-mobile-actions.png`, fullPage: false });
await page.keyboard.press("Escape");
if (await page.getByRole("button", { name: "Refresh session list" }).isVisible()) {
  throw new Error("Mobile page actions did not close with Escape");
}
await page.getByRole("button", { name: "Open navigation" }).click();
if (!(await page.getByRole("navigation", { name: "Primary" }).isVisible())) {
  throw new Error("Mobile navigation did not open");
}
await page.keyboard.press("Escape");
if (await page.getByRole("button", { name: "Close navigation" }).isVisible()) {
  throw new Error("Mobile navigation did not close with Escape");
}

await browser.close();
if (consoleErrors.length) {
  throw new Error(`Console errors observed:\n${consoleErrors.join("\n")}`);
}
await writeFile(`${screenshotDir}/nyx-browser-smoke-summary.txt`, `Browser smoke passed for ${baseURL}/sessions/${sessionID}\n`);
JS

export NYX_BROWSER_SMOKE_BASE_URL="http://127.0.0.1:$port"
export NYX_BROWSER_SMOKE_SESSION_ID="$session_id"
export NYX_BROWSER_SMOKE_SCREENSHOT_DIR="/tmp"
if [ "${NYX_BROWSER_SMOKE_SKIP_INSTALL:-}" != "1" ]; then
  (cd "$repo_root/web" && npx playwright install chromium >/dev/null)
fi

(cd "$repo_root/web" && node "$script_path")

echo "Browser smoke passed"
echo "session: $session_id"
echo "screenshots: /tmp/nyx-browser-*.png"
