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
await visit("power", `/sessions/${sessionID}/power`, "Power Features");
await page.getByRole("button", { name: "credentials" }).click();
if (!(await page.locator("text=Credential Testing").isVisible())) {
  throw new Error("Power credentials tab did not render");
}
await page.screenshot({ path: `${screenshotDir}/nyx-browser-power-credentials.png`, fullPage: false });
await page.getByRole("button", { name: "callbacks" }).click();
if (!(await page.locator("text=Callback Evidence").isVisible())) {
  throw new Error("Power callbacks tab did not render");
}
await visit("findings", `/sessions/${sessionID}/findings`, "Findings");
await visit("graph", `/sessions/${sessionID}/graph`, "Attack Paths");
await visit("reports", `/sessions/${sessionID}/report`, "Reports");

await page.setViewportSize({ width: 390, height: 844 });
await visit("mobile-power", `/sessions/${sessionID}/power`, "Power Features");

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
