#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
output_dir="${NYX_README_MEDIA_DIR:-$repo_root/docs/assets/readme}"
root_dir="$(mktemp -d)"
fixture_log="/tmp/nyx-readme-fixture.log"
scan_log="/tmp/nyx-readme-scan.log"
serve_log="/tmp/nyx-readme-serve.log"
script_path="$repo_root/web/.tmp-readme-media.mjs"
fixture_pid=""
serve_pid=""
fixture_port="${NYX_README_FIXTURE_PORT:-18084}"
serve_port="${NYX_README_SERVE_PORT:-16769}"

cleanup() {
  if [ -n "$serve_pid" ]; then
    kill "$serve_pid" >/dev/null 2>&1 || true
  fi
  if [ -n "$fixture_pid" ]; then
    kill "$fixture_pid" >/dev/null 2>&1 || true
  fi
  if [ "${NYX_KEEP_README_MEDIA_ARTIFACTS:-}" != "1" ]; then
    rm -rf "$root_dir"
  else
    echo "Keeping README media sessions under $root_dir"
  fi
  rm -f "$script_path"
}
trap cleanup EXIT INT TERM

fail() {
  echo "README media capture failed: $*" >&2
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

if ! command -v npx >/dev/null 2>&1; then
  fail "npx is required for README media capture"
fi
if ! command -v sqlite3 >/dev/null 2>&1; then
  fail "sqlite3 is required to seed deterministic README demo LLM history"
fi

mkdir -p "$output_dir"
rm -f "$output_dir"/nyx-*.png

fixture_addr="127.0.0.1:$fixture_port"
target="http://localhost:$fixture_port"
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
NYX_SESSION_DIR="$session_dir" go run . scan \
  --target "$target" \
  --tools security-headers,graphql-introspection,openapi-discovery,js-secret-scan,cors-check \
  --route-seeds "/api/search?q=nyx" \
  --no-llm \
  --config /dev/null >"$scan_log" 2>&1 || fail "demo scan failed"
session_id="$(session_id_for "$session_dir")"
session_db="$session_dir/$session_id/session.db"
sqlite3 "$session_db" <<SQL || fail "demo LLM history seed failed"
INSERT INTO llm_analyses (
  id,
  session_id,
  model_id,
  prompt_summary,
  messages,
  total_tokens,
  created_at
) VALUES (
  'readme-demo-analysis',
  '$session_id',
  'demo-analyst',
  'README fixture session summary',
  '[{"role":"user","content":"Summarize the highest-confidence risks and safe next checks."},{"role":"assistant","reasoning_content":"Reviewing normalized findings and tool-run evidence before selecting final summary.","content":"## Risk summary\n\n- **High:** Potential secret exposure was observed in JavaScript at /static/app.js.\n- **Medium:** GraphQL introspection and permissive CORS need owner review.\n- **Next checks:** Confirm whether the exposed token is real, restrict CORS origins, and decide whether API schema exposure is intended.","tool_calls":[{"id":"fixture-context","name":"list_findings","arguments":"{\"severity\":\"high\"}","result":"Returned 1 high finding from the fixture session."}]}]',
  218,
  strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
);
SQL

: >"$serve_log"
NYX_SESSION_DIR="$session_dir" go run . serve --host 127.0.0.1 --port "$serve_port" --config /dev/null >"$serve_log" 2>&1 &
serve_pid="$!"
i=0
until curl -fsS "http://127.0.0.1:$serve_port/api/health" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 40 ]; then
    fail "nyx serve did not become ready on port $serve_port"
  fi
  sleep 1
done

cat >"$script_path" <<'JS'
import { chromium } from "playwright";
import { mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { execFileSync } from "node:child_process";

const baseURL = process.env.NYX_README_MEDIA_BASE_URL;
const sessionID = process.env.NYX_README_MEDIA_SESSION_ID;
const outDir = process.env.NYX_README_MEDIA_OUTPUT_DIR;
await mkdir(outDir, { recursive: true });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 960 } });
const consoleErrors = [];
page.on("console", (message) => {
  if (message.type() !== "error") return;
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
});
page.on("pageerror", (error) => consoleErrors.push(error.message));

async function visit(name, path, expectedText, options = {}) {
  await page.goto(`${baseURL}${path}`, { waitUntil: "networkidle" });
  const body = await page.locator("body").innerText();
  if (!body.includes(expectedText)) {
    throw new Error(`${name} did not render expected text: ${expectedText}`);
  }
  if (/Checking API access|Loading$/.test(body.trim())) {
    throw new Error(`${name} stayed in a loading state`);
  }
  if (options.click) {
    await page.getByRole(options.click.role, { name: options.click.name }).click();
    if (options.click.expectedText && !(await page.locator(`text=${options.click.expectedText}`).isVisible())) {
      throw new Error(`${name} click target did not render ${options.click.expectedText}`);
    }
  }
  await page.screenshot({ path: `${outDir}/nyx-${name}.png`, fullPage: false });
}

await visit("command-center", `/sessions/${sessionID}`, "Command Center");
await visit("scan-builder", "/scan", "Scan Builder");
await visit("findings", `/sessions/${sessionID}/findings`, "Findings");
await visit("tool-runs", `/sessions/${sessionID}/runs`, "Tool Runs");
await visit("reports", `/sessions/${sessionID}/report`, "Reports");
await visit("llm-analyst", `/sessions/${sessionID}/llm`, "LLM Analyst");

await page.setViewportSize({ width: 390, height: 844 });
await visit("mobile-findings", `/sessions/${sessionID}/findings`, "Findings");

const summary = [
  "# README Media Assets",
  "",
  "These screenshots are generated from the local vulnerable fixture and a temporary Nyx session.",
  "",
  "Regenerate from the repository root:",
  "",
  "```sh",
  "./scripts/readme-media.sh",
  "```",
  "",
  "The script uses only localhost fixture data and does not require a real target, API key, or LLM endpoint.",
  "It seeds a small deterministic demo LLM history row so the Analyst screenshot is not model-dependent.",
  "",
  "GIF generation is optional. If ImageMagick is installed as `magick` or `convert`, or Python has Pillow available, the script also writes `nyx-demo-flow.gif`.",
  "",
].join("\n");
await writeFile(`${outDir}/README.md`, summary);

await browser.close();
if (consoleErrors.length) {
  throw new Error(`Console errors observed:\n${consoleErrors.join("\n")}`);
}

const frames = [
  `${outDir}/nyx-command-center.png`,
  `${outDir}/nyx-findings.png`,
  `${outDir}/nyx-tool-runs.png`,
  `${outDir}/nyx-reports.png`,
];
if (frames.every((frame) => existsSync(frame))) {
  try {
    execFileSync("magick", [...frames, "-delay", "140", "-loop", "0", `${outDir}/nyx-demo-flow.gif`], { stdio: "ignore" });
  } catch {
    try {
      execFileSync("convert", [...frames, "-delay", "140", "-loop", "0", `${outDir}/nyx-demo-flow.gif`], { stdio: "ignore" });
    } catch {
      try {
        execFileSync("python3", ["-c", `
from pathlib import Path
from PIL import Image
out = Path(${JSON.stringify(outDir)})
frames = [out / "nyx-command-center.png", out / "nyx-findings.png", out / "nyx-tool-runs.png", out / "nyx-reports.png"]
images = []
for frame in frames:
    image = Image.open(frame).convert("P", palette=Image.Palette.ADAPTIVE, colors=96)
    image.thumbnail((960, 640), Image.Resampling.LANCZOS)
    canvas = Image.new("P", (960, 640), 0)
    canvas.paste(image, ((960 - image.width) // 2, (640 - image.height) // 2))
    images.append(canvas)
images[0].save(out / "nyx-demo-flow.gif", save_all=True, append_images=images[1:], duration=1300, loop=0, optimize=True)
`], { stdio: "ignore" });
      } catch {
        // GIF generation is optional; screenshots are the canonical README media.
      }
    }
  }
}
JS

export NYX_README_MEDIA_BASE_URL="http://127.0.0.1:$serve_port"
export NYX_README_MEDIA_SESSION_ID="$session_id"
export NYX_README_MEDIA_OUTPUT_DIR="$output_dir"
if [ "${NYX_README_MEDIA_SKIP_INSTALL:-}" != "1" ]; then
  (cd "$repo_root/web" && npx playwright install chromium >/dev/null)
fi

(cd "$repo_root/web" && node "$script_path")

echo "README media captured for session $session_id"
echo "assets: $output_dir"
