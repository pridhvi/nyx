# Codex Linux VM UI/UX Review Prompt

Copy this prompt into Codex CLI from the root of the Nox repository on the Kali
VM.

```text
Act as a senior UI/UX reviewer and frontend quality engineer for the Nox app.

You may install any local UI review/testing tools you think are useful on this Kali VM, including Playwright, Chromium, Lighthouse, axe-core, pixelmatch, image tooling, or screenshot/trace utilities. Do not install telemetry/session-recording SaaS agents. Ask before installing very large desktop apps. Use local tools only.

Your goal is not just to test functionality. Your goal is to inspect the UI like a human operator would: what looks polished, what feels janky, what is confusing, what is visually noisy, what feels cramped, what is hard to scan, and what undermines trust.

Use only localhost and the local vulnerable fixture. Do not scan external targets.

Required workflow:

1. Prepare app state
   - Run `go test ./...`
   - Run `cd web && npm ci && npm run build`
   - Run `NOX_RUN_INTEGRATION=1 make test-integration`
   - If useful, run `NOX_RUN_LINUX_FULL=1 NOX_KEEP_LINUX_SMOKE_ARTIFACTS=1 make linux-full-smoke`
   - Build the app with `make build`

2. Start Nox locally
   - Generate an API key.
   - Start `./bin/nox serve --host 127.0.0.1 --port 6767`.
   - Keep the server running while you inspect.
   - Use the generated API key for login.

3. Create or reuse realistic data
   - Use the integration-created sessions if available.
   - Ensure at least one dynamic session, one static/audit session, one combined session, and one lean session exist.
   - If missing, create them against `scripts/vulnerable-fixture`.

4. Browser/UI inspection
   - Use browser automation if available.
   - If not available, install/use Playwright with Chromium.
   - Visit these routes in both dark and light mode:
     - `/`
     - `/scan`
     - `/findings`
     - `/source`
     - `/runs`
     - `/tools`
     - `/graph`
     - `/cves`
     - `/llm`
     - `/reports`
     - `/settings`
     - session-scoped versions for at least one populated session, e.g. `/sessions/<id>/findings`, `/sessions/<id>/graph`, `/sessions/<id>/runs`, `/sessions/<id>/reports`
   - Test these viewports:
     - mobile: 390x844
     - tablet: 768x1024
     - desktop: 1440x1000
     - wide: 1920x1080

5. Screenshot capture
   - Take screenshots for every route, theme, and viewport that matters.
   - Save screenshots under a temporary review folder, for example `/tmp/nox-ui-review`.
   - Use descriptive names like `desktop-dark-dashboard.png`, `mobile-light-findings.png`, `tablet-dark-graph-session.png`.

6. Inspect the screenshots yourself
   - Open/read/analyze each screenshot as visual evidence.
   - Do not rely only on DOM checks.
   - Judge the UI like a human:
     - Does the page feel trustworthy and professional?
     - Is the hierarchy obvious in the first 3 seconds?
     - Can a tired operator scan it quickly?
     - Are controls where a user expects them?
     - Does anything feel cramped, noisy, awkward, or unfinished?
     - Are cards/panels overused?
     - Do text, badges, buttons, and tables fit cleanly?
     - Are empty/loading/error states helpful?
     - Does mobile feel intentionally designed or merely squeezed?
     - Does light mode look first-class or secondary?
     - Does the attack graph feel useful or visually chaotic?
     - Do reports/tool-runs/findings pages make evidence easy to inspect?

7. Objective checks
   - Check browser console errors.
   - Check failed network requests.
   - Check horizontal overflow.
   - Check text clipping/overlap.
   - Check focus states and keyboard navigation where practical.
   - Run Lighthouse or axe accessibility checks if feasible.
   - Record performance/layout shift observations if obvious.

8. Interactions to test manually
   - Login flow.
   - Session selector.
   - Theme toggle.
   - Mobile nav open/close.
   - Scan Builder target/source mode changes.
   - Scan profile apply/save/import/export if practical.
   - Findings filters, row selection, detail panel, evidence tabs, bulk update.
   - Source filters and context expansion.
   - Tool Runs drawer, stdout/stderr tabs, empty log state.
   - Attack Graph density toggle, vector selection, edge labels.
   - Reports preview and download link.
   - Settings health panels.
   - Tools ready/missing filters.

9. Produce a dedicated UI/UX review report
   - Write the report to `/tmp/nox-ui-review/REPORT.md`.
   - Include:
     - executive summary
     - top 10 UX/UI issues ranked by impact
     - route-by-route observations
     - mobile-specific issues
     - light/dark theme issues
     - accessibility issues
     - screenshots referenced by path
     - quick wins
     - larger design recommendations
     - objective tool findings
   - For every issue include:
     - title
     - severity P0/P1/P2/P3
     - route
     - viewport/theme
     - screenshot path
     - what feels wrong
     - why a human user would care
     - likely root cause
     - concrete fix recommendation

10. Patch only if asked
   - Do not modify repo files unless I explicitly ask for remediation.
   - Do not commit.
   - At the end, summarize where the screenshots and report are saved.
```

After the first pass finishes, copy this follow-up prompt into Codex CLI:

```text
Now inspect your own screenshots again and do a second pass only for subjective product polish: hierarchy, spacing rhythm, visual noise, trust, scannability, and whether this feels like a serious offensive security operator tool. Update /tmp/nox-ui-review/REPORT.md with the second-pass findings.
```
