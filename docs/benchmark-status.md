# Nyx Benchmark Status

Last verified full-suite baseline: Linux VM, 2026-06-07, artifact `artifacts/benchmarks/20260607-221632`, aggregate `102/102` covered with all seven gates passing.

These benchmarks are release gates for scanner depth. They use safe local vulnerable applications, deterministic benchmark profiles, and expected mappings. App-specific credentials, setup, and expected labels live under `benchmarks/<target>/`; scanner logic should stay generic.

| Benchmark | Gate | Latest verified result | What it primarily exercises |
|---|---:|---:|---|
| DVWA | 14/14 | 14/14 | Authenticated classic web vulnerabilities, SQLi, XSS, command/file issues, CSRF/CSP/CAPTCHA review |
| OWASP Juice Shop | 15/15 | 15/15 | Modern single-page app/API workflow, XSS, redirects, exposed data, deserialization/observability review |
| OWASP crAPI | 12/12 | 12/12 | API authorization, JWT/auth flows, BOLA, excessive data exposure, SSRF/workflow review |
| OWASP Benchmark | 11/11 | 11/11 | Java source-audit vulnerability classes from `expectedresults-1.2.csv` |
| DVGA | 24/24 | 24/24 | GraphQL discovery, schema-shaped authorization/injection/DoS review, operation evidence |
| WebGoat | 14/14 | 14/14 | Java lesson-oriented source plus authenticated route evidence |
| NodeGoat | 12/12 | 12/12 | Node/Express source-authenticated evidence for classic server-side web issues |

## Artifact Outputs

Every benchmark run writes artifacts under `artifacts/benchmarks/<timestamp>/`:

- `index.md` and `index.json`: aggregate status across every target in the run.
- `<target>/summary.md` and `<target>/summary.json`: per-target coverage, finding, and tool-run summaries.
- `<target>/*.log`: setup, scan, and target logs useful for debugging failures.

The Integration GitHub Actions workflow has a manual `benchmark` input. When set to a target or `all`, the workflow provisions the Linux scanner tool set and uploads the aggregate index, per-target summaries, and logs as a short-lived artifact, even when the benchmark fails.

## Interpreting The Gates

A passing gate means Nyx produced the expected category-level evidence for that local benchmark and had no failed tool runs under strict mode. It does not mean every upstream challenge was exploit-confirmed or that every scanner result is a true positive.

Some categories intentionally remain human-assist findings. For example, DVGA destructive payload categories, crAPI workflow findings, CSP/CAPTCHA review, and observability/deserialization hints are scored when Nyx has useful deterministic context for an operator to review safely.

crAPI uses an API-focused default benchmark tool set and omits the external Dalfox XSS adapter because Dalfox does not contribute to crAPI's expected API coverage and can be timeout-prone on that target. Set `NYX_BENCHMARK_TOOLS_CRAPI` locally if you want to include Dalfox in an exploratory crAPI run.

## Running Locally

```sh
NYX_RUN_BENCHMARKS=1 make benchmark-all
```

Use individual targets while developing scanner depth:

```sh
NYX_RUN_BENCHMARKS=1 make benchmark-crapi
NYX_RUN_BENCHMARKS=1 make benchmark-dvga
```

Keep generated `artifacts/benchmarks/` output out of commits.
