# WordPress Plugin Research Pipeline

A local research pipeline for downloading a bounded set of WordPress.org plugin releases and finding review candidates in PHP, Python, Go, and Rust source. It does not execute plugin code, probe live sites, generate exploit payloads, or submit reports.

## Requirements

Python 3.10 or newer. Semgrep Community Edition is strongly recommended for syntax-aware source-to-sink analysis. Install it with `python -m pip install semgrep`; if it is absent, the built-in bounded heuristics still run.

## Run

```powershell
python scanner.py catalog --pages 2 --per-page 100 --browse popular --min-installs 25
python scanner.py scan --catalog output/catalog.json --review output/review.json --workers 2 --supabase
python scanner.py stream --browse popular --pages-per-cycle 2
python scanner.py drift --browse popular --pages 2
python scanner.py stream --ai-triage --workers 1
python scanner.py ai-setup
python scanner.py audit --root .
python scanner.py security-audit --root .
```

Install Phots into the active Python environment to use the short `phots` command from a terminal:

```powershell
python -m pip install -e .
phots
```

`phots` with no arguments opens the existing interactive launcher; it does not start a scan until you choose a mode. `python scanner.py` remains supported and opens the same UI.

All generated files default to the `output/` directory in the current working directory. `--out` can select a different output directory. `stream` defaults to the `popular` feed because the `new` feed commonly contains plugins below the default 25-install threshold. If a chosen feed has no unseen eligible releases, Phots automatically checks `popular` and explains the fallback in the dashboard/report. Completed `(plugin slug, version)` pairs are remembered in `output/phots_stream.sqlite3`; both `stream` and `scan` reuse saved results instead of scanning those versions again. `output/phots-memory.json` shows the last completed plugin, number of remembered versions, and drift-baseline coverage. A new version is a new scan; to re-check an already-scanned version for changed source, run the separate one-shot `drift` mode below.

The stream writes the live browser report to `output/phots-live-report.html` after each completed plugin, refreshes it periodically while work is running, and auto-refreshes the browser view. It also appends operational events to `output/phots-live.log` and refreshes `output/phots-designer-handoff.md` with a current snapshot, diagnostics, and recent events for product/design handoff. The event log rotates at 10 MiB to a `.1` backup. These files omit API keys and code excerpts. Override them with `--log-file` and `--handoff-file`. Add `--supabase` to persist each plugin and its findings to the connected Supabase project as well. In an interactive terminal, Phots displays each worker's current stage and elapsed step time. Press **P** to pause/resume dispatching more plugins and **Q** or **Ctrl+C** to stop cleanly. Existing scans finish before shutdown. The terminal dashboard can be disabled with `--no-tui`. Transient plugin failures get up to three attempts with a cooldown; the live status shows retry information.

### Separate source drift scan

`drift` is a finite scan type, separate from the continuous stream. It reads the selected WordPress.org feed, fetches fresh archives only for versions already present in Phots history, and compares hashes of supported source files (`.php`, `.py`, `.go`, `.rs`). Unchanged versions are skipped. Changed files trigger a fresh static scan, replace the saved findings for that plugin version, and update its fingerprint. Older history without a fingerprint gets one baseline scan the first time `drift` is run. New plugin versions are reported but left for normal stream discovery. Results are written under `output/drift/`, including `phots-drift-report.md`, `report.html`, and `phots-drift-report.json`.

```powershell
python scanner.py drift --browse popular --pages 2 --workers 2
```

Phots samples available physical memory and logical CPU count at startup. With Semgrep installed it budgets 2 GiB per concurrent stream; without Semgrep it budgets 512 MiB. It reserves 35% of currently free memory and selects the lower of memory capacity, CPU count, and `--max-workers` (default cap 10). For example, `--workers 2`, `--workers 3`, `--workers 4`, or `--workers 10` selects that many streams, while the default `--workers 0` uses the recommendation. The dashboard/report show a quick 1/2/3/4/10 fit check. The recommendation is a conservative starting point, not a throughput benchmark; actual best speed depends on disk, network, plugin size, and Semgrep rule downloads. If unsure, start at the recommendation and adjust based on observed throughput and memory.

## AI lead triage (optional)

AI triage is optional and opt-in. Phots runs normally without an AI provider. If `--ai-triage` is requested but the endpoint/model is not configured, it reports that AI triage is disabled and continues the scan:

```text
PHOTS_AI_BASE_URL=https://your-provider.example/v1
PHOTS_AI_MODEL=your-model-name
PHOTS_AI_API_KEY=your-key
```

Put these values in the ignored local `.env` file or set them in the process environment. `--ai-base-url` and `--ai-model` can override endpoint/model per run; the key is only read from `PHOTS_AI_API_KEY` and is never printed or passed as a command-line argument. Local HTTP endpoints are allowed only on localhost. A provider that does not implement the OpenAI-compatible chat-completions format needs an adapter before it can connect.

Run `python scanner.py ai-setup` (or choose **Configure optional AI triage** in the interactive launcher) to save the endpoint and model in `.env`; the API key prompt is hidden. AI triage remains opt-in for each scan.

Phots sends bounded source windows around findings in batches, plus a few related prior triage summaries. It does not send the whole plugin archive. Local persistent memory is stored in `phots_stream.sqlite3` (`ai_reviews` table): dispositions, confidence, verified code quotes, model name, and summaries; prompts and source windows are not retained. Exact signal IDs are reused from memory after restart. The report shows each disposition and source quote. High-confidence `likely_false_positive` items can be marked **AI closed** only when the quoted text is verified against the source. `likely_bug` means an unconfirmed candidate; static AI review cannot prove exploitability. Missing, malformed, or failed AI responses stay open as `needs_human`. At most 50 new findings per plugin are reviewed by default; excess leads remain open. Raise `--ai-max-findings-per-plugin` to process more, keeping provider cost, rate limits, and review time in mind.

The catalog uses the WordPress.org Plugin Information API. The scan fetches each package, safely extracts it, and analyzes `.php`, `.py`, `.go`, and `.rs` files. Semgrep runs bundled WordPress-specific taint rules by default with metrics disabled. `--semgrep-auto` opts into Semgrep registry auto-rules and enables Semgrep metrics because the CLI requires metrics for auto configuration. Source code remains analyzed locally.

Downloads and scans share a bounded worker pool of at most four. Plugin source is cached by slug and version. Semgrep has a per-plugin timeout and per-file size cap; the built-in scanner also has per-plugin file and finding limits.

## Local dependency audit

`audit` inventories `composer.json`/`composer.lock`, `package.json`/`package-lock.json`, and `npm-shrinkwrap.json` under the selected root. It skips common dependency/build directories such as `vendor/` and `node_modules/`. It runs `composer audit` or `npm audit` only when the executable is already installed and a matching manifest plus lockfile is present. It never installs dependencies or runs plugin code. These audit commands may contact the package registries configured for Composer/npm; review that before running against projects with private package names.

Reports are written to `output/audit/dependency-audit.md` and `output/audit/dependency-audit.json`; raw tool output is saved under `output/audit/tool-output/`. A nonzero tool exit is reported with its exit code and output path because it may represent vulnerabilities or a tool/registry error.

## Local WordPress security-audit workflow

Use `security-audit` for a repeatable, local-first pass over a plugin you own or are authorized to assess:

```powershell
python scanner.py security-audit --root C:\path\to\plugin
# Skip registry-backed dependency lookups:
python scanner.py security-audit --root C:\path\to\plugin --no-dependency-audits
# Explicitly opt into project-configured PHP tools:
python scanner.py security-audit --root C:\path\to\plugin --run-project-tools
```

The workflow inventories PHP/JS and supported source/configuration files, recording line locations for REST/AJAX/admin entrypoints, request sources, database/file/upload/deserialization/execution sinks, nonce/capability checks, state-changing APIs, and possible hardcoded-secret assignments. Secret values are not copied into the inventory. These are review locations, not proof that a guard is missing or a vulnerability exists.

It uses Phots' bundled Semgrep rules locally with metrics and version checks disabled. It runs Composer/npm audits only for matching manifest/lockfile pairs and installed executables; Composer plugins are disabled, but Composer/npm may still contact configured registries. If installed, Gitleaks is asked to redact its report, Retire.js checks local JavaScript, and Syft can create a CycloneDX SBOM. Grype and Trivy are run only when installed and configured to use cached vulnerability databases rather than update them. Missing tools are reported instead of installed.

PHPCS (WordPress and VIP standards), PHPStan, and Psalm run only when `--run-project-tools` is supplied. They are otherwise listed as opt-in because project-specific analyzer configurations may load bootstrap code. PHPStan/Psalm are run only when their project configuration is present; PHPCS standards run only when installed. CodeQL database creation and live WordPress testing remain manual: database/build configuration can execute project commands, and this workflow does not launch a site, send requests, or perform dynamic tests.

Reports are saved under `output/audit/`: `security-audit.md`, `security-audit.json`, `surface-inventory.json`, `file-inventory.txt`, and per-tool output in `tool-output/`. Common generated/dependency directories are excluded, and inventory limits are disclosed in the report. The report includes a manual review checklist for authorization, nonce/CSRF, data-flow, and workflow logic. Use the existing `audit` command when you only need the Composer/npm dependency audit.

## Kubernetes (manual local scan)

The local-first Kubernetes setup runs one bounded `scan` Job against a supplied catalog. It does not start the continuous stream or an unattended schedule. The Job uses the existing Supabase result persistence and a PVC for source cache, SQLite completion history, and reports. It runs as a non-root user with a read-only container filesystem and explicit CPU, memory, and temporary-storage limits. AI triage remains disabled unless separately configured.

Build and load the image into a local cluster:

```powershell
docker build -t phots:local .
kind load docker-image phots:local --name YOUR_KIND_CLUSTER
# Or, for minikube:
minikube image load phots:local
```

Create the namespace and catalog ConfigMap, then copy `.env.k8s.example` to the ignored `.env.k8s` file and fill in the Supabase credentials. Keep that file out of source control:

```powershell
Copy-Item .env.k8s.example .env.k8s
kubectl apply -f deployment/kubernetes/base/namespace.yaml
kubectl create configmap phots-scan-catalog --namespace phots --from-file=catalog.json=output/catalog.json
kubectl create secret generic phots-supabase --namespace phots --from-env-file=.env.k8s
kubectl apply -k deployment/kubernetes/base
```

The cluster needs a default StorageClass capable of provisioning the 10 GiB `ReadWriteOnce` PVC. To rerun, delete the completed Job and create it again. The catalog ConfigMap is limited by Kubernetes' ConfigMap size constraints; use an approved mounted input source for larger catalogs. These scans download plugin archives from WordPress.org and write results to the configured Supabase project, so use only a project and catalog you are authorized to assess. Do not apply database migrations or run Jobs against the active project without checking its configuration first.

`deployment/kubernetes/base/scan-job.yaml` deliberately fixes worker concurrency at one and has no CronJob or stream Deployment. Horizontal or unattended scanning is not part of this local manual setup.

## Analysis and outputs

- `output/catalog.json`: selected plugins and WordPress.org metadata.
- `output/review.json`: optional human review decisions used by `scan`.
- `output/signals.json`: findings with source language, engine, class hint, code excerpt, and stable `signal_id`.
- `output/decisions.json`: scope decision (`FAIL`, `REVIEW`, or `PASS`) for each candidate.
- `output/alerts.json`: candidates that pass Wordfence's filter after human review, sorted with high-threat classes first.
- `output/report.md`: readable summary grouped by review urgency, with plain-language descriptions and suggested validation steps.
- `output/report.html`: simple browser-friendly version of the same report.
- `output/source/`: downloaded plugin source.

The report groups signals as “Review first,” “Review,” “Unclassified,” or “Eligible candidate — human review required.” These are workflow buckets, not severity ratings. Every automated signal is explicitly described as unconfirmed, and the report includes the file/line, language, scanner source, scope-filter explanation, and suggested next steps.

Bundled taint rules cover SQL injection, XSS output, command execution, unsafe deserialization, dynamic PHP includes, file/path operations, arbitrary option changes, user-role assignments, and file uploads. When explicitly enabled with `--semgrep-auto`, Semgrep's auto-selected community rules broaden the language coverage. The code hints only prioritize manual review; the reviewer must establish reachability, permission level, impact, patch status, duplicates, and a safe reproducible proof of concept.

Each candidate has a stable `signal_id`; use it as the key in `review.json`. The filter pre-fills the vulnerability class only when a rule has a recognized Wordfence class hint. A `PASS` still requires a person to confirm every scope and evidence field.

Semgrep Community Edition analyzes files individually; cross-file analysis requires Semgrep Pro. No scanner can guarantee discovery of every vulnerability or prove that a finding has never been reported. New discoveries still depend on validating unusual code paths, framework behavior, and interactions that static rules miss.

## Human review gate

```json
{
  "signal_id_from_signals_json": {
    "review_status": "confirmed",
    "asset_type": "plugin",
    "active_installs": 75000,
    "vulnerability_type": "sql_injection",
    "attacker_auth": "unauthenticated",
    "explicitly_out_of_scope": false,
    "open_to_downloads": true,
    "has_existing_bug_bounty": false,
    "researcher_is_software_developer": false,
    "researcher_registered": true,
    "wordfence_exclusive_disclosure": true,
    "demonstrable_security_impact": true,
    "working_poc": true,
    "duplicate_checked": true,
    "wordpress_org_listed": true,
    "is_premium": false,
    "evidence": "Describe verified impact and safe reproduction steps."
  }
}
```

WordPress.org install counts are rounded; verify them and other scope facts before review. Wordfence's published rules warn against bulk automated bounty hunting. Use this for internal research and submit only individually validated reports through the authorized researcher workflow. The scanner never auto-submits findings.

## Supabase

The scanner is connected to the active project **buggy** (`ogqsngiqokpevjwkzoei`). `supabase_schema.sql` defines the catalog, run history, per-run signals, and scope-review tables. RLS is enabled, and only the server-side `service_role` has table grants.

The ignored local `.env` file holds the Supabase secret key. The key is not in the tracked source files. Add `--supabase` to `catalog` or `scan` to persist results. Catalog runs upsert plugin metadata; scans batch-write run status, signals, and reviewed decisions.

## Known limits

Semgrep and the fallback heuristics produce candidates, not confirmed vulnerabilities. The tool does not execute plugins, dynamically fuzz WordPress sites, prove exploitability, or independently identify every asset's competing bounty status. Wordfence makes the final eligibility decision, and its rules can change.
