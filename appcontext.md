# AVRC Project Context

## What This Project Is

AVRC is an autonomous vulnerability remediation core for code, containers, repos, and hybrid environments. The goal is to:

- scan applications and infrastructure with real or mocked tools
- deduplicate vulnerability records by canonical CVE
- enrich findings with OSV/NVD and remediation guidance
- generate fixes with LLM assistance
- route repo changes through GitOps flow
- keep chat context alive during an active session

The stack is designed to run locally on Windows with Docker Compose, while Ollama remains installed on the host and is not part of the container stack.

## Current Runtime Setup

- Host OS: Windows
- Working directory: `C:\Users\tejde\tejcsdevwork\dbtechhCKthon2026\dbtechhCKthon2026`
- Main app UI and orchestrator: `http://localhost:3000`
- Forgejo: `http://localhost:3001`
- GitOps API: `http://localhost:4100`
- Trivy API: `http://localhost:4140`
- Renovate API: `http://localhost:4150`
- Semgrep API: `http://localhost:4210`
- OSV API: `http://localhost:4230`
- Local Ollama: `http://localhost:11434`

## Live Services

These are currently implemented as real live services in the compose stack:

- `avrc-orchestrator`
- `forgejo`
- `git-ops-tool`
- `trivy-scan-tool`
- `renovate-fix-tool`
- `semgrep-scan-tool`
- `osv-lookup-tool`

Several other tools remain mock or placeholder services, but the orchestrator is wired to them through config.

## Recent Important Changes

- Removed Ollama from `docker-compose.yml`
- Updated chat to use host Ollama through `host.docker.internal`
- Added live Semgrep wrapper service
- Added live Renovate wrapper service
- Added Forgejo as the self-hosted git service
- Added fake app inventory and seeded repos for testing
- Added OSV enrichment path and CVE deduplication flow
- Added chat model picker and model test endpoint
- Added context retention during an active chat session

## Semgrep Status

Semgrep is now real and working.

Behavior:

- clones a Forgejo repo from `http://localhost:3001/...`
- rewrites that URL internally to `http://forgejo:3000/...` for container access
- runs `semgrep scan --config p/default`
- normalizes findings into AVRC format

Key fix that was needed:

- the first clone implementation returned a temp folder that got cleaned too early
- the wrapper now uses a persistent temp directory and cleans it after the scan

Validation result:

- real scan against `tejdeep/avrc-payments-service-0001`
- returned 4 findings

## Renovate Status

Renovate is now real and working in dry-run mode.

Behavior:

- uses the Renovate CLI inside a container
- targets Forgejo using the Forgejo/Gitea-compatible API
- rewrites clone URLs from `localhost:3001` to `forgejo:3000`
- runs dry-run scans by default
- only applies changes if explicitly requested by the approval flow

Key fixes that were needed:

- Renovate initially tried to use the browser-facing URL inside the container
- Git URL rewriting was added so container-local cloning works
- platform was aligned to `forgejo`
- healthchecks required `wget`, so it was added to the image

Validation result:

- real dry-run against `tejdeep/avrc-payments-service-0001`
- cloned successfully
- extracted dependencies
- found 7 update branches it would create

## Orchestrator And Chat Flow

The orchestrator is meant to:

- ask for missing context progressively
- remember collected context during the active session
- route a request to the right tool based on app type and scan target
- show user-friendly progress rather than raw agent internals
- deduplicate findings before enrichment
- enrich with OSV/NVD after scan results are collected
- generate remediation content via LLM when enough context exists

The chat UI and server files currently live under `src/` and have already been expanded to support:

- model selection
- LLM tests
- context retention
- streaming chat responses
- progress updates

## Config Files Of Interest

- `config/config.json`
- `docker-compose.yml`
- `config.yml`

The JSON config is used by the app runtime for model, agent, and tool routing.

## Fake Data And Seeded Test Assets

Generated test data already exists in `data/`:

- `data/fake-applications.json`
- `data/fake-applications.csv`
- `data/seed-summary.json`

The seed includes 1000 fake applications with different environments and vulnerability profiles.

Forgejo repos were also seeded for testing, including sample repos under user `tejdeep`.

## Testing Notes

Useful checks that have already been verified:

- `docker compose config --quiet`
- `Invoke-RestMethod http://localhost:3000/health`
- `Invoke-RestMethod http://localhost:4210/health`
- `Invoke-RestMethod http://localhost:4150/health`

Useful manual scan examples:

```powershell
$body = @{ operation='scan'; params=@{ repo='http://localhost:3001/tejdeep/avrc-payments-service-0001.git' } } | ConvertTo-Json -Depth 5
Invoke-RestMethod -Uri http://localhost:4210/semgrep/scan -Method Post -Body $body -ContentType 'application/json'
Invoke-RestMethod -Uri http://localhost:4150/renovate/scan -Method Post -Body $body -ContentType 'application/json'
```

## Current Caveats

- Compose still warns about orphan containers from earlier Ollama/GitLab experiments
- Those old containers are not part of the current stack
- Renovate may warn about missing GitHub token for GitHub-hosted dependencies in some repos
- Semgrep is using `p/default`, which can take a bit the first time because rules are fetched

## What To Keep In Mind Next

- Keep using Docker service names inside containers
- Keep Ollama host-only
- Keep scan results deduplicated by canonical CVE before enrichment
- Keep chat responses contextual and user-friendly
- Prefer real tools when available; only fall back to mocked tools when necessary
