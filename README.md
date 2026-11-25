# AgentShield — Batch 1: Sample Application Foundation

AgentShield is a secure AI incident-investigation agent project. **Batch 1** provides the reproducible, SQLite-backed FastAPI sample application, five controlled incident scenarios, read-only diagnostic endpoints, structured JSON logging, and an initial local Streamlit dashboard.

> **Important:** All incidents in this repository are **controlled local simulations** designed for testing and later AI agent investigation. This Batch 1 foundation is **not** production-ready and does **not** include the AI agent (Batch 2) or full security evaluation suite (Batch 3).

## Architecture

```text
AgentShield/
  app/
    __init__.py          # Package version metadata
    main.py              # FastAPI app and endpoint registration
    database.py          # SQLite schema initialization and parameterized queries
    logging_config.py    # Structured JSON logging and safe log persistence
    models.py            # Pydantic request/response schemas and scenario enum
    scenarios.py         # Five reproducible incident scenarios and reset logic
    diagnostics.py       # Read-only diagnostic queries (PRAGMA query_only)
  dashboard/
    streamlit_app.py     # Local demonstration dashboard
  tests/
    __init__.py
    conftest.py          # Isolated temporary SQLite fixtures
    test_health.py       # Health endpoint tests
    test_scenarios.py    # Scenario activation, behavior, and reset tests
    test_diagnostics.py  # Read-only diagnostics, metrics, and deployment tests
  data/
    .gitkeep
  .gitignore
  requirements.txt
  README.md
  run.py                 # Uvicorn entrypoint
```

## Technology Stack

- Python 3.13
- FastAPI & Uvicorn
- SQLite (`sqlite3` standard library)
- Streamlit
- pytest & HTTPX

## Windows Setup & Installation

Create and activate a Python 3.13 virtual environment, then install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

No API keys, cloud credentials, or external services are required for Batch 1.

## Running the Applications

### 1. Start the FastAPI Server

```powershell
.\.venv\Scripts\Activate.ps1
python run.py
```

By default, FastAPI runs at `http://127.0.0.1:8000` (interactive docs at `http://127.0.0.1:8000/docs`).

### 2. Start the Streamlit Dashboard

In a second terminal:

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run dashboard/streamlit_app.py
```

The dashboard connects to `http://127.0.0.1:8000` over HTTP and can be pointed to another local URL in the sidebar.

## Incident Scenarios & Controls

All incidents are persisted in SQLite (`data/agentshield.db` by default) and survive server restarts until reset.

| Scenario ID | Behavior |
|---|---|
| `database_failure` | Sets the simulated DB failure flag. `GET /api/demo/request` returns HTTP `503`, while SQLite itself stays intact and `GET /api/database/health` reports SQLite connectivity separately. |
| `high_latency` | Injects a bounded artificial delay (`0.50s`, max `2.0s`) into `GET /api/demo/request` and records elevated duration in metrics and logs. |
| `http_500` | Causes `GET /api/demo/request` to return HTTP `500` and increments failure/500 metrics and error logs. |
| `bad_deployment` | Records an unhealthy deployment (`1.1.0-bad`) in `deployment_history` and marks application/deployment status as `unhealthy`. |
| `malicious_log` | Inserts six representative hostile/prompt-injection log strings as inert operational log entries with timestamps and severity. Strings are never executed or evaluated. |

### Activating Scenarios via HTTP

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/incidents/database_failure
curl.exe -X POST http://127.0.0.1:8000/api/incidents/high_latency
curl.exe -X POST http://127.0.0.1:8000/api/incidents/http_500
curl.exe -X POST http://127.0.0.1:8000/api/incidents/bad_deployment
curl.exe -X POST http://127.0.0.1:8000/api/incidents/malicious_log
```

### Resetting All Scenarios

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/reset
```

### Read-Only Diagnostic Endpoints

- `GET /health` — Overall health, UTC timestamp, and version
- `GET /api/status` — Active incidents, deployment status, and simulation flags
- `GET /api/logs` — Paginated structured logs (`limit`, `offset`, optional `severity`)
- `GET /api/metrics` — Demo request metrics: total, successful, failed, average duration, and HTTP 500 counts (counts only `GET /api/demo/request`, not every FastAPI endpoint)
- `GET /api/database/health` — Real SQLite connectivity, integrity check, and simulated failure flag
- `GET /api/deployments` — Chronological deployment history

## Running Tests

Tests use isolated temporary SQLite databases via `pytest` fixtures and do not touch `data/agentshield.db`:

```powershell
.\.venv\Scripts\Activate.ps1
pytest -v
```

## Known Limitations

- **Simulated incidents only:** Failures, deployments, and latencies are simulated locally and do not model distributed infrastructure.
- **No AI agent or MCP tools:** Automated investigation (LangGraph / MCP) is deferred to Batch 2.
- **Subset of hostile payloads:** Only 6 representative malicious log strings are included in Batch 1; the full adversarial evaluation suite belongs to Batch 3.
- **Single-node local storage:** SQLite is intended for local demonstration and testing, not multi-instance production workloads.
