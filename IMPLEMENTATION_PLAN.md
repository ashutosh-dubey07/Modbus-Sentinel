# Modbus Sentinel Implementation Plan

## Project boundary

Modbus Sentinel is an industrial cybersecurity application. Its network, traffic,
containment, and recovery actions run only inside a local simulation. It does not
scan real networks, connect to real PLCs, or change real network controls.

## Phase 0 findings

Status: Passed. Workspace inspection and planning are recorded. The user's
PowerShell confirmed Python 3.15.0. It also confirmed that Streamlit, PyModbus,
pandas, Plotly, and pytest are not installed in that interpreter. The Codex
command shell still cannot invoke that Python installation.

### Workspace contents

- `pyproject.toml`, `README.md`, `config.toml`, and `.gitignore`
- `src/modbus_sentinel/` with `cli.py`, `client.py`, `config.py`, `dashboard.py`,
  `simulator.py`, package entry points, and `web/index.html`
- Generated `src/modbus_sentinel.egg-info/` and `__pycache__/` directories
- No `tests/` directory or test files
- No `.git/` directory, and the `git` executable is unavailable in this shell

### Existing behavior and conflicts

- `client.py` opens a TCP connection to the configured host and reads holding
  registers. This is a live network client, not the isolated event simulator
  required by this project.
- `simulator.py` serves fixed register values on localhost. It does not model an
  industrial asset inventory, network segments, or structured security events.
- `cli.py` polls the configured device and checks simple raw-value thresholds.
- `dashboard.py` serves a small custom HTML page. The target application requires
  Streamlit and security workflow pages.
- There is no persistent database, event parser, detection engine, incident
  workflow, containment, independent verification, audit chain, recovery,
  evaluation engine, or gap analyzer yet.
- The current project metadata declares no runtime dependencies and the README
  describes the earlier register-monitor prototype.

The old TCP client is now a disabled compatibility stub. The MVP must not
connect to a real industrial device.

### Baseline environment

- User PowerShell: Python 3.15.0
- User PowerShell: Streamlit, PyModbus, pandas, Plotly, and pytest not installed
- Codex shell: `py -0p` reports no installed Python; `python` is unavailable
- `pytest`: no existing test suite and no Python interpreter in the Codex shell
- Baseline tests: none exist in the workspace, so there is no existing test suite
  to run
- Dependency versions: not confirmed in this shell
- Git status: unavailable because this folder has no `.git/` directory and Git is
  not installed in this shell

## Proposed architecture

Use the existing `src/modbus_sentinel/` package layout. Keep responsibilities
separate:

1. Configuration and SQLite database/repository layer
2. Industrial asset inventory and network-segment model
3. Deterministic, local event simulator
4. Modbus TCP subset parser and event validation
5. Detection rules and evidence references
6. Incident lifecycle, demo operator authorization, and notifications
7. Simulation-only containment adapter
8. Independent containment and recovery verifier
9. Append-only audit log with a verifiable hash chain
10. Ground-truth evaluator and detection-gap analyzer
11. Streamlit dashboard, topology, and reports

Data flow:

`Simulator -> parser -> event store -> detector -> evidence and incident ->
administrator decision -> simulated containment -> independent verification ->
audit and recovery`

Evaluation runs labelled scenarios through the detector separately from
containment. Dashboard metrics must come from stored scenario results.

## Dependency plan

- Python 3.11 or newer, subject to checking the actual development interpreter
- Streamlit for the dashboard
- SQLite through Python's standard library
- Pandas for analysis and exports
- Plotly or Streamlit-native charts
- Pytest for unit and integration tests
- PyModbus only where its installed, compatible API is useful for local simulation

Pinned versions are listed in `requirements.txt`: Streamlit 1.66.0, PyModbus
3.16.1, pandas 3.0.6, and Plotly 7.1.0. They are not needed by Phase 1 and are
not installed by the Phase 1 setup command. Pytest 9.1.1 is the only package
needed for the current tests. PyModbus's package metadata requires Python 3.10 or
newer, while its published test matrix currently lists Python through 3.14, so
its Python 3.15 behavior must be checked before a phase uses it. No cloud service
or paid API is needed.

The installed Python 3.15.0 environment has the editable `modbus-sentinel`
package and pytest 9.1.1. Streamlit, PyModbus, pandas, and Plotly are not
installed yet, as planned for later phases. `python -m pip check` reports no
broken requirements. The user ran the setup command, and
`data/modbus_sentinel.sqlite3` was confirmed in the workspace.

## Phase checklist

| Phase | Scope | Status |
|---|---|---|
| 0 | Workspace inspection and project planning | Passed |
| 1 | Foundation, configuration, and database | Passed |
| 2 | Industrial network model and simulator | Passed |
| 3 | Modbus TCP parser and event validation | Passed |
| 4 | Detection engine and evidence generation | Passed |
| 5 | Incident management and administrator notification | Passed |
| 6 | Containment approval and execution | Passed |
| 7 | Independent isolation verification | Not started |
| 8 | Audit trail and integrity verification | Not started |
| 9 | Recovery and restoration | Not started |
| 10 | Detection evaluation engine | Not started |
| 11 | Detection-gap analyzer | Not started |
| 12 | Dashboard, network topology, and reports | Not started |
| 13 | Integration and end-to-end testing | Not started |
| 14 | Final quality assurance and release | Not started |

## Phase 1 completed

- `config.toml` now contains local app settings and fixes the mode to simulation.
- `settings.py` validates those settings and resolves the database path.
- `database.py` creates the local SQLite file, records schema migrations, and
  provides commit/rollback sessions.
- The Phase 1 `cli.py` initialized local settings and SQLite without polling a
  device or starting a network listener. Phase 2 extends it to seed the sample
  inventory while keeping that local-only behavior.
- `tests/test_settings.py` and `tests/test_database.py` cover the new foundation.
- Phase 1 tests: 8 passed with Python 3.15.0 and pytest 9.1.1.
- The user ran the local setup command, and `data/modbus_sentinel.sqlite3` was
  confirmed in the workspace.

## Phase 2 completed

- `database.py` adds versioned tables for simulation-only network segments and
  assets, including database checks against live asset records.
- `inventory.py` provides seed, add, and list operations for the fictional plant
  inventory.
- `simulation.py` builds deterministic Modbus TCP request bytes for normal polls,
  address sweeps, and write attempts. It does not open a socket.
- `cli.py` upgrades the database and seeds sample inventory without starting a
  listener.
- All 21 tests pass with Python 3.15.0 and pytest 9.1.1.
- Re-run the setup command once to upgrade the existing local database to schema
  version 2 and add the sample inventory.

## Phase 3 completed

- `protocol.py` parses Modbus TCP read holding registers, read input registers,
  and write single register requests. It checks the MBAP header and request
  fields without opening a network connection.
- `event_validation.py` checks request structure and local asset references,
  while retaining errors for invalid frames.
- `events.py` stores both valid and invalid simulated requests, including each
  original frame, in SQLite.
- `database.py` adds schema version 3 for simulation event records.
- `python -m pytest`: 34 passed with Python 3.15.0 and pytest 9.1.1.
- Phase 4 advances the local database beyond this version while retaining
  existing inventory and event rows.

## Phase 4 completed

- `detection.py` evaluates simulated events using request behavior, without
  using scenario names as detection input.
- Rules flag Modbus single-register write requests, reads across at least four
  distinct register addresses from one source to one destination, and invalid
  requests.
- `detections` stores each finding and its details. `detection_evidence` links
  findings to the exact events and records why each event supports the finding.
- `cli.py` accepts `--scenario` to generate and evaluate a local sample run.
- `python -m pytest`: 41 passed with Python 3.15.0 and pytest 9.1.1.
- The setup command or a scenario command applies schema version 4 and keeps
  existing inventory and event rows.

## Phase 5 completed

- `incidents.py` creates one open incident per stored detection and supports
  listing, acknowledging, and closing incidents.
- Operators and admins can acknowledge incidents. Only admins can close an
  acknowledged incident. The demo role check is a workflow gate, not user
  authentication.
- New incidents create a persistent in-app notification for the admin. No
  email or external message is sent.
- `cli.py` now creates incidents after evaluating a scenario and reports the
  local notification.
- `database.py` adds schema version 5 for incident lifecycle and admin inbox
  records. Existing scenario and inventory data remain in place.
- `python -m pytest`: 45 passed with Python 3.15.0 and pytest 9.1.1.
- Run the scenario command once to apply schema version 5 and create a sample
  incident plus its admin notification.

## Phase 6 completed

- `containment.py` supports requesting, approving, rejecting, and executing a
  simulated asset isolation action.
- Requests require an acknowledged incident and a simulated inventory asset.
- Only an admin can decide a request, and the requester cannot approve their
  own request. A pending or approved request must be resolved before its
  incident can be closed.
- Each containment request creates an in-app admin notification that can be
  read from the local inbox.
- Execution is blocked until approval. It updates only `simulated_asset_state`
  in SQLite; it does not change a real network or device.
- `database.py` adds schema version 6 for containment actions, simulated asset
  state, and approval notifications. Assets start as connected until a
  simulated action changes them.
- `python -m pytest`: 48 passed with Python 3.15.0 and pytest 9.1.1.
- Run the scenario command once to apply schema version 6. The containment
  workflow will be available through the application interface added later.

## Phase gates

Work on one phase at a time. Before each phase, report the files and interfaces
involved. After the phase, report changes, exact test commands and actual results,
remaining work, and whether its exit gate passed. Do not advance a phase while its
required tests or verification gate are unresolved.

Phase 0 was completed after the user confirmed their PowerShell interpreter and
installed packages. The app environment is now known; the Codex execution shell
cannot run the user's Python, so test results must be collected in PowerShell.
