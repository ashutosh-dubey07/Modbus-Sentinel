# Modbus Sentinel

Modbus Sentinel is a local, simulation-only industrial cybersecurity learning
project. It will model industrial assets, generate test traffic, detect suspicious
behavior, and demonstrate an approval-based response workflow. It does not
connect to physical PLCs or change real network controls.

The earlier live Modbus TCP client has been disabled. This release does not read
from real devices.

The project is being built in phases. The current foundation stores a fictional
plant inventory in SQLite, creates deterministic Modbus request samples in
memory, parses them, and saves valid or invalid events with their original
frames. A rule engine can flag write requests, reads across several register
addresses, and invalid requests. Each finding keeps references to its source
events. Findings create incidents and local in-app notifications for the admin.
Operators can acknowledge incidents; admins can close them. These demo role
checks are workflow rules, not a user login system. Simulated response and the
containment request and approval flow are simulation-only. Executing an
approved action updates only local simulated asset state. A containment request
also creates an in-app admin notification. It does not change real network
controls. The dashboard comes in a later phase.

## Requirements

- Python 3.11 or newer
- Pytest for this phase, listed in `requirements-dev.txt`
- The full app packages in `requirements.txt` are needed in later phases

## Set up

Run these commands in PowerShell from this folder:

```powershell
python -m pip install -e . -r requirements-dev.txt
python -m modbus_sentinel --config config.toml
```

The first command installs the project and pytest. The second checks the local
settings, updates the SQLite schema, and seeds a small fictional plant inventory
under `data`. It does not start a network listener or install the future
dashboard and Modbus packages.

To create one sample run, evaluate it, and open incidents for any findings, add
a scenario:

```powershell
python -m modbus_sentinel --config config.toml --scenario address_sweep
```

Use `normal_poll`, `address_sweep`, or `write_attempt`. Requests are built in
memory and their records are saved to the local database. No request is
transmitted. Administrator notifications remain in the local database; no
external message is sent.

## Run the checks

```powershell
python -m pytest
```

The simulator builds labeled Modbus request samples in memory. It does not
transmit them. The current phase does not connect to any device. Install
`requirements.txt` later, when those packages are used by their project phases.
