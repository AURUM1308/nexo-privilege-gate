# NEXO Privilege Gate

> A least-privilege security gateway for AI agents.

**Current release:** v0.4.0  
**Status:** Early-stage open-source security prototype

NEXO Privilege Gate explores a simple security principle:

**An AI agent requesting an action should not automatically have the authority to execute it.**

NEXO introduces an independent authorization layer between an AI agent and the tools or resources it wants to use.

The current v0.4.0 implementation provides real local filesystem enforcement inside an isolated sandbox.

---

## Why NEXO exists

AI agents are becoming increasingly capable of interacting with files, applications, networks, browsers, APIs, and operating systems.

Giving an agent access to a computer should not imply unlimited authority.

NEXO is designed around:

- least privilege
- independent authorization
- explicit human approval for consequential actions
- explainable policy decisions
- restricted execution environments
- tamper-evident audit history

The long-term goal is a reusable authorization gateway between capable AI agents and the systems they operate.

---

## Current capabilities

NEXO v0.4.0 currently implements:

- Structured filesystem operations
- `ALLOW`, `REVIEW`, and `DENY` authorization decisions
- Isolated local filesystem sandbox
- Path-traversal protection
- Canonical-path validation before authorization
- Sensitive-file protection
- Human approval for destructive or state-changing operations
- One-time approval execution
- Quarantine instead of permanent deletion
- Tamper-evident HMAC audit chain
- Human-control dashboard
- Local agent API
- Windows launcher
- Regression-test gate before startup

---

## Authorization model

Every requested action is evaluated before execution.

```text
AI Agent
   │
   ▼
NEXO Privilege Gate
   │
   ▼
Policy Engine
   │
   ├── ALLOW ───────────────► Execute
   │
   ├── REVIEW ─► Human approval ─► Execute / Deny
   │
   └── DENY ────────────────► Block
```

The component requesting an action is therefore separated from the component deciding whether that action is allowed.

---

## Current filesystem operations

The local prototype currently supports structured operations including:

```text
list
read
write
mkdir
delete
```

### Safe read

```text
read welcome.txt
```

Expected decision:

```text
ALLOW
```

### Destructive delete

```text
delete important.txt
```

Expected decision:

```text
REVIEW
```

The operation does not execute until a human explicitly approves it.

Deletion uses quarantine rather than permanent removal.

### Sandbox escape attempt

```text
read ../outside.txt
```

Expected decision:

```text
DENY
```

---

## Security hardening with GPT-6 Astra

A pre-release adversarial review using GPT-6 Astra identified a path-alias authorization bypass.

A protected file such as:

```text
.env
```

could potentially be represented using aliases such as:

```text
.env/.
```

or, on Windows:

```text
.env.
```

Policy evaluation and filesystem resolution could therefore disagree about which resource was being accessed.

v0.4.0 fixes this by validating and normalizing paths before policy evaluation.

The same validated path representation is now used for:

```text
authorization
audit logging
pending approval
execution
```

Astra also added eight HTTP-level regression tests covering the vulnerability and related server behavior.

---

## Validation

The current automated test suite passes:

```text
34 / 34 tests
```

Testing includes policy, sandbox, audit, and HTTP server behavior.

Manual end-to-end validation on Windows also confirmed:

- safe directory listing executes
- safe file reads execute
- `../` path traversal is denied
- destructive deletion requires human approval
- denying approval prevents execution
- one-time approval executes exactly once
- approved deletion moves the target to quarantine
- intact audit history verifies successfully
- manual modification of an audit record is detected
- canonical-path aliases for sensitive files are denied

These tests provide evidence for the behaviors above, but they do not prove that NEXO is free of security vulnerabilities.

---

## Quick start on Windows

### Requirements

- Windows 10 or Windows 11
- Python 3.11 or newer

Verify Python with:

```bat
py --version
```

or:

```bat
python --version
```

### Download

Download the latest release from GitHub or clone the repository.

Then open the project folder.

You should see:

```text
nexo-privilege-gate/
├── nexo/
├── static/
├── tests/
├── .gitignore
├── LICENSE
├── README.md
├── index.html
├── run.bat
└── server.py
```

### Start NEXO

On Windows, double-click:

```text
run.bat
```

The launcher will:

```text
1. detect Python
2. run the security regression suite
3. refuse to start if tests fail
4. start the local enforcement server
```

If all tests pass, NEXO prints a private Human Control URL.

Open that URL in your browser.

The server binds only to:

```text
127.0.0.1
```

by default.

---

## Run tests manually

From the repository root:

```bat
py -m unittest discover -s tests -p "test_*.py" -v
```

Expected result for v0.4.0:

```text
Ran 34 tests

OK
```

---

## Run the server manually

```bat
py server.py
```

The local dashboard is served from:

```text
static/index.html
```

The root-level:

```text
index.html
```

is the public GitHub Pages policy preview and is intentionally separate from the local enforcement dashboard.

---

## Local security state

At runtime NEXO creates local state such as:

```text
.nexo_state/
sandbox_data/
```

These directories are intentionally excluded from Git.

Sensitive runtime material such as:

```text
agent.token
audit.key
```

must never be committed.

---

## Audit integrity

NEXO uses a chained HMAC audit log.

Each record references the authentication code of the previous record:

```text
record 1
   ↓
record 2
   ↓
record 3
   ↓
...
```

Changing a historical record without the audit key causes integrity verification to fail.

This makes the log **tamper-evident**, not tamper-proof.

An attacker with complete control of the machine and the audit key is outside the current security boundary.

---

## Current scope

NEXO v0.4.0 currently enforces:

```text
filesystem operations inside its isolated local sandbox
```

It does **not** currently claim enforcement over:

```text
arbitrary Windows actions
browser automation
general network access
financial transactions
MCP tools
arbitrary shell execution
full computer control
```

The public browser demo also remains a policy simulation and should not be confused with the local enforcement server.

---

## Known hardening areas

Important future work includes:

- concurrency-safe audit writes
- stronger human-control session expiration and reuse protection
- broader adversarial testing
- additional protected tool domains
- capability-scoped agent credentials
- richer policy composition
- network authorization
- MCP/tool gateway support
- operating-system integration

---

## Project structure

```text
nexo-privilege-gate/
│
├── nexo/
│   ├── __init__.py
│   ├── audit.py
│   ├── policy.py
│   └── sandbox.py
│
├── static/
│   └── index.html
│
├── tests/
│   ├── test_core.py
│   └── test_server.py
│
├── .gitignore
├── LICENSE
├── README.md
├── index.html
├── run.bat
└── server.py
```

---

## Security status

NEXO is currently an **early-stage security prototype**.

It is suitable for experimentation, research, testing, and development.

It should **not yet be treated as a production security boundary** for untrusted agents or sensitive systems.

Security reports and adversarial testing are welcome.

---

## Public preview

The browser-based policy preview is available through GitHub Pages:

https://aurum1308.github.io/nexo-privilege-gate/

The public page demonstrates policy decisions but does not execute real filesystem operations.

---

## Release

Latest release:

**NEXO Privilege Gate v0.4.0**

The release includes the local enforcement server, human-control dashboard, filesystem sandbox, tamper-evident audit chain, canonical-path hardening, and the current regression test suite.

---

## License

NEXO Privilege Gate is released under the MIT License.

---

## Roadmap

The long-term architecture is intended to evolve toward:

```text
AI Agent
   ↓
NEXO Authorization Gateway
   ↓
Policy / Capability Engine
   ↓
Human Approval when required
   ↓
Protected tools and resources
```

The objective is not to make AI agents less capable.

It is to make their authority explicit, limited, auditable, and revocable.
