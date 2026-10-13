# Adaptive Login Attack Detection and Prevention Simulator

**A cybersecurity mini-project** built with Python and Flask. It demonstrates controlled login-attack simulations, account lockouts, honeypot detection, and **explainable rule-based risk scoring** through a local security dashboard and PDF reports.

> **Educational use only.** This is a localhost demonstration, not a production authentication service or an AI/ML detection system. Use only synthetic credentials and your own simulator.

## Features

- **Login demonstration:** Flask webpage with salted PBKDF2 password hashes for predefined demo accounts.
- **Prevention controls:** A regular account locks for 10 seconds after three incorrect passwords; honeypot accounts trigger a 600-second lockout and never authenticate.
- **Attack simulator:** Bounded, localhost-only client supporting brute-force, password-spraying, credential-stuffing, and mixed synthetic scenarios.
- **Rule-based detection:** A rolling 60-second risk score (0–100), with severity, a suspected pattern, and contributing signals.
- **Live dashboard:** Automatically refreshes every two seconds, showing login outcomes, lockouts, honeypot alerts, active locks, recent events, and risk indicators.
- **Reporting:** Charts and a PDF summary of recorded login events.
- **Automated tests:** Unit tests for authentication, lockouts, honeypots, dashboard statistics, and detection/scenario behavior.

## Requirements

- Python 3.10 or newer
- Dependencies listed in `requirements.txt`: Flask, Requests, and Matplotlib

## Setup and run (Windows / VS Code PowerShell)

From the project directory:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open these pages in your browser:

- **Login form:** http://127.0.0.1:5000/
- **Security dashboard:** http://127.0.0.1:5000/dashboard

Leave the server running. Open a **second VS Code terminal** in the same folder to run simulations.

On macOS/Linux, create the environment with `python3 -m venv .venv` and use `.venv/bin/python` instead of `.\.venv\Scripts\python.exe`.

## Demo credentials

| Username | Password | Expected behavior |
| --- | --- | --- |
| `alice` | `DemoPass123!` | Successful demo login when not locked |
| `admin_test` | `HoneyDemo123!` | Honeypot: login always rejected; triggers a 600-second lockout |
| `root_local` | `HoneyRoot123!` | Honeypot: login always rejected; triggers a 600-second lockout |

For `alice`, three incorrect passwords trigger a **10-second account lockout**. The published credentials are synthetic and must never be reused for real accounts. A successful demo login does not create a real authenticated session.

## Run the simulated attacks

With `app.py` running, execute these commands in a second terminal:

**Single-account brute-force simulation:**

```powershell
.\.venv\Scripts\python.exe attacker.py --scenario bruteforce --attempts 30
```

**Password-spraying simulation:**

```powershell
.\.venv\Scripts\python.exe attacker.py --scenario spraying --attempts 30
```

**Synthetic credential-stuffing simulation:**

```powershell
.\.venv\Scripts\python.exe attacker.py --scenario stuffing --attempts 30
```

**Mixed demo traffic:**

```powershell
.\.venv\Scripts\python.exe attacker.py --scenario mixed --attempts 30
```

The script sends requests **only to `http://127.0.0.1:5000/`**, allows **1–100 attempts per run**, and prints each server response (such as invalid credentials or account locked). The demo includes predefined accounts and an unknown synthetic username; it does not test real websites or credentials.

Open the dashboard while a scenario runs to see counters and recent events update. Because the risk score uses a 60-second window, its value can decrease after recent activity expires. Account lockouts can also affect later demonstrations; wait for them to expire when needed.

## How detection works

`detection.py` evaluates failed login events from the **last 60 seconds**. The risk score combines:

- Number of recent failed attempts
- Highest failure count against one account
- Number of distinct targeted usernames
- Honeypot-trigger events

The score is capped at **100**. Severity is **low** below 35, **medium** from 35 to 64, and **high** from 65 upward.

The detector assigns a descriptive pattern based on its rules:

| Pattern | Rule |
| --- | --- |
| Honeypot activity | At least one recent `honeypot_triggered` event |
| Multi-account burst (spraying/stuffing-like) | At least 6 failures across 3 or more usernames, without a honeypot trigger taking precedence |
| Single-account brute-force pattern | At least 3 recent failures against one username, without a higher-priority pattern |
| Insufficient evidence | None of the above rules match |

These are **heuristics, not proof of the attack type**. Password spraying and credential stuffing can produce similar username/outcome patterns. The simulator records a scenario label in the event log for demonstration context, but the detector **does not use that label** to decide its classification.

The risk score informs monitoring; **account lockouts and honeypot rules** provide the actual prevention behavior. This project does not implement adaptive risk-based blocking.

## Generate the PDF report

After recording some login attempts:

```powershell
.\.venv\Scripts\python.exe analyze.py
```

The report is saved at:

```text
reports/login_analysis_report.pdf
```

Four PNG charts are also saved in `reports/`. The report summarizes recorded attempts, successes/failures, lockout and honeypot events, scenario labels, and a risk assessment at the **last recorded event's timestamp**. It does **not** calculate detection accuracy, precision, recall, or false-positive rates.

## Run the tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
```

This discovers the authentication/dashboard tests and the additional detection and scenario-generation tests in `test_app.py`.

## Project structure

```text
.
├── app.py            # Flask login form, dashboard, API, lockouts, honeypots, event logging
├── attacker.py       # Local-only synthetic attack scenarios
├── detection.py      # Rolling-window risk score and heuristic classification
├── analyze.py        # PNG charts and PDF report
├── test_app.py       # Automated tests
├── requirements.txt  # Python dependencies
├── .gitignore        # Excludes local environment and generated artifacts
└── README.md
```

At runtime, the app creates `runtime_data/` for synthetic user records and event logs. Reporting creates `reports/`. Both directories, along with `.venv/`, should remain outside version control.

## Scope and limitations

- Intended for **local academic demonstration only**; the Flask development server binds to `127.0.0.1` with debug mode disabled.
- Demo accounts and passwords are intentionally public. Passwords are stored as salted hashes, and attempted passwords are **not** written to event logs.
- The dashboard is unauthenticated because it is a local teaching tool; do not expose it to a public network.
- The project does not provide production login sessions, CSRF protection, distributed rate limiting, or comprehensive bot detection.
- Risk scoring is **rule-based**, not machine learning. It does not guarantee attack attribution or provide a measured detection accuracy.
- Local JSON/CSV storage is appropriate for a small simulator, not a multi-server deployment.

## Academic context

Originally developed as a Master's Semester 3 cybersecurity mini-project and subsequently refined for portfolio presentation with a monitoring dashboard, synthetic attack scenarios, explainable risk scoring, tests, and reporting.
