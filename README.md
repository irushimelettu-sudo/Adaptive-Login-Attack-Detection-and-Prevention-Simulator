# Login Brute Force Protection Simulator

A **Master's Semester 3 academic mini-project** demonstrating how repeated login attempts can trigger account lockouts and honeypot alerts. It is a local, educational simulation, **not a production authentication system**.

## Features

- Flask-based demonstration login page
- Three-failure lockout (10 seconds)
- Honeypot accounts that trigger longer lockouts (600 seconds)
- Passwords stored as salted PBKDF2 hashes (no plaintext passwords in storage)
- CSV event logging **without recording attempted passwords**
- Bounded, localhost-only test client
- Charts and PDF report summarizing simulated login events

## Requirements

Python **3.10+** on Windows, macOS, or Linux. Internet access is needed only to install Python dependencies. The demo server binds to `127.0.0.1`.

## Run on Windows (PowerShell)

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open **http://127.0.0.1:5000/**. In a second PowerShell window, from this project folder:

```powershell
.\.venv\Scripts\python.exe attacker.py --attempts 30
.\.venv\Scripts\python.exe analyze.py
```

The generated charts and PDF will be in `reports/`. Stop the server with **Ctrl+C**.

On macOS/Linux, use `python3 -m venv .venv` and `.venv/bin/python` instead of the Windows interpreter path.

## Demo accounts

| Username | Password | Behavior |
|---|---|---|
| `alice` | `DemoPass123!` | Successful demo login; three failures cause a 10-second lockout |
| `admin_test` | `HoneyDemo123!` | Honeypot; every login attempt triggers a 600-second lockout |
| `root_local` | `HoneyRoot123!` | Honeypot; every login attempt triggers a 600-second lockout |

These are **public demonstration credentials only**. Never reuse real passwords. The login success message does not create a real authenticated session.

## How to demonstrate

1. Start the Flask app and open the page.
2. Log in as `alice` with the correct demo password to see a successful result.
3. Submit three incorrect passwords for `alice` to trigger a temporary lockout.
4. Try `admin_test` to demonstrate honeypot detection.
5. Run the bounded test client against **your own localhost simulator only**.
6. Run `analyze.py` to create the event report.

## Project layout

- `app.py` — Flask UI, hashed demo accounts, lockouts, honeypot logic and CSV event logging
- `attacker.py` — bounded localhost-only login-attempt generator
- `analyze.py` — report and chart generator
- `requirements.txt` — dependencies
- `runtime_data/` — generated accounts and logs (excluded from Git)
- `reports/` — generated figures and PDF (excluded from Git)

## Limitations and responsible use

- This is a **teaching prototype**, not a deployable security product.
- Lockouts are account-based, not a comprehensive rate-limiting or bot-defense system.
- The demonstration does not implement real user sessions, CSRF protection, or a production account lifecycle.
- Local JSON storage is suitable only for this small demonstration, not concurrent multi-server use.
- Use only dummy accounts and synthetic attempts. Do not point the test client at external sites or real services.
- Never expose the Flask development server publicly.

## Origin

Adapted and cleaned up from an existing Master's Semester 3 academic mini-project for portfolio presentation. Core educational ideas (login attempts, lockouts, honeypot accounts, and analysis) are preserved.


## Live monitoring dashboard (portfolio upgrade)

Start the Flask application and open **http://127.0.0.1:5000/dashboard**. The dashboard refreshes every two seconds and shows real counts from `runtime_data/timeline.csv`: login attempts, failed/successful logins, lockout events, honeypot alerts, active account locks, an activity chart, and recent events.

In a second terminal, run `python attacker.py --attempts 30` to generate bounded, synthetic localhost-only traffic. The terminal now prints the actual login response (invalid, locked, or successful), rather than only HTTP 200.

Run `python analyze.py` to export the PDF report and charts to `reports/`. Generated data and reports are ignored by Git.

**Limitations:** This is a local academic simulator, not a production authentication system. Dashboard data is intentionally unauthenticated for localhost teaching use. Lockouts are per demo account and are not an IP-based rate limiter.

## Adaptive detection upgrade

The dashboard now includes a **60-second rolling risk score (0–100)** with an explainable category and contributing signals. The detector uses failure volume, concentration on one account, number of targeted accounts, and honeypot events. Risk is heuristic and resets as events age out; it does **not** use machine learning or guarantee attack attribution. The existing lockout and honeypot rules provide the prevention component.

### Run controlled attack scenarios

With `app.py` running, use a second terminal:

```powershell
.\.venv\Scripts\python.exe attacker.py --scenario bruteforce --attempts 30
.\.venv\Scripts\python.exe attacker.py --scenario spraying --attempts 30
.\.venv\Scripts\python.exe attacker.py --scenario stuffing --attempts 30
```

- **Bruteforce:** multiple synthetic guesses for `alice`.
- **Spraying:** one synthetic password against several demo usernames.
- **Stuffing:** distinct, synthetic username/password pairs across demo accounts.

Open `/dashboard` to watch risk signals and lockouts. These patterns may overlap in a short simulation: **password spraying and credential stuffing cannot be reliably distinguished from username/outcome logs alone**, so the dashboard correctly labels both as *multi-account burst*. The test client's `X-Demo-Scenario` header records the *known simulated scenario* for later evaluation; it is **not used as a detection signal**. All traffic is hardcoded to loopback, capped at 100 requests per run. Never use against real accounts.

Run `python -m unittest -v test_app` to execute the original and additional detection tests.
