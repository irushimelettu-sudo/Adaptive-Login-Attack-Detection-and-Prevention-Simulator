"""Generate plots and a PDF summary from simulated login attempts."""
import csv
from collections import Counter
from datetime import datetime
from pathlib import Path
from detection import assess
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

BASE = Path(__file__).resolve().parent
SOURCE = BASE / 'runtime_data' / 'timeline.csv'
OUTPUT = BASE / 'reports'


def main():
    if not SOURCE.exists():
        print('No attempts recorded yet. Run app.py and attacker.py first.')
        return
    with SOURCE.open(newline='', encoding='utf-8') as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        print('No attempts recorded yet.')
        return
    OUTPUT.mkdir(exist_ok=True)
    reasons = Counter(row['reason'] for row in rows)
    usernames = Counter(row['username'] for row in rows)
    successes = sum(row['success'].lower() == 'true' for row in rows)
    failures = len(rows) - successes

    risk = assess(rows, max(float(row['ts']) for row in rows))
    scenarios = Counter(row.get('scenario', '') for row in rows if row.get('scenario'))
    figures = []
    fig, ax = plt.subplots(figsize=(9, 4))
    times = [datetime.fromtimestamp(float(row['ts'])) for row in rows]
    ax.hist(times, bins=min(20, max(1, len(times))), color='#4f46e5')
    ax.set(title='Login attempts over time', xlabel='Time', ylabel='Attempts')
    fig.autofmt_xdate(); fig.tight_layout(); figures.append(fig)

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(['Success', 'Failure'], [successes, failures], color=['#16a34a', '#dc2626'])
    ax.set(title='Login outcomes', ylabel='Attempts'); fig.tight_layout(); figures.append(fig)

    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(list(reasons), list(reasons.values()), color='#6366f1')
    ax.set(title='Protection events', ylabel='Count'); fig.autofmt_xdate(rotation=30); fig.tight_layout(); figures.append(fig)

    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(list(usernames), list(usernames.values()), color='#0891b2')
    ax.set(title='Attempts per demo username', ylabel='Count'); fig.autofmt_xdate(rotation=30); fig.tight_layout(); figures.append(fig)

    with PdfPages(OUTPUT / 'login_analysis_report.pdf') as pdf:
        cover, ax = plt.subplots(figsize=(8, 6))
        ax.axis('off')
        summary = (f'Login Protection Simulator — Academic Report\n\n'
                   f'Attempts: {len(rows)}\nSuccessful: {successes}\nFailed: {failures}\n'
                   f'Honeypot triggers: {reasons["honeypot_triggered"]}\n'
                   f'Lockout events: {reasons["locked_due_failed_attempts"] + reasons["locked"]}\n\n'
                   f'Risk at last recorded event: {risk["score"]}/100 ({risk["level"]})\n'
                   f'Observed pattern: {risk["pattern"]}\n'
                   f'Scenario labels (synthetic ground truth): {dict(scenarios)}\n\n'
                   'Heuristic signals are not proof of attack type.\n'
                   'Only synthetic local test traffic. Passwords are never logged.')
        ax.text(.08, .9, summary, transform=ax.transAxes, va='top', fontsize=13)
        pdf.savefig(cover); plt.close(cover)
        for index, fig in enumerate(figures, 1):
            fig.savefig(OUTPUT / f'chart_{index}.png', dpi=140)
            pdf.savefig(fig); plt.close(fig)
    print(f'Report generated: {OUTPUT / "login_analysis_report.pdf"}')


if __name__ == '__main__':
    main()
