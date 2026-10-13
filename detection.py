"""Explainable rolling-window heuristics for synthetic login traffic."""
from collections import Counter

WINDOW_SECONDS = 60


def assess(events, now):
    """Score activity observed within 60 seconds; never inspect password values."""
    recent = [e for e in events if 0 <= now - float(e['ts']) <= WINDOW_SECONDS]
    failures = [e for e in recent if str(e['success']).lower() != 'true']
    accounts = {e['username'] for e in failures}
    per_account = Counter(e['username'] for e in failures)
    max_target = max(per_account.values(), default=0)
    honeypots = sum(e['reason'] == 'honeypot_triggered' for e in recent)
    score = min(100, min(len(failures), 10) * 4 + min(max_target, 8) * 5 +
                min(len(accounts), 8) * 5 + min(honeypots, 2) * 20)
    if honeypots:
        category = 'honeypot activity'
    elif len(accounts) >= 3 and len(failures) >= 6:
        category = 'multi-account burst (spraying/stuffing-like)'
    elif max_target >= 3:
        category = 'single-account brute-force pattern'
    else:
        category = 'insufficient evidence'
    level = 'high' if score >= 65 else 'medium' if score >= 35 else 'low'
    signals = {'failures_60s': len(failures), 'targeted_accounts_60s': len(accounts),
               'max_failures_one_account_60s': max_target, 'honeypot_hits_60s': honeypots}
    return {'score': score, 'level': level, 'pattern': category, 'signals': signals,
            'detected': level in ('medium', 'high')}
