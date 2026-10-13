"""Synthetic, bounded, loopback-only login scenarios. Never use against real services."""
import argparse
import random
import re
import time
from html import unescape
from urllib.parse import urlsplit
import requests

URL = 'http://127.0.0.1:5000/'
DEMO_USERS = ('alice', 'admin_test', 'root_local', 'unknown_demo')
DEMO_PASSWORDS = ('wrong-demo-1', 'wrong-demo-2', 'guess123', 'DemoPass123!')


def generate(scenario, attempts):
    for i in range(attempts):
        if scenario == 'bruteforce':
            yield 'alice', f'wrong-guess-{i}'
        elif scenario == 'spraying':
            yield DEMO_USERS[i % len(DEMO_USERS)], 'CommonDemoGuess!'
        elif scenario == 'stuffing':
            yield DEMO_USERS[i % len(DEMO_USERS)], f'synthetic-pair-{i}'
        else:
            yield random.choice(DEMO_USERS), random.choice(DEMO_PASSWORDS)


def run(scenario='mixed', attempts=30, delay=0.1):
    if urlsplit(URL).hostname not in ('localhost', '127.0.0.1', '::1'):
        raise ValueError('Only loopback addresses are allowed')
    for number, (username, password) in enumerate(generate(scenario, attempts), 1):
        try:
            response = requests.post(URL, data={'username': username, 'password': password},
                                     headers={'X-Demo-Scenario': scenario}, timeout=5)
            response.raise_for_status()
            match = re.search(r'<div class="notice" role="status">(.*?)</div>', response.text, re.S)
            result = unescape(re.sub('<[^>]*>', '', match.group(1))).strip() if match else 'No response message'
            print(f'{number}/{attempts} [{scenario}] {username}: {result}')
        except requests.RequestException as error:
            print(f'Local simulator unavailable: {error}')
            break
        time.sleep(delay)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Synthetic local login attack scenarios')
    parser.add_argument('--scenario', choices=['mixed', 'bruteforce', 'spraying', 'stuffing'], default='mixed')
    parser.add_argument('--attempts', type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.attempts <= 100:
        parser.error('--attempts must be between 1 and 100')
    run(args.scenario, args.attempts)
