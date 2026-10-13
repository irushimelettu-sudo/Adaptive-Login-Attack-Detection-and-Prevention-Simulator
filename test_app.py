import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import app as project


class SimulatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.patches = [patch.object(project, 'USERS_FILE', root / 'users.json'), patch.object(project, 'CSV_FILE', root / 'timeline.csv')]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_login_and_lockout(self):
        self.assertIn('successful', project.check_login('alice', 'DemoPass123!', now=100))
        for _ in range(2):
            self.assertEqual('Invalid credentials', project.check_login('alice', 'wrong', now=101))
        self.assertIn('locked', project.check_login('alice', 'wrong', now=102))
        self.assertIn('locked', project.check_login('alice', 'DemoPass123!', now=103))
        self.assertIn('successful', project.check_login('alice', 'DemoPass123!', now=113))

    def test_honeypot_never_authenticates(self):
        self.assertIn('locked', project.check_login('admin_test', 'HoneyDemo123!', now=100))

    def test_log_does_not_contain_password(self):
        project.check_login('alice', 'secret-attempt', now=100)
        self.assertNotIn('secret-attempt', project.CSV_FILE.read_text())

    def test_dashboard_stats(self):
        project.check_login('alice', 'wrong', now=100)
        project.check_login('admin_test', 'wrong', now=101)
        response = project.app.test_client().get('/api/stats')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['total'], 2)
        self.assertEqual(data['failed'], 2)
        self.assertEqual(data['honeypot_events'], 1)
        self.assertNotIn('password', str(data).lower())
        self.assertEqual(project.app.test_client().get('/dashboard').status_code, 200)

    def test_http(self):
        response = project.app.test_client().get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Login Protection Simulator', response.data)


if __name__ == '__main__':
    unittest.main()

class DetectionTests(unittest.TestCase):
    def test_single_account_pattern(self):
        from detection import assess
        events = [{'ts': 100+i, 'username': 'alice', 'success': 'False', 'reason': 'invalid'} for i in range(5)]
        result = assess(events, 105)
        self.assertEqual(result['pattern'], 'single-account brute-force pattern')
        self.assertTrue(result['detected'])

    def test_multi_account_pattern(self):
        from detection import assess
        events = [{'ts': 100+i, 'username': f'user{i%4}', 'success': 'False', 'reason': 'invalid'} for i in range(8)]
        self.assertIn('multi-account', assess(events, 108)['pattern'])

    def test_old_events_expire(self):
        from detection import assess
        events = [{'ts': 10, 'username': 'alice', 'success': 'False', 'reason': 'invalid'}]
        self.assertEqual(assess(events, 100)['score'], 0)

    def test_scenario_generators(self):
        from attacker import generate
        for scenario in ('bruteforce', 'spraying', 'stuffing', 'mixed'):
            self.assertEqual(len(list(generate(scenario, 10))), 10)
