"""进程回收证据只认可指定原生用例，不把跳过或包级成功算作通过。"""
import json
import pathlib
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import verify_process_lifecycle as lifecycle


class ProcessLifecycleEvidenceTests(unittest.TestCase):
    def test_comparison_executes_same_readonly_binary_without_a_compiler(self):
        state = {'directory': '/owned', 'project': 'owned'}
        control = lifecycle.service_definition(state, 'image', '/cache', '/binary', False)
        fixed = lifecycle.service_definition(state, 'image', '/cache', '/binary', True)
        self.assertEqual({k: v for k, v in control.items() if k != 'init'}, {k: v for k, v in fixed.items() if k != 'init'})
        self.assertEqual(fixed['command'][0], '/tmp/lifecycle-bin/test2json')
        self.assertNotIn('go', fixed['command'])
        self.assertIn('/binary:/tmp/lifecycle-bin:ro', fixed['volumes'])
        self.assertIn('-test.count=1', fixed['command'])
        self.assertIn('-test.timeout=120s', fixed['command'])

    def test_emulated_target_is_rejected_before_checking_images(self):
        for host in (b"linux/aarch64\n", b"windows/amd64\n", b"linux/armv7\n"):
            with self.subTest(host=host), mock.patch.object(lifecycle.remote, 'ssh', return_value=subprocess.CompletedProcess([], 0, host)) as ssh:
                with self.assertRaisesRegex(ValueError, '原生 Linux amd64'):
                    lifecycle.remote.verify_architecture({'host': 'owned'})
                self.assertEqual(ssh.call_count, 1)

    def test_native_host_and_every_image_must_match(self):
        state = {'host': 'owned', 'project': 'owned'}
        outputs = [b'linux/x86_64\n'] + [b'linux/amd64\n'] * 5
        with mock.patch.object(lifecycle.remote, 'ssh', side_effect=[subprocess.CompletedProcess([], 0, value) for value in outputs]) as ssh:
            lifecycle.remote.verify_architecture(state)
        self.assertEqual(ssh.call_count, 6)
        outputs[-1] = b'linux/arm64\n'
        with mock.patch.object(lifecycle.remote, 'ssh', side_effect=[subprocess.CompletedProcess([], 0, value) for value in outputs]), self.assertRaisesRegex(ValueError, '架构不一致'):
            lifecycle.remote.verify_architecture(state)

    def test_package_success_and_unrelated_tests_do_not_replace_required_tests(self):
        raw = '\n'.join(json.dumps(event) for event in [
            {"Action": "pass", "Package": "agent"},
            {"Action": "pass", "Test": "TestOther"},
            {"Action": "output", "Test": next(iter(lifecycle.TESTS))},
        ]).encode()
        self.assertEqual(lifecycle.test_results(raw), {})

    def test_failure_and_skip_are_preserved(self):
        names = sorted(lifecycle.TESTS)
        events = [{"Action": "fail", "Test": names[0]}, {"Action": "skip", "Test": names[1]}]
        self.assertEqual(lifecycle.test_results(('noise\n' + '\n'.join(map(json.dumps, events))).encode()), {names[0]: "fail", names[1]: "skip"})

    def test_duplicate_end_event_is_rejected(self):
        event = json.dumps({"Action": "pass", "Test": next(iter(lifecycle.TESTS))}).encode()
        with self.assertRaisesRegex(ValueError, "重复"):
            lifecycle.test_results(event + b'\n' + event)


if __name__ == "__main__":
    unittest.main()
