"""编译准备不能代替用例执行，失败时不得继续生成业务验收报告。"""
import pathlib
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import remote_acceptance as acceptance


class BackendPreparationTests(unittest.TestCase):
    state = {'host': 'owned', 'directory': '/tmp/starbeacon-acceptance-sbacc_' + 'a' * 16}

    def test_preparation_keeps_original_cases_and_execution_deadlines(self):
        calls = []
        def compose(_state, args, **options):
            calls.append((args, options.get('timeout')))
            return subprocess.CompletedProcess([], 0, stdout=b'')
        with mock.patch.object(acceptance, 'compose', side_effect=compose), mock.patch.object(acceptance, 'ssh'):
            acceptance.run_backend(self.state)
        preparations = [(args, timeout) for args, timeout in calls if '--entrypoint' in args and 'go' in args]
        self.assertEqual(len(preparations), 2)
        for args, timeout in preparations:
            self.assertIn('-run=^$', args)
            self.assertIn('-count=1', args)
            self.assertIn('-race', args)
            self.assertIn('-json', args)
            self.assertEqual(timeout, 600)
            self.assertFalse(any(arg.startswith('-coverprofile=') for arg in args))
        actual = [(args[-1], timeout) for args, timeout in calls if args[0] == 'run' and '--entrypoint' not in args]
        self.assertEqual(actual, [('runner', 3000), ('capture-runner', 360)])
        self.assertLess(calls.index(preparations[0]), next(i for i, (args, _) in enumerate(calls) if args[-1] == 'runner' and '--entrypoint' not in args))

    def test_failed_preparation_never_starts_real_cases_or_capture(self):
        calls = []
        def compose(_state, args, **_options):
            calls.append(args)
            if args[0] == 'ps':
                return subprocess.CompletedProcess([], 0, stdout=b'')
            raise subprocess.CalledProcessError(1, args)
        with mock.patch.object(acceptance, 'compose', side_effect=compose), mock.patch.object(acceptance, 'ssh'), self.assertRaises(subprocess.CalledProcessError):
            acceptance.run_backend(self.state)
        self.assertEqual(len(calls), 2)
        self.assertIn('-run=^$', calls[-1])
        self.assertFalse(any(args[0] == 'run' and 'capture-runner' in args for args in calls))


if __name__ == '__main__':
    unittest.main()
