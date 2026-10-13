"""核对独立运行实例的来源约束，以及只读查看和变更操作的项目边界。"""
import contextlib
import copy
import io
import pathlib
import subprocess
import sys
import unittest
import unittest.mock as mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import remote_candidate_review as candidate
import remote_review as review_tools


def instance():
    state = {'project': 'sbacc_owned', 'host': 'owned_host', 'directory': '/tmp/starbeacon-acceptance-sbacc_owned'}
    directory = state['directory'] + '/review-' + 'a' * 16
    review = {'project': state['project'], 'directory': directory, 'runtime_service_project': 'sbacc_owned_r91',
              'backend_source': 'c' * 64, 'frontend_source': 'd' * 64,
              'runtime_backend_source': 'e' * 64, 'runtime_frontend_source': 'f' * 64,
              'runtime_candidate': {'scope': 'engineering_actual_zip_review_not_formal_release', 'status': 'passed',
                                    'project': state['project'], 'base_project': state['project'], 'runtime_project': 'sbacc_owned_r91',
                                    'directory': directory + '/candidate-' + 'b' * 16, 'backend_source': 'e' * 64, 'frontend_source': 'f' * 64}}
    return state, review


class RuntimeIdentityTests(unittest.TestCase):
    def test_legacy_runtime_keeps_original_project(self):
        state, _ = instance()
        self.assertEqual(review_tools.active_runtime_project(state, {}), state['project'])

    def test_registered_runtime_selects_matching_source(self):
        state, review = instance()
        self.assertEqual(review_tools.active_runtime_project(state, review), 'sbacc_owned_r91')

    def test_cross_project_and_malformed_runtime_are_rejected(self):
        state, review = instance()
        for project in ('other_r91', 'sbacc_owned_r0', 'sbacc_owned_r91/other', 'sbacc_owned_r9999', None):
            with self.subTest(project=project), self.assertRaises(ValueError):
                review_tools.active_runtime_project(state, dict(review, runtime_service_project=project))

    def test_missing_or_inconsistent_evidence_cannot_fall_back(self):
        state, review = instance()
        changes = [('status', 'failed'), ('scope', 'production'), ('base_project', 'other'),
                   ('runtime_project', 'sbacc_owned_r92'), ('backend_source', '1' * 64),
                   ('frontend_source', '2' * 64), ('directory', None), ('directory', '/tmp/other/candidate-' + 'b' * 16)]
        for key, value in changes:
            with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                changed = copy.deepcopy(review)
                changed['runtime_candidate'][key] = value
                review_tools.active_runtime_project(state, changed)
        changed = copy.deepcopy(review)
        del changed['runtime_service_project']
        with self.assertRaises(ValueError):
            review_tools.active_runtime_project(state, changed)

    def test_status_uses_only_active_runtime_definition(self):
        state, review = instance()
        with mock.patch.object(review_tools.acceptance, 'ssh') as ssh:
            review_tools.compose(state, review, ['ps', '--all', 'review', 'review-web', 'review-capture'])
        arguments = ssh.call_args.args[1]
        self.assertEqual(arguments[arguments.index('-p') + 1], 'sbacc_owned_r91')
        self.assertEqual(arguments.count('-f'), 1)
        self.assertEqual(arguments[arguments.index('-f') + 1], review['runtime_candidate']['directory'] + '/isolated-runtime-compose.json')
        self.assertIn(state['directory'] + '/dependencies.env', arguments)

    def test_gateway_reads_active_container(self):
        state, review = instance()
        with mock.patch.object(review_tools.acceptance, 'ssh', return_value=subprocess.CompletedProcess([], 0, b'[]')) as ssh, contextlib.redirect_stdout(io.StringIO()):
            report = review_tools.verify_gateway(state, review)
        self.assertEqual(ssh.call_args.args[1][:3], ['docker', 'exec', 'sbacc_owned_r91-review-1'])
        self.assertEqual(report['runtime_project'], 'sbacc_owned_r91')
        self.assertEqual(report['backend_source'], review['runtime_backend_source'])

    def test_mutations_are_rejected_before_remote_access(self):
        state, review = instance()
        with mock.patch.object(review_tools.acceptance, 'ssh') as ssh:
            for arguments in (['up', '-d'], ['stop', 'review'], ['run', '--rm', 'review-init']):
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    review_tools.compose(state, review, arguments)
            ssh.assert_not_called()

    def test_candidate_update_rejects_before_artifact_or_remote_access(self):
        state, review = instance()
        with mock.patch.object(candidate.review_tools, 'read_review', return_value=(state, review)), \
             mock.patch.object(candidate.review_tools, 'backend_image') as image, \
             mock.patch.object(candidate.acceptance, 'ssh') as ssh, self.assertRaisesRegex(ValueError, '专属部署定义'):
            candidate.deploy(None)
        image.assert_not_called()
        ssh.assert_not_called()


if __name__ == '__main__':
    unittest.main()
