"""验收环境的凭据文件和路径必须限制在本项目，不覆盖已有制品。"""
import importlib.util
import json
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import remote_review

spec = importlib.util.spec_from_file_location('review_runtime', ROOT / 'tests/acceptance/review_runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
capture_spec = importlib.util.spec_from_file_location('review_capture_runtime', ROOT / 'tests/acceptance/review_capture_runtime.py')
capture_runtime = importlib.util.module_from_spec(capture_spec)
capture_spec.loader.exec_module(capture_runtime)


class ReviewBoundaryTest(unittest.TestCase):
    def test_isolated_capture_never_starts_embedded_agent_with_same_identity(self):
        self.assertEqual(runtime.supervised_roles({})[-1], ('agent', 'starbeacon-agent'))
        roles = runtime.supervised_roles({'collector_execution': 'isolated_managed'})
        self.assertEqual([name for name, _ in roles], ['platform', 'ingest', 'worker'])
        for invalid in ('unknown', None, True):
            with self.assertRaises(ValueError):
                runtime.supervised_roles({'collector_execution': invalid})

    def test_managed_capture_requires_owned_persistent_directory_and_fixed_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / '.local/acceptance/capture-ui.json'
            path.parent.mkdir(parents=True)
            state = {'project': 'sbacc_1234567890abcdef'}
            review = {'directory': '/tmp/starbeacon-acceptance-sbacc_1234567890abcdef/review-1234567890abcdef'}
            valid = {'project': state['project'], 'bundle': review['directory'] + '/capture-ui-1234567890abcdef', 'agent_data': review['directory'] + '/capture-ui-1234567890abcdef/agent-data', 'scope': 'isolated_live_capture_ui_review', 'host_network': False, 'host_network_admin': False, 'capabilities': ['NET_RAW', 'SETFCAP']}
            with patch.object(remote_review, 'ROOT', root):
                self.assertIsNone(remote_review.managed_capture_metadata(state, review))
                path.write_text(json.dumps(valid))
                got = remote_review.managed_capture_metadata(state, review)
                self.assertEqual(got['agent_data'], valid['agent_data'])
                service = remote_review.capture_service(state, 'sha256:fixture', review['directory'] + '/bundle-1234567890abcdef', got, {'security_opt': ['no-new-privileges:true']})
                self.assertEqual(service['volumes'][0], valid['agent_data'] + ':/data')
                self.assertEqual(service['volumes'][1], review['directory'] + '/bundle-1234567890abcdef/capture_runtime.py:/capture-review/capture_runtime.py:ro')
                self.assertEqual(service['network_mode'], 'service:review')
                self.assertEqual(service['cap_add'], ['NET_RAW', 'SETFCAP'])
                self.assertNotIn('environment', service)
                for change in ({'project': 'other'}, {'bundle': '/tmp/other'}, {'agent_data': review['directory'] + '/data'}, {'agent_data': '../agent-data'}, {'host_network': True}, {'host_network_admin': True}, {'capabilities': ['NET_ADMIN']}):
                    path.write_text(json.dumps(dict(valid, **change)))
                    with self.subTest(change=change), self.assertRaises(ValueError):
                        remote_review.managed_capture_metadata(state, review)

    def test_capture_runtime_never_inherits_platform_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            data = pathlib.Path(directory)
            path = data / 'agent.json'
            valid = {'SB_SENSOR_ID': 'sensor_review', 'SB_TENANT_ID': 'review_1234567890abcdef', 'SB_STATE_PATH': '/data/agent.db'}
            path.write_text(json.dumps(valid))
            config = capture_runtime.configuration(data)
            self.assertEqual(config['SB_STATE_PATH'], valid['SB_STATE_PATH'])
            self.assertEqual(config['SB_CAPTURE_MANAGED'], 'true')
            self.assertEqual(config['SB_CAPTURE_SPOOL_BYTES'], '104857600')
            for key in ('SB_DATABASE_URL', 'SB_MIGRATION_DATABASE_URL', 'SB_REDIS_URL', 'SB_NATS_URL'):
                path.write_text(json.dumps(dict(valid, **{key: 'fixture'})))
                with self.subTest(key=key), self.assertRaises(ValueError):
                    capture_runtime.configuration(data)
            path.unlink()
            with self.assertRaises(ValueError):
                capture_runtime.configuration(data)

    def test_state_replacement_retains_private_mode_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'review.json'
            with patch.object(remote_review, 'STATE', path):
                remote_review.write_review({'runtime_backend_source': 'first'})
                remote_review.write_review({'runtime_backend_source': 'second'})
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(json.loads(path.read_text()), {'runtime_backend_source': 'second'})
                path.unlink()
                target = pathlib.Path(temporary) / 'original'
                target.write_text('must remain')
                path.symlink_to(target)
                with self.assertRaises(ValueError):
                    remote_review.write_review({})
                self.assertEqual(target.read_text(), 'must remain')

    def test_private_artifact_is_owner_only_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            file = pathlib.Path(temporary) / 'config.json'
            runtime.private_json(file, {'identity': 'fixture'})
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                runtime.private_json(file, {'identity': 'replacement'})
            self.assertEqual(json.loads(file.read_text()), {'identity': 'fixture'})
            link = pathlib.Path(temporary) / 'link.json'
            link.symlink_to(file)
            with self.assertRaises(FileExistsError):
                runtime.private_json(link, {})

    def test_migration_rejects_business_databases_and_mismatched_tenants(self):
        with tempfile.TemporaryDirectory() as temporary:
            data = pathlib.Path(temporary)
            config = data / 'config.json'
            with patch.object(runtime, 'CONFIG', config), patch.object(runtime, 'DATA', data), patch.object(runtime.subprocess, 'run') as execute:
                (data/'ready.json').write_text(json.dumps({'tenant':'own','scope':'development_ui_review'}))
                for candidate in ({'database':'starbeacon','tenant':'own'}, {'database':'sbui_1234567890abcdef','tenant':'other'}):
                    config.write_text(json.dumps(candidate))
                    with self.assertRaises(ValueError):
                        runtime.migrate()
                execute.assert_not_called()

    def test_migration_only_runs_schema_and_permission_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            data=pathlib.Path(temporary)
            config=data/'config.json'
            config.write_text(json.dumps({'database':'sbui_1234567890abcdef','tenant':'own'}))
            (data/'ready.json').write_text(json.dumps({'tenant':'own','scope':'development_ui_review'}))
            platform={'SB_DATABASE_URL':'postgres://fixture@postgres/sbui_1234567890abcdef','SB_CREDENTIAL_KEY':'fixture-private'}
            agent={'SB_TENANT_ID':'own','SB_SENSOR_ID':'sensor_review','SB_LOCAL_PASSWORD':'fixture-password'}
            for name,value in (('platform',platform),('agent',agent)):
                (data/(name+'.json')).write_text(json.dumps(value))
            with patch.object(runtime,'CONFIG',config),patch.object(runtime,'DATA',data),patch.dict(runtime.os.environ,{'POSTGRES_PASSWORD':'fixture-value','SB_RUNTIME_DB_PASSWORD':'fixture-runtime'}),patch.object(runtime.subprocess,'run') as execute:
                execute.return_value.returncode=0
                runtime.migrate()
                self.assertEqual([call.args[0] for call in execute.call_args_list],[['starbeaconctl','migrate'],['starbeaconctl','runtime-role']])
                for call in execute.call_args_list:
                    self.assertIn('/sbui_1234567890abcdef?',call.kwargs['env']['SB_MIGRATION_DATABASE_URL'])
                for name,prior in (('platform',platform),('agent',agent)):
                    path=data/(name+'.json')
                    current=json.loads(path.read_text())
                    self.assertEqual(current,{**prior,'SB_TRUSTED_PROXY_CIDRS':'127.0.0.1/32,::1/128'})
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
                execute.return_value.returncode=1
                with self.assertRaises(ValueError):
                    runtime.migrate()

    def test_migration_rejects_foreign_or_symlinked_identity_before_database_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            data=pathlib.Path(temporary)
            config=data/'config.json'
            config.write_text(json.dumps({'database':'sbui_1234567890abcdef','tenant':'own'}))
            (data/'ready.json').write_text(json.dumps({'tenant':'own','scope':'development_ui_review'}))
            (data/'platform.json').write_text(json.dumps({'SB_DATABASE_URL':'postgres://fixture@postgres/other'}))
            (data/'agent.json').write_text(json.dumps({'SB_TENANT_ID':'own','SB_SENSOR_ID':'sensor_review'}))
            with patch.object(runtime,'CONFIG',config),patch.object(runtime,'DATA',data),patch.object(runtime.subprocess,'run') as execute:
                with self.assertRaises(ValueError):runtime.migrate()
                execute.assert_not_called()
                (data/'platform.json').unlink()
                (data/'platform.json').symlink_to(data/'agent.json')
                with self.assertRaises(ValueError):runtime.migrate()
                execute.assert_not_called()

    def test_review_cannot_select_another_directory_project_or_privileged_port(self):
        state = {'project': 'sbacc_1234567890abcdef', 'directory': '/tmp/starbeacon-acceptance-sbacc_1234567890abcdef'}
        valid = {'project': state['project'], 'name': 'review_1234567890abcdef', 'directory': state['directory'] + '/review_1234567890abcdef', 'platform_port': 35174, 'collector_port': 35175}
        valid['name'] = 'review-1234567890abcdef'
        valid['directory'] = state['directory'] + '/' + valid['name']
        valid['database'] = 'sbui_1234567890abcdef'
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / 'review.json'
            with patch.object(remote_review, 'STATE', path), patch.object(remote_review.acceptance, 'read_state', return_value=state):
                path.write_text(json.dumps(valid))
                self.assertEqual(remote_review.read_review(), (state, valid))
                for change in ({'project': 'other'}, {'name': '../other'}, {'directory': '/tmp/other'}, {'database': 'starbeacon'}, {'database': 'sbui_0000000000000000'}, {'database': None}, {'platform_port': True}, {'collector_port': 80}, {'platform_port': 65536}):
                    path.write_text(json.dumps(dict(valid, **change)))
                    with self.subTest(change=change), self.assertRaises(ValueError):
                        remote_review.read_review()

    def test_ui_update_refuses_a_backend_from_another_workspace_snapshot(self):
        with patch.object(remote_review.acceptance, 'snapshot_sources', return_value=({}, 'current')), patch.object(remote_review.acceptance, 'verify_image') as verify:
            with self.assertRaises(ValueError):
                remote_review.backend_image({'workspace_sha256': 'previous'})
            verify.assert_not_called()

    def test_frontend_snapshot_requires_both_builds_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with patch.object(remote_review, 'ROOT', root):
                with self.assertRaises(ValueError):
                    remote_review.frontend_files()
                for app in ('platform', 'collector'):
                    directory = root / 'web' / app / 'dist'
                    directory.mkdir(parents=True)
                    (directory / 'index.html').write_text('fixture-' + app)
                files, digest = remote_review.frontend_files()
                self.assertEqual(set(files), {'ui/platform/index.html', 'ui/collector/index.html'})
                self.assertEqual(len(digest), 64)
                (root / 'web/platform/dist/index.html').write_text('changed')
                self.assertNotEqual(remote_review.frontend_files()[1], digest)
                (root / 'web/platform/dist/leak').symlink_to(root / 'web/collector/dist/index.html')
                with self.assertRaises(ValueError):
                    remote_review.frontend_files()


if __name__ == '__main__':
    unittest.main()
