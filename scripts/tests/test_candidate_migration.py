"""保证实际 ZIP 升级先迁移已有数据库，并保留失败依据和设备身份。"""
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import unittest
import unittest.mock as mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import remote_candidate_review as candidate


def instance():
    state = {'project': 'sbacc_'+'a'*16, 'host': 'owned', 'directory': '/tmp/starbeacon-acceptance-sbacc_'+'a'*16, 'workspace_sha256': 'b'*64}
    name = 'review-'+'c'*16
    root = state['directory']+'/'+name
    directory = root+'/candidate-'+'d'*16
    review = {'scope': 'development_ui_review', 'name': name, 'directory': root, 'database': 'sbui_'+'c'*16}
    runtime = {'image': 'sha256:'+'e'*64, 'entrypoint': ['python3','/review/runtime.py'], 'environment': {key: '${'+key+'}' for key in ('SB_RUNTIME_DB_PASSWORD','REDIS_PASSWORD','NATS_TOKEN')}, 'volumes': [root+'/data:/data',root+'/bundle:/review:ro',*[directory+'/bin/'+role+':/usr/local/bin/'+role+':ro' for role in candidate.ROLES['platform']]], 'read_only': True, 'cap_drop': ['ALL'], 'user': '65532:65532', 'healthcheck': {'test': ['CMD','true']}, 'depends_on': {'review-init': {'condition': 'service_completed_successfully'}}, 'ports': ['127.0.0.1:5184:8080'], 'restart': 'unless-stopped'}
    return state, review, {'services': {'review': runtime}}, directory


class CandidateMigrationTests(unittest.TestCase):
    def test_frontend_only_requires_matching_metadata_and_actual_online_bytes(self):
        state, review, _, _ = instance()
        image='sha256:'+'e'*64
        binaries={'starbeacon':{'sha256':'f'*64}}
        checksums={'version':'v0.1.0-rc.1','commit':'f'*40}
        review.update(runtime_backend_image=image,runtime_candidate={'status':'passed','backend_source':state['workspace_sha256'],'binaries':binaries,**checksums})
        with mock.patch.object(candidate,'verify_online') as observe:
            self.assertTrue(candidate.verified_frontend_only(state,review,image,binaries,checksums))
            observe.assert_called_once_with(state,image,binaries,checksums)
        for field,value in [('backend_source','0'*64),('status','failed'),('version','v0.1.0'),('binaries',{}),('commit','0'*40)]:
            other=copy.deepcopy(review);other['runtime_candidate'][field]=value
            with self.subTest(field=field), mock.patch.object(candidate,'verify_online') as observe:
                self.assertFalse(candidate.verified_frontend_only(state,other,image,binaries,checksums))
                observe.assert_not_called()
        with mock.patch.object(candidate,'verify_online',side_effect=ValueError('在线字节不同')), self.assertRaises(ValueError):
            candidate.verified_frontend_only(state,review,image,binaries,checksums)

    def test_frontend_activation_never_stops_or_removes_capture_or_platform(self):
        state,review,definition,directory=instance()
        original=copy.deepcopy(definition);events=[]
        with mock.patch.object(candidate,'migrate_candidate',side_effect=lambda *_:(events.append('migrate') or {'status':'passed'})), mock.patch.object(candidate.review_tools,'compose',side_effect=lambda _s,_r,args,**_k:events.append(args)), mock.patch.object(candidate,'remove_stopped_dependencies',side_effect=lambda _s,services:events.append(services)), mock.patch.object(candidate.acceptance,'ssh',side_effect=lambda *_a,**_k:events.append('copy')):
            candidate.activate_frontend(state,review,definition,directory)
        self.assertEqual(definition,original)
        self.assertEqual(events,['migrate',['stop','--timeout','15','review-web'],('review-web',),'copy',['up','-d','--no-deps','review-web']])

    def test_failed_frontend_migration_preserves_running_gateway_and_capture(self):
        with mock.patch.object(candidate,'migrate_candidate',side_effect=ValueError('迁移失败')), mock.patch.object(candidate.review_tools,'compose') as compose, mock.patch.object(candidate,'remove_stopped_dependencies') as remove, mock.patch.object(candidate.acceptance,'ssh') as ssh, self.assertRaisesRegex(ValueError,'迁移失败'):
            candidate.activate_frontend(*instance())
        compose.assert_not_called();remove.assert_not_called();ssh.assert_not_called()

    def test_dependency_scope_rejects_other_roles_or_unrequested_container(self):
        state,_,_,_=instance()
        for services in ((),('review',),('postgres',),('review-web','review-web')):
            with self.subTest(services=services), mock.patch.object(candidate.acceptance,'ssh') as ssh, self.assertRaises(ValueError):
                candidate.remove_stopped_dependencies(state,services)
            ssh.assert_not_called()
        data=json.dumps([{'service':'review-capture','id':'f'*64}]).encode()
        with mock.patch.object(candidate.acceptance,'ssh',return_value=subprocess.CompletedProcess([],0,data)) as ssh,self.assertRaises(ValueError):
            candidate.remove_stopped_dependencies(state,('review-web',))
        self.assertEqual(ssh.call_count,1)

    def test_migration_uses_zip_cli_and_minimal_owned_mounts_without_reinitializing(self):
        state, review, definition, directory = instance()
        original = copy.deepcopy(definition)
        result = candidate.migration_service(state, review, definition, directory)
        runtime = result['services']['review-migrate']
        self.assertEqual(definition, original)
        self.assertEqual(set(result['services']), {'review-migrate'})
        self.assertEqual(runtime['command'], ['migrate'])
        self.assertEqual(runtime['entrypoint'], ['python3','/migration/runtime.py'])
        self.assertEqual(runtime['volumes'], [review['directory']+'/data:/data', review['directory']+'/bundle:/review:ro',directory+'/bin/starbeaconctl:/usr/local/bin/starbeaconctl:ro',directory+'/migration-runtime.py:/migration/runtime.py:ro'])
        self.assertEqual(runtime['environment'], {'SB_RUNTIME_DB_PASSWORD':'${SB_RUNTIME_DB_PASSWORD}','POSTGRES_PASSWORD':'${POSTGRES_PASSWORD}'})
        self.assertNotIn('POSTGRES_PASSWORD', definition['services']['review']['environment'])
        self.assertTrue(runtime['read_only'])
        self.assertTrue(runtime['init'])
        self.assertEqual(runtime['cap_drop'], ['ALL'])
        self.assertTrue(all(key not in runtime for key in ('depends_on','healthcheck','ports','container_name')))
        self.assertEqual(runtime['restart'], 'no')
        self.assertEqual(runtime['labels']['io.starbeacon.candidate.source'], state['workspace_sha256'])

    def test_foreign_instance_and_database_are_rejected_before_stopping_roles(self):
        for field, value in [('scope','production'),('database','production'),('directory','/other/review-'+'c'*16),('name','review-other')]:
            state, review, definition, directory = instance()
            review[field] = value
            with self.subTest(field=field), mock.patch.object(candidate,'stop_roles') as stop, mock.patch.object(candidate.acceptance,'ssh') as ssh, self.assertRaises(ValueError):
                candidate.activate_candidate(state, review, definition, directory)
            stop.assert_not_called()
            ssh.assert_not_called()

    def test_foreign_candidate_directory_cannot_activate(self):
        state, review, definition, directory = instance()
        for value in (directory+'/../candidate-'+'f'*16, '/other/candidate-'+'d'*16, directory[:-1]):
            with self.subTest(value=value), mock.patch.object(candidate,'stop_roles') as stop, self.assertRaises(ValueError):
                candidate.activate_candidate(state, review, definition, value)
            stop.assert_not_called()

    def test_invalid_cli_config_or_network_cannot_activate(self):
        changes = [lambda r: r.update(network_mode='host'), lambda r: r.update(entrypoint=['starbeaconctl','bootstrap']), lambda r: r['volumes'].remove(next(v for v in r['volumes'] if '/bin/starbeaconctl:' in v)), lambda r: r['volumes'].append('/foreign:/data'), lambda r: r['volumes'].__setitem__(1,'/foreign:/review:ro'), lambda r: r['volumes'].__setitem__(1,r['volumes'][1].replace('/bundle:', '/../other:')), lambda r: r['environment'].update(POSTGRES_PASSWORD='secret'), lambda r: r['environment'].pop('SB_RUNTIME_DB_PASSWORD')]
        for index, change in enumerate(changes):
            state, review, definition, directory = instance()
            change(definition['services']['review'])
            with self.subTest(index=index), mock.patch.object(candidate,'stop_roles') as stop, mock.patch.object(candidate.acceptance,'ssh') as ssh, self.assertRaises(ValueError):
                candidate.activate_candidate(state, review, definition, directory)
            stop.assert_not_called()
            ssh.assert_not_called()

    def test_activation_waits_for_migration_before_starting_candidate_roles(self):
        args = instance()
        events = []
        receipt = {'status':'passed','exit_code':0}
        def migrate(*_):
            events.append('migrate')
            return receipt
        with mock.patch.object(candidate,'stop_roles',side_effect=lambda *_:events.append('stop')), mock.patch.object(candidate.acceptance,'ssh',side_effect=lambda *_a,**_k:events.append('copy')), mock.patch.object(candidate,'migrate_candidate',side_effect=migrate), mock.patch.object(candidate,'start_roles',side_effect=lambda *_:events.append('start')):
            self.assertEqual(candidate.activate_candidate(*args), receipt)
        self.assertEqual(events, ['stop','copy','migrate','start'])

    def test_failed_migration_does_not_start_candidate(self):
        with mock.patch.object(candidate,'stop_roles'), mock.patch.object(candidate.acceptance,'ssh'), mock.patch.object(candidate,'migrate_candidate',side_effect=ValueError('迁移失败')), mock.patch.object(candidate,'start_roles') as start, self.assertRaisesRegex(ValueError,'迁移失败'):
            candidate.activate_candidate(*instance())
        start.assert_not_called()

    def test_success_records_actual_exit_and_log_digest(self):
        state, review, definition, directory = instance()
        output = '界面验收数据库结构与运行权限已就绪\n'.encode()
        observation={'container':'owned-migration','container_id':'f'*64,'state':{'ExitCode':0,'Running':False,'OOMKilled':False}}
        with mock.patch.object(candidate.review_tools,'compose',return_value=subprocess.CompletedProcess([],0,output)) as compose, mock.patch.object(candidate.acceptance,'ssh') as ssh, mock.patch.object(candidate,'migration_observation',return_value=observation):
            result = candidate.migrate_candidate(state, review, definition, directory)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['log_sha256'], hashlib.sha256(output).hexdigest())
        self.assertEqual(result['database'], review['database'])
        self.assertEqual(compose.call_args.args[2], ['-f',directory+'/migrate.json','run','--no-deps','-T','--name',state['project']+'-review-migrate-'+'d'*16,'review-migrate'])
        self.assertEqual(result['execution'], observation)
        self.assertEqual(ssh.call_args_list[1].kwargs['input'], output)
        self.assertEqual(json.loads(ssh.call_args_list[2].kwargs['input']), result)

    def test_failed_process_retains_actual_exit_and_log(self):
        state, review, definition, directory = instance()
        error = subprocess.CalledProcessError(7, ['compose'], output=b'migration unavailable\n')
        with mock.patch.object(candidate.review_tools,'compose',side_effect=error), mock.patch.object(candidate.acceptance,'ssh') as ssh, self.assertRaisesRegex(ValueError,'执行记录已保留'):
            candidate.migrate_candidate(state, review, definition, directory)
        result = json.loads(ssh.call_args_list[-1].kwargs['input'])
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['exit_code'], 7)
        self.assertEqual(ssh.call_args_list[-2].kwargs['input'], error.output)

    def test_timeout_and_oversize_output_never_pass(self):
        for execution in (subprocess.TimeoutExpired(['compose'],200,output=b'timed out\n'), subprocess.CompletedProcess([],0,b'x'*(512*1024+1))):
            patches = {'side_effect':execution} if isinstance(execution,Exception) else {'return_value':execution}
            with self.subTest(execution=type(execution).__name__), mock.patch.object(candidate.review_tools,'compose',**patches), mock.patch.object(candidate.acceptance,'ssh') as ssh, self.assertRaises(ValueError):
                candidate.migrate_candidate(*instance())
            result = json.loads(ssh.call_args_list[-1].kwargs['input'])
            self.assertEqual(result['status'], 'failed')
            self.assertLessEqual(len(ssh.call_args_list[-2].kwargs['input']),512*1024)

    def test_control_success_requires_independent_actual_exit_observation(self):
        with mock.patch.object(candidate.review_tools,'compose',return_value=subprocess.CompletedProcess([],0,b'ready\n')), mock.patch.object(candidate.acceptance,'ssh') as ssh, mock.patch.object(candidate,'migration_observation',side_effect=ValueError('实际程序来源不同')), self.assertRaisesRegex(ValueError,'启动已停止'):
            candidate.migrate_candidate(*instance())
        receipt=json.loads(ssh.call_args_list[-1].kwargs['input'])
        self.assertEqual(receipt['status'],'failed')
        self.assertEqual(receipt['exit_code'],0)
        self.assertEqual(receipt['observation_error'],'ValueError')


if __name__ == '__main__':
    unittest.main()
