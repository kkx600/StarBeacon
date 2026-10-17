import json
import io
import contextlib
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import remote_acceptance as acceptance
import remote_review as review


class PersistentAcceptanceStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.project = 'sbacc_' + 'a' * 16

    def prepare(self, base):
        return subprocess.run([sys.executable, '-c', acceptance.PREPARE_DIRECTORY, str(base), self.project], capture_output=True, text=True)

    def test_private_persistent_owner_and_no_existing_project_takeover(self):
        base = self.root / 'persistent'
        self.assertEqual(self.prepare(base).returncode, 0)
        owner = base / self.project / 'owner.json'
        self.assertEqual(json.loads(owner.read_text())['project'], self.project)
        self.assertEqual(base.stat().st_mode & 0o777, 0o700)
        self.assertEqual(owner.stat().st_mode & 0o777, 0o600)
        sentinel = base / self.project / 'identity'
        sentinel.write_text('existing identity')
        self.assertNotEqual(self.prepare(base).returncode, 0)
        self.assertEqual(sentinel.read_text(), 'existing identity')

    def test_parent_symlink_and_shared_permissions_are_rejected(self):
        target = self.root / 'outside'
        target.mkdir(mode=0o700)
        link = self.root / 'link'
        link.symlink_to(target, target_is_directory=True)
        self.assertNotEqual(self.prepare(link).returncode, 0)
        self.assertFalse((target / self.project).exists())
        target.chmod(0o755)
        self.assertNotEqual(self.prepare(target).returncode, 0)
        self.assertFalse((target / self.project).exists())

    def test_saved_state_binds_exact_persistent_or_legacy_directory(self):
        state = {'host': 'owned', 'project': self.project, 'commit': 'b' * 40, 'workspace_sha256': 'c' * 64}
        path = self.root / 'state.json'
        for directory in (acceptance.PERSISTENT_DIRECTORY + '/' + self.project, '/tmp/starbeacon-acceptance-' + self.project):
            state['directory'] = directory
            path.write_text(json.dumps(state))
            self.assertEqual(acceptance.read_state(path)['directory'], directory)
        for directory in (acceptance.PERSISTENT_DIRECTORY + '/' + 'sbacc_' + 'd' * 16,
                          acceptance.PERSISTENT_DIRECTORY + '/' + self.project + '/../other', '/tmp', '/var/lib'):
            state['directory'] = directory
            path.write_text(json.dumps(state))
            with self.assertRaises(ValueError):
                acceptance.read_state(path)

    def review_fixture(self):
        root = self.root.resolve() / 'review'
        root.mkdir()
        files = {'config.json': {'tenant': 'review_owned', 'database': 'sbui_owned'},
                 'data/ready.json': {'tenant': 'review_owned', 'scope': 'development_ui_review'},
                 'data/agent.json': {'SB_TENANT_ID': 'review_owned', 'SB_STATE_PATH': '/data/agent.db'}}
        for role in ('platform', 'ingest', 'worker'):
            files['data/' + role + '.json'] = {'role': role}
        for name, value in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))
        for name in ('agent.db', 'pki/ca.crt', 'pki/server.crt', 'pki/server.key', 'trust/command.key', 'trust/command.pub', 'sensor/agent.crt', 'sensor/agent.key'):
            path = root / 'data' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'fixture-existing-content')
        return root

    def probe(self, root):
        return subprocess.run([sys.executable, '-c', review.EXISTING_IDENTITY_PROBE, str(root), 'sbui_owned', 'review_owned'], capture_output=True, text=True)

    def test_start_requires_existing_identity_and_wal_and_never_reinitializes(self):
        root = self.review_fixture()
        before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
        self.assertEqual(self.probe(root).returncode, 0)
        self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()})
        (root / 'data/agent.db').unlink()
        self.assertNotEqual(self.probe(root).returncode, 0)
        self.assertFalse((root / 'data/agent.db').exists())
        (root / 'data/agent.db').write_bytes(b'restored-exact-content')
        (root / 'data/ready.json').unlink()
        self.assertNotEqual(self.probe(root).returncode, 0)
        self.assertFalse((root / 'data/ready.json').exists())

    def test_identity_probe_rejects_cross_tenant_symlink_and_path_escape(self):
        root = self.review_fixture()
        agent = root / 'data/agent.json'
        original = agent.read_text()
        values = json.loads(original)
        for key, invalid in (('SB_TENANT_ID', 'other'), ('SB_STATE_PATH', '/data/../outside'), ('SB_STATE_PATH', '/other/agent.db')):
            agent.write_text(json.dumps(dict(values, **{key: invalid})))
            self.assertNotEqual(self.probe(root).returncode, 0)
        agent.write_text(original)
        certificate = root / 'data/sensor/agent.key'
        certificate.unlink()
        certificate.symlink_to(root / 'data/pki/server.key')
        self.assertNotEqual(self.probe(root).returncode, 0)


class ScopedCaptureMetadataTests(unittest.TestCase):
    def test_explicit_instance_path_does_not_consume_other_project_state(self):
        with tempfile.TemporaryDirectory() as directory:
            base=pathlib.Path(directory)
            global_file=base/'.local/acceptance/capture-ui.json'
            global_file.parent.mkdir(parents=True)
            global_file.write_text('{"project":"other"}')
            dedicated=base/'instance-capture.json'
            with mock.patch.object(review,'ROOT',base),mock.patch.object(review,'CAPTURE_STATE',dedicated):
                self.assertIsNone(review.managed_capture_metadata({'project':'owned'},{'directory':'/owned'}))
                dedicated.write_text('{"project":"other"}')
                with self.assertRaises(ValueError):
                    review.managed_capture_metadata({'project':'owned'},{'directory':'/owned'})
            self.assertEqual(global_file.read_text(),'{"project":"other"}')

    def test_scoped_capture_still_requires_exact_instance_and_safe_capabilities(self):
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'capture.json'
            instance={'directory':'/var/lib/starbeacon-acceptance/sbacc_'+ 'a'*16+'/review-'+ 'b'*16}
            project='sbacc_'+'a'*16
            bundle=instance['directory']+'/capture-ui-'+ 'c'*16
            value={'project':project,'scope':'isolated_live_capture_ui_review','bundle':bundle,'agent_data':bundle+'/agent-data','host_network':False,'host_network_admin':False,'capabilities':['NET_RAW','SETFCAP']}
            with mock.patch.object(review,'CAPTURE_STATE',path):
                path.write_text(json.dumps(value))
                self.assertEqual(review.managed_capture_metadata({'project':project},instance),value)
                for replacement in ({'host_network':True},{'bundle':'/other'},{'capabilities':['NET_ADMIN']}):
                    path.write_text(json.dumps(value|replacement))
                    with self.assertRaises(ValueError):review.managed_capture_metadata({'project':project},instance)

    def test_update_writes_back_only_to_explicit_capture_state(self):
        with tempfile.TemporaryDirectory() as directory:
            base=pathlib.Path(directory)
            global_file=base/'.local/acceptance/capture-ui.json'
            global_file.parent.mkdir(parents=True)
            global_file.write_text('{"project":"other"}')
            selected=base/'selected-capture.json'
            project='sbacc_'+'a'*16
            parent='/var/lib/starbeacon-acceptance/'+project+'/review-'+'b'*16
            bundle=parent+'/capture-ui-'+'c'*16
            capture={'project':project,'scope':'isolated_live_capture_ui_review','bundle':bundle,'agent_data':bundle+'/agent-data','host_network':False,'host_network_admin':False,'capabilities':['NET_RAW','SETFCAP']}
            selected.write_text(json.dumps(capture))
            state={'project':project,'directory':parent.rsplit('/',1)[0],'host':'owned','workspace_sha256':'d'*64}
            image='sha256:'+'e'*64
            instance={'project':project,'directory':parent,'database':'sbui_'+'b'*16,'name':'review-'+'b'*16,'scope':'development_ui_review','runtime_backend_image':image}
            definition={'services':{'review-init':{},'review':{'environment':{},'security_opt':[]},'review-web':{},'review-capture':{}}}
            helpers=base/'tests/acceptance';helpers.mkdir(parents=True)
            for name in ('review_runtime.py','review_capture_runtime.py'):(helpers/name).write_text('# isolated fixture\n')
            def ssh(_host,arguments,**_options):
                if arguments[:1]==['cat']:
                    raw=json.dumps({'database':instance['database'],'tenant':'review_'+'b'*16} if arguments[1].endswith('/config.json') else definition).encode()
                elif arguments[:2]==['docker','inspect']:raw=(image+'\n').encode()
                else:raw=b''
                return subprocess.CompletedProcess(arguments,0,stdout=raw)
            with mock.patch.object(review,'ROOT',base),mock.patch.object(review,'CAPTURE_STATE',selected),mock.patch.object(review,'backend_image',return_value=image),mock.patch.object(review,'frontend_files',return_value=({},'f'*64)),mock.patch.object(review,'upload_bundle'),mock.patch.object(review,'nginx_config',return_value='owned config'),mock.patch.object(review,'compose'),mock.patch.object(review,'write_review'),mock.patch.object(review.acceptance,'ssh',side_effect=ssh),contextlib.redirect_stdout(io.StringIO()):
                review.update(state,instance)
            self.assertEqual(global_file.read_text(),'{"project":"other"}')
            self.assertEqual(json.loads(selected.read_text())['source_sha256'],state['workspace_sha256'])


if __name__ == '__main__':
    unittest.main()
