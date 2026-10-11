"""核对工程候选前端来源、挂载范围及真实 HTTP 字节验收。"""
import contextlib
import http.server
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock as mock
import urllib.parse
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import remote_candidate_review as candidate


def pages():
    return {'ui/platform/index.html':b'<div id="app"></div>',
            'ui/platform/assets/app.js':b'export const revision=2;',
            'ui/collector/index.html':b'<div id="app"></div>'}


class FrontendCandidateTests(unittest.TestCase):
    def probe(self, expected, actual, redirect=False):
        servers, threads, ports = [], [], {}
        for app in ('platform', 'collector'):
            def handler(application):
                class Handler(http.server.BaseHTTPRequestHandler):
                    def do_GET(self):
                        relative = urllib.parse.unquote(self.path).lstrip('/')
                        if redirect and relative.endswith('app.js'):
                            self.send_response(302)
                            self.send_header('Location', '/index.html')
                            self.end_headers()
                            return
                        data = actual.get('ui/' + application + '/' + relative)
                        self.send_response(200 if data is not None else 404)
                        if data is not None:
                            self.send_header('Content-Length', str(len(data)))
                        self.end_headers()
                        if data is not None:
                            self.wfile.write(data)

                    def log_message(self, *_):
                        pass
                return Handler
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler(app))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
            ports[app] = server.server_port
        try:
            output = io.StringIO()
            with mock.patch.object(sys, 'argv', ['probe', json.dumps(candidate.frontend_records(expected)), json.dumps(ports)]), contextlib.redirect_stdout(output):
                exec(candidate.FRONTEND_HTTP_PROBE, {'__name__':'__main__'})
            return json.loads(output.getvalue())
        finally:
            for server, thread in zip(servers, threads):
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_real_http_matches_both_applications(self):
        files = pages()
        self.assertEqual(self.probe(files, files), candidate.frontend_records(files))

    def test_real_http_rejects_stale_asset_with_same_size(self):
        files, actual = pages(), pages()
        actual['ui/platform/assets/app.js'] = b'export const revision=1;'
        self.assertEqual(len(files['ui/platform/assets/app.js']), len(actual['ui/platform/assets/app.js']))
        with self.assertRaisesRegex(ValueError, '字节与 ZIP 不一致'):
            self.probe(files, actual)

    def test_real_http_rejects_truncation(self):
        files, actual = pages(), pages()
        actual['ui/platform/assets/app.js'] = actual['ui/platform/assets/app.js'][:-1]
        with self.assertRaisesRegex(ValueError, '字节与 ZIP 不一致'):
            self.probe(files, actual)

    def test_real_http_rejects_extra_bytes(self):
        files, actual = pages(), pages()
        actual['ui/platform/assets/app.js'] += b';'
        with self.assertRaisesRegex(ValueError, '长度与 ZIP 不一致'):
            self.probe(files, actual)

    def test_real_http_rejects_redirect(self):
        with self.assertRaisesRegex(ValueError, '响应无效'):
            self.probe(pages(), pages(), redirect=True)

    def test_real_http_rejects_missing_current_asset(self):
        actual = pages()
        del actual['ui/platform/assets/app.js']
        with self.assertRaisesRegex(ValueError, '在线前端文件不可用'):
            self.probe(pages(), actual)

    def test_mount_replacement_preserves_other_runtime_mounts(self):
        before = ['/owned/old/ui:/ui:ro', '/owned/config:/config/nginx.conf:ro', '/owned/runtime:/review:ro']
        self.assertEqual(candidate.replace_frontend_mount(before, '/owned/candidate'),
                         ['/owned/candidate/ui:/ui:ro', *before[1:]])
        self.assertEqual(before[0], '/owned/old/ui:/ui:ro')
        for values in [[], ['/old:/ui'], ['/old:/ui:rw'], ['/a:/ui:ro','/b:/ui:ro'], [1]]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                candidate.replace_frontend_mount(values, '/owned/candidate')

    def test_manifest_requires_scoped_paths_and_both_entries(self):
        files = pages()
        for name, content in [('../private', b''), ('ui/platform/../secret', b''), ('ui/platform//asset.js', b''), ('ui/unknown/index.html', b''), ('ui/platform/private\x00', b''), ('ui/platform/asset.js', 'text')]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                candidate.frontend_records(dict(files, **{name:content}))
        del files['ui/collector/index.html']
        with self.assertRaises(ValueError):
            candidate.frontend_records(files)
        large = pages()
        large['ui/platform/assets/large.js'] = b'a' * (32*1024*1024)
        with self.assertRaises(ValueError):
            candidate.frontend_records(large)

    def test_gateway_result_cannot_omit_or_change_a_file(self):
        files, state = pages(), {'project':'sbacc_test', 'host':'owned'}
        expected = candidate.frontend_records(files)
        with mock.patch.object(candidate.acceptance, 'ssh', return_value=subprocess.CompletedProcess([], 0, json.dumps(expected).encode())):
            self.assertEqual(candidate.verify_online_frontend(state, files)['files'], expected)
        for result in [{}, dict(expected, **{'ui/platform/assets/app.js':{'size':1,'sha256':'0'*64}})]:
            with self.subTest(result=result), mock.patch.object(candidate.acceptance, 'ssh', return_value=subprocess.CompletedProcess([], 0, json.dumps(result).encode())), self.assertRaises(ValueError):
                candidate.verify_online_frontend(state, files)

    def test_stopped_dependency_removal_uses_only_verified_ids_without_force_or_volumes(self):
        records = [{'service':'review-capture','id':'a'*64},{'service':'review-web','id':'b'*64}]
        state = {'project':'sbacc_test','host':'owned'}
        with mock.patch.object(candidate.acceptance,'ssh',side_effect=[subprocess.CompletedProcess([],0,json.dumps(records).encode()),subprocess.CompletedProcess([],0,b''),subprocess.CompletedProcess([],0,b'')]) as ssh:
            candidate.remove_stopped_dependencies(state)
            self.assertEqual([call.args[1] for call in ssh.call_args_list[1:]], [['docker','rm','a'*64],['docker','rm','b'*64]])
        for result in [[{'service':'postgres','id':'a'*64}], records+[records[0]], [{'service':'review-web','id':'wrong'}]]:
            with self.subTest(result=result), mock.patch.object(candidate.acceptance,'ssh',return_value=subprocess.CompletedProcess([],0,json.dumps(result).encode())) as ssh, self.assertRaises(ValueError):
                candidate.remove_stopped_dependencies(state)
            self.assertEqual(ssh.call_count,1)

    def test_start_order_releases_dependencies_before_recreating_platform(self):
        events=[]
        with mock.patch.object(candidate,'remove_stopped_dependencies',side_effect=lambda _:events.append('remove')), mock.patch.object(candidate.review_tools,'compose',side_effect=lambda _state,_review,args,**_:events.append(args)):
            candidate.start_roles({'project':'sbacc_test'}, {})
        self.assertEqual(events[0],'remove')
        self.assertEqual([event[-1] for event in events[1:]],['review','review-web','review-capture'])
        self.assertTrue(all('--no-deps' in event for event in events[1:]))
        self.assertTrue(all('review-init' not in event for event in events[1:]))

    def test_candidate_keeps_actual_zip_frontend_bytes(self):
        state = {'directory':'/owned', 'workspace_sha256':'a'*64, 'project':'sbacc_test','commit':'b'*40}
        checksums = {'version':'v0.1.0-rc.1', 'commit':state['commit'], 'archives':[]}
        identity = {'directory':'/owned/linux-candidate-0123456789ab', 'status':'passed','project':state['project'],'backend_source':state['workspace_sha256'],'commit':state['commit'],'version':checksums['version'],'checksums':checksums}
        files = pages()
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            for app, roles in candidate.ROLES.items():
                name = 'starbeacon-'+app+'-'+checksums['version']+'-linux-amd64.zip'
                checksums['archives'].append({'name':name})
                with zipfile.ZipFile(directory/name,'w') as archive:
                    prefix = 'starbeacon-'+app
                    archive.writestr(prefix+'/manifest.json',json.dumps({'binaries':{role:{} for role in roles}}))
                    for role in roles:
                        archive.writestr(prefix+'/bin/'+role,b'binary')
                    for path, data in files.items():
                        if path.startswith('ui/'+app+'/'):
                            archive.writestr(prefix+'/www/'+path.removeprefix('ui/'+app+'/'),data)
            (directory/'checksums.json').write_text(json.dumps(checksums))
            with mock.patch.object(candidate, 'verify_archive'):
                actual, _, _ = candidate.candidate_files(directory, identity, state, files)
                self.assertEqual({key:value for key,value in actual.items() if key.startswith('ui/')}, files)
                stale = dict(files, **{'ui/platform/assets/app.js':b'export const revision=1;'})
                with self.assertRaisesRegex(ValueError,'实际页面'):
                    candidate.candidate_files(directory, identity, state, stale)


if __name__ == '__main__':
    unittest.main()
