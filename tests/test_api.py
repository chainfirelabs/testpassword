import asyncio
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src/api'))
import main
import dataset
import manage
from fastapi.testclient import TestClient


def setUpModule():
    # Ingestion progress goes to stderr; keep it out of test output.
    quiet = patch.object(manage, 'log', lambda message: None)
    quiet.start()
    unittest.addModuleCleanup(quiet.stop)


class API(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.directory = self.root / 'pwnedpasswords'
        self.directory.mkdir()
        self.index = self.directory / 'sha1.index'
        self.index.write_text('index')
        self.backend = main.DirBackend(self.root)
        self.patch = patch.object(main, 'BACKEND', self.backend)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.client = TestClient(main.app, raise_server_exceptions=False)

    def marker(self):
        marker = dict(version=1, format='sha1', prefix_count=dataset.PREFIX_COUNT,
                      generation='a'*32, index_signature=dataset.signature(self.index))
        (self.directory / dataset.MARKER).write_text(json.dumps(marker))

    def lookup(self):
        return self.client.get('/lookup/sha1/' + 'A'*40)

    def test_missing_range_is_inconclusive_even_with_marker(self):
        self.marker()
        result = self.lookup().json()
        self.assertFalse(result['pwned'])
        self.assertFalse(result['data_complete'])

    def test_legacy_index_is_not_completion(self):
        (self.directory / 'AAAAA.txt').write_text('B'*35 + ':1\n')
        self.assertFalse(self.lookup().json()['data_complete'])

    def test_updates_invalidate_cache(self):
        path = self.directory / 'AAAAA.txt'
        path.write_text('B'*35 + ':1\n')
        self.marker()
        self.assertEqual(self.lookup().json()['count'], 0)
        path.write_text('A'*35 + ':42\n')
        self.assertEqual(self.lookup().json()['count'], 42)
        path.unlink()
        self.assertFalse(self.lookup().json()['data_complete'])

    def test_changed_index_revokes_marker(self):
        self.marker()
        self.assertTrue(self.backend.data_state('sha1')[1])
        self.index.write_text('changed')
        self.assertFalse(self.backend.data_state('sha1')[1])

    def test_corrupt_ranges_fail_closed(self):
        for body in ['', 'A'*35+':-1\n', 'garbage', 'A'*35+':1\n'+'A'*35+':2\n']:
            with self.subTest(body=body):
                (self.directory / 'AAAAA.txt').write_text(body)
                self.assertEqual(self.lookup().status_code, 503)

    def test_validation_redacts_inputs(self):
        for payload in [{'password': 123456789}, {'password': 'secret', 'formats': ['secret']},
                        {'password': 'secret'*1000}, {'password': '\ud800'},
                        {'password': 'secret', 'formats': ['sha1']*3}]:
            response = self.client.post('/check', content=json.dumps(payload), headers={'content-type': 'application/json'})
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json(), {'detail': 'Invalid request'})

    def test_large_and_malformed_bodies(self):
        self.assertEqual(self.client.post('/check', content=b'x'*17000).status_code, 413)
        response = self.client.post('/check', content='{"password":"secret",')
        self.assertEqual(response.status_code, 422)
        self.assertNotIn('secret', response.text)

    def test_hash_vectors_and_empty_password(self):
        self.assertEqual(main.md4(b'').hex(), '31d6cfe0d16ae931b73c59d7e0c089c0')
        self.assertEqual(main.hash_password('password', 'ntlm'), '8846F7EAEE8FB117AD06BDD830B7586C')
        self.assertEqual(self.client.post('/check', json={'password': ''}).status_code, 200)

    def test_sensitive_headers(self):
        self.assertEqual(self.lookup().headers['cache-control'], 'no-store')

    def test_default_path(self):
        self.assertEqual(main.DEFAULT_DATA_DIR, Path(__file__).resolve().parents[1] / 'data')

    def test_chunked_body_limit(self):
        async def run():
            async def app(*args):
                self.fail('oversized body reached application')
            messages = iter([{'type': 'http.request', 'body': b'x'*9000, 'more_body': True},
                             {'type': 'http.request', 'body': b'x'*9000, 'more_body': False}])
            async def receive(): return next(messages)
            output = []
            async def send(message): output.append(message)
            await main.RequestLimits(app)({'type': 'http'}, receive, send)
            self.assertEqual(output[0]['status'], 413)
        asyncio.run(run())


class ClientError(Exception):
    def __init__(self, code):
        self.response = {'Error': {'Code': code}}


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.calls = []
        self.streams = []
        self.fail = False

    def get_object(self, Bucket, Key):
        self.calls.append(Key)
        if self.fail: raise ClientError('AccessDenied')
        if Key not in self.objects: raise ClientError('NoSuchKey')
        stream = io.BytesIO(self.objects[Key])
        self.streams.append(stream)
        return {'Body': stream}

    def list_objects_v2(self, **kwargs): return {'KeyCount': 0}

    def put_object(self, Bucket, Key, Body, **kwargs):
        if self.fail: raise RuntimeError('upload failed')
        self.objects[Key] = Body
        self.calls.append(Key)


class S3(unittest.TestCase):
    def setUp(self):
        self.client = FakeS3()
        self.backend = main.S3Backend(self.client, 'bucket', ClientError)

    def marker(self, generation='a'*32):
        self.client.objects['pwnedpasswords/complete.json'] = json.dumps(dict(
            version=1, format='sha1', prefix_count=dataset.PREFIX_COUNT,
            generation=generation)).encode()

    def test_cached_state_and_ranges_then_new_generation(self):
        self.marker()
        key = 'generations/'+'a'*32+'/pwnedpasswords/AAAAA.txt'
        self.client.objects[key] = ('A'*35+':1\n').encode()
        with patch.object(main.time, 'monotonic', return_value=0):
            self.assertTrue(self.backend.data_state('sha1')[1])
            self.assertEqual(self.backend.load_prefix('sha1', 'AAAAA')['A'*35], 1)
            self.backend.data_state('sha1')
            self.backend.load_prefix('sha1', 'AAAAA')
            self.assertEqual(len(self.client.calls), 2)
        self.marker('b'*32)
        self.client.objects[key.replace('a'*32, 'b'*32)] = ('A'*35+':42\n').encode()
        with patch.object(main.time, 'monotonic', return_value=6):
            self.assertEqual(self.backend.load_prefix('sha1', 'AAAAA')['A'*35], 42)
        self.assertTrue(all(stream.closed for stream in self.client.streams))

    def test_missing_and_access_denied(self):
        self.marker()
        self.assertIsNone(self.backend.load_prefix('sha1', 'AAAAA'))
        self.client.fail = True
        with self.assertRaises(ClientError): self.backend.load_prefix('sha1', 'BBBBB')

    def test_publication_is_last_and_failure_preserves_previous(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory/'sha1.index').write_text('00000\ttag\n00001\ttag\n')
            (directory/'00000.txt').write_text('A'*35+':1\n')
            (directory/'00001.txt').write_text('B'*35+':2\n')
            with patch.object(manage, 'PREFIX_COUNT', 2), patch.object(dataset, 'PREFIX_COUNT', 2):
                manage.validate(directory, 'sha1')
                manage.publish(directory, 'sha1', self.client, 'bucket')
                self.assertEqual(self.client.calls[-1], 'pwnedpasswords/complete.json')
                previous = self.client.objects[self.client.calls[-1]]
                self.client.fail = True
                with self.assertRaises(RuntimeError): manage.publish(directory, 'sha1', self.client, 'bucket')
                self.assertEqual(self.client.objects['pwnedpasswords/complete.json'], previous)

    def test_validation_requires_every_range(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory/'sha1.index').write_text('00000\ttag\n00001\ttag\n')
            with patch.object(manage, 'PREFIX_COUNT', 2):
                with self.assertRaises(FileNotFoundError): manage.validate(directory, 'sha1')
            self.assertFalse((directory/dataset.MARKER).exists())


class Ingestion(unittest.TestCase):
    def test_incomplete_index_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / 'sha1.index').write_text('00000\ttag\n')
            with patch.object(manage, 'PREFIX_COUNT', 2):
                with self.assertRaisesRegex(ValueError, 'incomplete'):
                    manage.validate(directory, 'sha1')
            self.assertFalse((directory / dataset.MARKER).exists())

    def test_download_revokes_marker_before_running_and_validates_afterward(self):
        for exit_code in [0, 1]:
            with self.subTest(exit_code=exit_code), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp) / 'pwnedpasswords'
                directory.mkdir()
                marker = directory / dataset.MARKER
                marker.write_text('old marker')
                test = self
                class Process:
                    def __init__(self, command):
                        test.assertFalse(marker.exists())
                        test.assertIn(str(directory), command)
                    def wait(self):
                        (directory / 'sha1.index').write_text('00000\ttag\n00001\ttag\n')
                        for n in range(2):
                            (directory / f'{n:05X}.txt').write_text('A'*35 + ':1\n')
                        return exit_code
                    def send_signal(self, number): pass
                with patch.dict(main.os.environ, {'PWNED_DATA_DIR': temp}), \
                     patch.object(sys, 'argv', ['manage.py', 'download', 'sha1']), \
                     patch.object(manage.subprocess, 'Popen', Process), \
                     patch.object(manage, 'PREFIX_COUNT', 2), \
                     patch.object(dataset, 'PREFIX_COUNT', 2):
                    if exit_code:
                        with self.assertRaises(RuntimeError): manage.main()
                        self.assertFalse(marker.exists())
                    else:
                        manage.main()
                        self.assertIsNotNone(dataset.local_marker(directory, 'sha1'))

    def test_ingest_checks_bucket_then_downloads_everything_before_publishing(self):
        calls = []
        with patch.object(manage, 'run_download', lambda root, fmt, extra: calls.append(('download', fmt))), \
             patch.object(manage, 'run_upload', lambda root, fmt: calls.append(('upload', fmt))), \
             patch.object(manage, 's3_client', lambda: (None, 'bucket')), \
             patch.object(manage, 'wait_for_bucket', lambda client, bucket: calls.append(('bucket', bucket))):
            manage.ingest(Path('/data'), ['sha1', 'ntlm'], publishing=True)
            self.assertEqual(calls, [('bucket', 'bucket'), ('download', 'sha1'), ('download', 'ntlm'),
                                     ('upload', 'sha1'), ('upload', 'ntlm')])
            calls.clear()
            manage.ingest(Path('/data'), ['sha1', 'ntlm'])
            self.assertEqual(calls, [('download', 'sha1'), ('download', 'ntlm')])

    def test_ingest_stops_at_the_first_failure(self):
        def download(root, fmt, extra):
            raise RuntimeError('downloader exited with status 1')
        with patch.object(manage, 'run_download', download), \
             patch.object(manage, 'run_upload', lambda root, fmt: self.fail('uploaded after a failed download')):
            with self.assertRaises(RuntimeError): manage.ingest(Path('/data'), ['sha1'])


class Progress(unittest.TestCase):
    def setUp(self):
        self.lines = []
        logging = patch.object(manage, 'log', self.lines.append)
        logging.start()
        self.addCleanup(logging.stop)

    def test_reports_are_throttled_and_always_finish(self):
        clock = iter([0, 5, 20, 21, 30])
        with patch.object(manage, 'PREFIX_COUNT', 4), patch.object(manage.time, 'monotonic', lambda: next(clock)):
            progress = manage.Progress('upload sha1')
            for _ in range(4):
                progress.advance()
        self.assertEqual(self.lines, ['upload sha1: 2/4 ranges (50.0%), 0m20s elapsed, about 0m20s left',
                                      'upload sha1: all 4 ranges in 0m30s'])

    def test_validation_and_upload_report(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(manage, 'PREFIX_COUNT', 2), patch.object(dataset, 'PREFIX_COUNT', 2):
            directory = Path(temp)
            (directory/'sha1.index').write_text('00000\ttag\n00001\ttag\n')
            for n in range(2):
                (directory/f'{n:05X}.txt').write_text('A'*35 + ':1\n')
            manage.validate(directory, 'sha1')
            manage.publish(directory, 'sha1', FakeS3(), 'bucket')
        self.assertIn('validate sha1: all 2 ranges in 0m00s', self.lines)
        self.assertIn('upload sha1: all 2 ranges in 0m00s', self.lines)
        self.assertEqual(self.lines[-1], 'upload sha1: published pwnedpasswords/complete.json; '
                                         'the API switches to it within 5 seconds')

    def test_lock_wait_is_reported(self):
        def flock(lock, operation):
            if operation & manage.fcntl.LOCK_NB: raise BlockingIOError
        with tempfile.TemporaryDirectory() as temp, \
             patch.dict(main.os.environ, {'PWNED_DATA_DIR': temp}), \
             patch.object(sys, 'argv', ['manage.py', 'validate', 'sha1']), \
             patch.object(manage.fcntl, 'flock', flock):
            with self.assertRaises(FileNotFoundError): manage.main()
        self.assertTrue(self.lines[0].startswith('validate sha1: waiting for another sha1 job to release'))


if __name__ == '__main__':
    unittest.main()
