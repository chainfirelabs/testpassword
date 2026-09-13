"""Test rebuilt API and socket-free proxy with a disposable trusted TLS cert."""
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

name = 'pwned-http-' + uuid.uuid4().hex[:12]
proxy_image = 'traefik:v3.7@sha256:5203c3f39ca70de6790d964624e042463ffbd57715bc82be155cf224c0dd5144'
# Same reference compose resolves; `ci/build.sh` builds it locally.
registry = os.environ.get('PWNED_REGISTRY', 'ghcr.io')
namespace = os.environ.get('PWNED_IMAGE_NAMESPACE', 'chainfirelabs/testpassword')
api_image = f"{registry}/{namespace}/pwned-api:{os.environ.get('PWNED_IMAGE_TAG', 'latest')}"

def docker(*args, **kwargs):
    return subprocess.run(['docker', *args], check=True, capture_output=True, text=True, **kwargs)

script = '''
import json, ssl, time, urllib.request, urllib.error
context = ssl.create_default_context(cafile='/certs/fullchain.pem')
for attempt in range(30):
    try:
        response = urllib.request.urlopen('https://proxy:8443/health', context=context, timeout=2)
        assert json.load(response)['status'] == 'ok'
        break
    except (OSError, urllib.error.URLError): time.sleep(.5)
else: raise AssertionError('proxy never ready')
for password, expected in [('', 200), ('a'*1025, 422), ('a'*17000, 413)]:
    request = urllib.request.Request('https://proxy:8443/check',
        data=json.dumps({'password':password}).encode(), headers={'Content-Type':'application/json'})
    try: response = urllib.request.urlopen(request, context=context)
    except urllib.error.HTTPError as exc: response = exc
    assert response.status == expected, response.status
    if expected == 200:
        assert not json.load(response)['results']['sha1']['data_complete']
    elif expected == 422:
        assert json.load(response) == {'detail':'Invalid request'}
response = urllib.request.urlopen('https://proxy:8443/', context=context)
assert b'TestPassword' in response.read()
assert response.headers['Cache-Control'] == 'no-store'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args): return None
try: urllib.request.build_opener(NoRedirect).open('http://proxy:8080/')
except urllib.error.HTTPError as exc:
    assert exc.code in (301,302,307,308)
    assert exc.headers['Location'] in ('https://proxy/', 'https://proxy:443/'), exc.headers['Location']
print('HTTPS certificate validation, proxy routing/redirect, request limits and empty-data behavior passed')
'''
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    root.chmod(0o755)
    certs = root / 'certs'; certs.mkdir()
    dynamic = root / 'dynamic'; dynamic.mkdir()
    (dynamic/'app.yaml').write_text(Path('deploy/standalone/proxy/dynamic/app.yaml').read_text())
    (dynamic/'tls.yaml').write_text(Path('deploy/standalone/proxy/tls.yaml.example').read_text())
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=proxy', '-addext', 'subjectAltName=DNS:proxy',
                    '-keyout', str(certs/'privkey.pem'), '-out', str(certs/'fullchain.pem')],
                   check=True, capture_output=True)
    (certs/'privkey.pem').chmod(0o644)
    try:
        docker('network', 'create', name)
        docker('run', '-d', '--name', name+'-api', '--network', name, '--network-alias', 'api',
               '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', api_image)
        docker('run', '-d', '--name', name+'-proxy', '--network', name, '--network-alias', 'proxy',
               '--read-only', '--user', '65532:65532', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '-v', f'{dynamic}:/etc/traefik/dynamic:ro',
               '-v', f'{certs}:/certs:ro', proxy_image,
               '--providers.file.directory=/etc/traefik/dynamic', '--entrypoints.web.address=:8080',
               '--entrypoints.websecure.address=:8443', '--entrypoints.web.http.redirections.entrypoint.to=:443',
               '--entrypoints.web.http.redirections.entrypoint.scheme=https')
        result = docker('run', '--rm', '-i', '--network', name, '--read-only',
                        '-v', f'{certs}:/certs:ro', 'pwned-api', '-', input=script)
        print(result.stdout)
    except subprocess.CalledProcessError as exc:
        print(exc.stdout, exc.stderr)
        raise
    finally:
        for suffix in ['-proxy', '-api']:
            subprocess.run(['docker', 'rm', '-f', name+suffix], capture_output=True)
        subprocess.run(['docker', 'network', 'rm', name], capture_output=True)
