"""Isolated real SeaweedFS authentication/publication test.

Needs the pwned-api-s3 image present locally: `ci/build.sh` builds it, or pull
it. Override the reference with PWNED_REGISTRY/PWNED_IMAGE_NAMESPACE/
PWNED_IMAGE_TAG, matching the names compose uses.
"""
import json
import os
from pathlib import Path
import subprocess
import uuid

name = 'pwned-review-' + uuid.uuid4().hex[:12]
image = 'chrislusf/seaweedfs@sha256:08d516132314207d10c8e37cbffc1f32b147d870169688734cc61c6231625b62'
registry = os.environ.get('PWNED_REGISTRY', 'ghcr.io')
namespace = os.environ.get('PWNED_IMAGE_NAMESPACE', 'chainfirelabs/testpassword')
api_image = f"{registry}/{namespace}/pwned-api-s3:{os.environ.get('PWNED_IMAGE_TAG', 'latest')}"

def docker(*args, **kwargs):
    return subprocess.run(['docker', *args], check=True, text=True, capture_output=True, **kwargs)

script = '''
import io, json, tempfile
from pathlib import Path
from unittest.mock import patch
import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
import dataset, manage, main
client, bucket = manage.s3_client()
manage.wait_for_bucket(client, bucket, create=True)
for kwargs in [dict(config=Config(signature_version=UNSIGNED)),
               dict(aws_access_key_id='wrong', aws_secret_access_key='wrong')]:
    unauthorized = boto3.client('s3', endpoint_url='http://seaweedfs:8333', **kwargs)
    try:
        unauthorized.put_object(Bucket=bucket, Key='unauthorized', Body=b'no')
        raise AssertionError('unauthorized write accepted')
    except ClientError as exc:
        assert exc.response['ResponseMetadata']['HTTPStatusCode'] == 403
with tempfile.TemporaryDirectory() as temp:
    directory = Path(temp)
    (directory/'sha1.index').write_text('00000\\ttag\\n00001\\ttag\\n')
    (directory/'00000.txt').write_text('A'*35+':42\\n')
    (directory/'00001.txt').write_text('B'*35+':1\\n')
    with patch.object(dataset, 'PREFIX_COUNT', 2), patch.object(manage, 'PREFIX_COUNT', 2):
        manage.validate(directory, 'sha1')
        manage.publish(directory, 'sha1', client, bucket)
        backend = main.S3Backend(client, bucket, ClientError)
        assert backend.data_state('sha1') == (True, True)
        assert backend.load_prefix('sha1', '00000')['A'*35] == 42
        assert backend.load_prefix('sha1', '00002') is None
print('Real S3: anonymous/wrong credentials rejected; generation publication and lookup passed')
'''
try:
    docker('network', 'create', name)
    docker('run', '-d', '--name', name, '--network', name, '--network-alias', 'seaweedfs',
           '-e', 'AWS_ACCESS_KEY_ID=review-access', '-e', 'AWS_SECRET_ACCESS_KEY=review-secret',
           image, 'server', '-dir=/data', '-s3', '-filer', '-s3.port=8333')
    result = docker('run', '--rm', '-i', '--network', name, '--read-only', '--tmpfs', '/tmp',
                    '-e', 'PWNED_S3_ENDPOINT=http://seaweedfs:8333', '-e', 'PWNED_S3_BUCKET=review',
                    '-e', 'PWNED_S3_ACCESS_KEY=review-access', '-e', 'PWNED_S3_SECRET_KEY=review-secret',
                    api_image, '-', input=script)
    print(result.stdout)
except subprocess.CalledProcessError as exc:
    print(exc.stdout, exc.stderr)
    raise
finally:
    subprocess.run(['docker', 'rm', '-f', '-v', name], capture_output=True)
    subprocess.run(['docker', 'network', 'rm', name], capture_output=True)
