"""Validate downloads and publish complete, immutable S3 generations."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
import fcntl
import json
import os
import re
from pathlib import Path
import subprocess
import signal
import sys
import time
import uuid

from dataset import FORMATS, MARKER, PREFIX_COUNT, local_marker, read_range, signature


def log(message):
    # Timestamped and flushed so `docker logs` shows progress as it happens.
    print(time.strftime('%Y-%m-%d %H:%M:%S ') + message, file=sys.stderr, flush=True)


def duration(seconds):
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f'{hours}h{minutes:02d}m' if hours else f'{minutes}m{seconds:02d}s'


class Progress:
    """Logs ranges done out of PREFIX_COUNT, at most once per interval."""

    def __init__(self, label, interval=15):
        self.label, self.interval, self.done = label, interval, 0
        self.started = self.reported = time.monotonic()

    def advance(self, count=1):
        self.done += count
        now = time.monotonic()
        elapsed = now - self.started
        if self.done >= PREFIX_COUNT:
            log(f'{self.label}: all {PREFIX_COUNT:,} ranges in {duration(elapsed)}')
        elif now - self.reported >= self.interval:
            self.reported = now
            left = (PREFIX_COUNT - self.done) * elapsed / self.done
            log(f'{self.label}: {self.done:,}/{PREFIX_COUNT:,} ranges '
                f'({100 * self.done / PREFIX_COUNT:.1f}%), {duration(elapsed)} elapsed, '
                f'about {duration(left)} left')


def validate(directory, fmt):
    log(f'validate {fmt}: checking every range in {directory}')
    index_signature = signature(directory / f'{fmt}.index')
    seen = bytearray(PREFIX_COUNT)
    with (directory / f'{fmt}.index').open('r', encoding='ascii') as stream:
        for line in stream:
            prefix, separator, etag = line.rstrip('\n').partition('\t')
            if not re.fullmatch('[0-9A-F]{5}', prefix) or not separator or not etag:
                raise ValueError('invalid downloader index')
            number = int(prefix, 16)
            if number >= PREFIX_COUNT or seen[number]:
                raise ValueError('duplicate or unexpected index prefix')
            seen[number] = 1
    if not all(seen):
        raise ValueError('downloader index is incomplete')
    progress = Progress(f'validate {fmt}')
    for n in range(PREFIX_COUNT):
        read_range(directory / f'{n:05X}.txt', fmt)
        progress.advance()
    if index_signature != signature(directory / f'{fmt}.index'):
        raise RuntimeError('dataset changed during validation')
    marker = dict(version=1, format=fmt, prefix_count=PREFIX_COUNT,
                  generation=uuid.uuid4().hex, index_signature=index_signature)
    temporary = directory / (MARKER + '.tmp')
    temporary.write_text(json.dumps(marker))
    temporary.replace(directory / MARKER)
    log(f'validate {fmt}: complete; wrote {directory / MARKER}')
    return marker


def s3_client():
    import boto3
    from botocore.config import Config
    bucket = os.environ['PWNED_S3_BUCKET']
    key = os.environ.get('PWNED_S3_ACCESS_KEY')
    secret = os.environ.get('PWNED_S3_SECRET_KEY')
    if bool(key) != bool(secret):
        raise RuntimeError('set both S3 credentials or use the AWS credential chain')
    client = boto3.client('s3', endpoint_url=os.environ.get('PWNED_S3_ENDPOINT') or None,
                         aws_access_key_id=key or None, aws_secret_access_key=secret or None,
                         region_name=os.environ.get('PWNED_S3_REGION', 'us-east-1'),
                         config=Config(connect_timeout=3, read_timeout=10,
                                       retries={'mode': 'standard', 'total_max_attempts': 3},
                                       max_pool_connections=16))
    return client, bucket


def wait_for_bucket(client, bucket, create=False):
    from botocore.exceptions import BotoCoreError, ClientError
    for attempt in range(30):
        try:
            client.head_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code in ('403', 'AccessDenied', 'InvalidAccessKeyId', 'SignatureDoesNotMatch'):
                raise
            if create and code in ('404', 'NoSuchBucket'):
                client.create_bucket(Bucket=bucket)
                log(f'created bucket {bucket}')
                return
            error = exc
        except BotoCoreError as exc:
            error = exc
        if attempt == 0:
            log(f'waiting up to a minute for bucket {bucket}: {error}')
        if attempt < 29:
            time.sleep(2)
    raise RuntimeError('S3 bucket did not become ready')


def publish(directory, fmt, client, bucket):
    marker = local_marker(directory, fmt)
    if marker is None:
        raise RuntimeError('validate the local dataset before uploading')
    # Never overwrite the generation currently served by readers.
    generation = uuid.uuid4().hex
    root = f'generations/{generation}/{FORMATS[fmt][0]}'
    log(f'upload {fmt}: publishing to s3://{bucket}/{root}/')
    progress = Progress(f'upload {fmt}')

    def upload(n):
        name = f'{n:05X}.txt'
        body = read_range(directory / name, fmt)
        client.put_object(Bucket=bucket, Key=f'{root}/{name}', Body=body,
                          ContentType='text/plain')

    with ThreadPoolExecutor(max_workers=16) as pool:
        # Batches bound pending futures rather than queuing a million objects.
        for start in range(0, PREFIX_COUNT, 256):
            batch = range(start, min(start + 256, PREFIX_COUNT))
            list(pool.map(upload, batch))
            progress.advance(len(batch))
    if local_marker(directory, fmt) != marker:
        raise RuntimeError('local dataset changed during upload')
    published = {k: marker[k] for k in ('version', 'format', 'prefix_count')}
    published['generation'] = generation
    client.put_object(Bucket=bucket, Key=f'{FORMATS[fmt][0]}/{MARKER}',
                      Body=json.dumps(published).encode(), ContentType='application/json')
    log(f'upload {fmt}: published {FORMATS[fmt][0]}/{MARKER}; the API switches to it within 5 seconds')


@contextlib.contextmanager
def locked(root, fmt, action):
    # Shared by the downloader, validator and uploader. Keep this file in place.
    with (root / f'.{fmt}.lock').open('r' if action == 'upload' else 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            log(f'{action} {fmt}: waiting for another {fmt} job to release {lock.name}')
            fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def run_download(root, fmt, extra=()):
    directory = root / FORMATS[fmt][0]
    root.mkdir(parents=True, exist_ok=True)
    with locked(root, fmt, 'download'):
        directory.mkdir(exist_ok=True)
        (directory / MARKER).unlink(missing_ok=True)
        command = ['/usr/local/bin/haveibeenpwned-downloader', str(directory), '-p', '32']
        if fmt == 'ntlm':
            command.append('-n')
        log(f'download {fmt}: starting; the downloader reports "Hash ranges processed" each percent')
        started = time.monotonic()
        process = subprocess.Popen(command + list(extra))
        previous = {}
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous[sig] = signal.signal(sig, lambda number, frame: process.send_signal(number))
        try:
            code = process.wait()
            if code:
                raise RuntimeError(f'downloader exited with status {code}')
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        log(f'download {fmt}: downloader finished in {duration(time.monotonic() - started)}')
        validate(directory, fmt)


def run_validate(root, fmt):
    directory = root / FORMATS[fmt][0]
    root.mkdir(parents=True, exist_ok=True)
    with locked(root, fmt, 'validate'):
        (directory / MARKER).unlink(missing_ok=True)
        validate(directory, fmt)


def run_upload(root, fmt):
    with locked(root, fmt, 'upload'):
        client, bucket = s3_client()
        wait_for_bucket(client, bucket)
        publish(root / FORMATS[fmt][0], fmt, client, bucket)


def ingest(root, formats, extra=(), publishing=False):
    """Download and validate every format, then publish each one."""
    started = time.monotonic()
    if publishing:
        # Fail on a bad bucket or credentials now, not after hours of downloading.
        client, bucket = s3_client()
        wait_for_bucket(client, bucket)
        log(f'ingest: download {", ".join(formats)}, then upload them to s3://{bucket}')
    else:
        log(f'ingest: download {", ".join(formats)}; no S3 bucket configured, so nothing to upload')
    for fmt in formats:
        run_download(root, fmt, extra)
    if publishing:
        for fmt in formats:
            run_upload(root, fmt)
    log(f'ingest: finished in {duration(time.monotonic() - started)}')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['download', 'validate', 'upload', 'ready', 'ingest'])
    parser.add_argument('format', choices=FORMATS, nargs='?')
    parser.add_argument('--create-bucket', action='store_true')
    args, extra = parser.parse_known_args()
    if extra and args.action not in ('download', 'ingest'):
        parser.error('unexpected arguments')
    if any(arg in ('-s', '--single') for arg in extra):
        parser.error('single-file mode is unsupported')
    if args.action == 'ready':
        client, bucket = s3_client()
        wait_for_bucket(client, bucket, create=args.create_bucket)
        log(f'bucket {bucket} is ready')
        return
    root = Path(os.environ.get('PWNED_DATA_DIR', '/data'))
    if args.action == 'ingest':
        formats = [args.format] if args.format else list(FORMATS)
        ingest(root, formats, extra, publishing=bool(os.environ.get('PWNED_S3_BUCKET')))
        return
    fmt = args.format or 'sha1'
    if args.action == 'download':
        run_download(root, fmt, extra)
    elif args.action == 'validate':
        run_validate(root, fmt)
    else:
        run_upload(root, fmt)


if __name__ == '__main__':
    main()
