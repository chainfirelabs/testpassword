"""Shared range validation and completion marker contract."""
import json
import re
from pathlib import Path

FORMATS = {'sha1': ('pwnedpasswords', 40), 'ntlm': ('pwnedpasswords_ntlm', 32)}
MARKER = 'complete.json'
PREFIX_COUNT = 16 ** 5
MAX_RANGE_BYTES = 4 * 1024 * 1024


def signature(path):
    s = Path(path).stat()
    return [s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def parse_range(body, fmt):
    if not body or len(body) > MAX_RANGE_BYTES:
        raise ValueError('empty or oversized range')
    pattern = re.compile(r'[0-9A-F]{%d}:[1-9][0-9]*' % (FORMATS[fmt][1] - 5))
    mapping = {}
    for line in body.decode('ascii').splitlines():
        if not pattern.fullmatch(line):
            raise ValueError('invalid range record')
        suffix, count = line.split(':')
        if suffix in mapping or len(count) > 18:
            raise ValueError('duplicate suffix or oversized count')
        mapping[suffix] = int(count)
    if not mapping:
        raise ValueError('empty range')
    return mapping


def read_range(path, fmt):
    with Path(path).open('rb') as stream:
        body = stream.read(MAX_RANGE_BYTES + 1)
    parse_range(body, fmt)
    return body


def valid_marker(marker, fmt):
    return (isinstance(marker, dict) and marker.get('version') == 1
            and marker.get('format') == fmt and marker.get('prefix_count') == PREFIX_COUNT
            and isinstance(marker.get('generation'), str)
            and re.fullmatch('[0-9a-f]{32}', marker['generation']) is not None)


def local_marker(directory, fmt):
    try:
        with (directory / MARKER).open('rb') as stream:
            marker = json.loads(stream.read(4096))
        if valid_marker(marker, fmt) and marker.get('index_signature') == signature(directory / f'{fmt}.index'):
            return marker
    except (OSError, ValueError, TypeError):
        pass
    return None
