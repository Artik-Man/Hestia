"""Compare private installed configuration identity without exporting profile contents."""
import hashlib
import json
from pathlib import Path
import sys


def identity():
    """Hash full file inventory, accepting JSON formatting only with a valid profile marker."""
    root = Path('/etc/hestia')
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('Unexpected configuration symlink')
        if not path.is_file():
            continue
        name = str(path.relative_to(root))
        content = path.read_bytes()
        if name == 'profile-source.sha256':
            expected = hashlib.sha256((root / 'profile.json').read_bytes()).hexdigest()
            if content.decode().strip() != expected:
                raise RuntimeError('Invalid profile source checksum')
            result[name] = 'valid-profile-source-checksum'
            continue
        if path.suffix == '.json':
            content = json.dumps(json.loads(content), sort_keys=True, separators=(',', ':')).encode()
        result[name] = hashlib.sha256(content).hexdigest()
    return result


def main():
    """Save a guest-private baseline or require exact semantic identity after all phases."""
    baseline = Path(sys.argv[2])
    current = identity()
    if sys.argv[1] == 'save':
        baseline.write_text(json.dumps(current))
    elif sys.argv[1] != 'check' or json.loads(baseline.read_text()) != current:
        raise SystemExit('Installed configuration changed; preserving diagnostic state, no blind restore')


if __name__ == '__main__':
    main()
