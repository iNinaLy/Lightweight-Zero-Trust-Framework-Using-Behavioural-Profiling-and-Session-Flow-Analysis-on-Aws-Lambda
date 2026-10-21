"""Run the prepared live check and restore its temporary AWS mapping in finally."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def aws(state, *args):
    output = subprocess.check_output([
        'aws', *args, '--region', state['region'], '--output', 'json', '--no-cli-pager',
    ])
    return json.loads(output) if output.strip() else {}


def restore(state, state_path):
    current = aws(state, 'lambda', 'get-function-configuration', '--function-name', state['function'])
    variables = current['Environment']['Variables']
    actual = json.loads(variables['IDENTITY_MAP_JSON'])
    if actual not in (state['temporary_mapping'], state['original_mapping']):
        raise RuntimeError('Mapping changed independently; leaving it untouched for manual review.')
    if actual != state['original_mapping']:
        variables['IDENTITY_MAP_JSON'] = json.dumps(state['original_mapping'])
        with tempfile.TemporaryDirectory(prefix='lzta-restore-') as directory:
            payload = Path(directory) / 'environment.json'
            payload.write_text(json.dumps({'Variables': variables}), encoding='utf-8')
            aws(state, 'lambda', 'update-function-configuration', '--function-name', state['function'],
                '--revision-id', current['RevisionId'], '--environment', 'file://' + str(payload))
        subprocess.run(['aws', 'lambda', 'wait', 'function-updated-v2', '--function-name', state['function'],
                        '--region', state['region']], check=True)
    verified = aws(state, 'lambda', 'get-function-configuration', '--function-name', state['function'])
    if json.loads(verified['Environment']['Variables']['IDENTITY_MAP_JSON']) != state['original_mapping']:
        raise RuntimeError('Original mapping restoration could not be verified')
    state['restored'] = True
    state_path.write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
    print('Original identity mapping restored and verified.', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, default=ROOT / 'reports/live-authorization-check-state.json')
    parser.add_argument('--restore-only', action='store_true')
    args = parser.parse_args()
    state = json.loads(args.state.read_text(encoding='utf-8'))
    if args.restore_only:
        restore(state, args.state)
        return
    if state.get('restored'):
        parser.error('This check has already been restored. It must be prepared again before another run.')
    try:
        if datetime.now(timezone.utc).isoformat()[:13] not in state['prepared_utc_hours']:
            raise RuntimeError('The prepared test window has expired. Restoring the mapping; ask to prepare a fresh check.')
        subprocess.run([
            sys.executable, str(ROOT / 'tools/test_cognito_login.py'),
            '--domain', state['domain'], '--client-id', state['client_id'],
            '--endpoint', state['endpoint'], '--user-agent', state['user_agent'], '--check-changed-agent',
        ], check=True)
    finally:
        restore(state, args.state)


if __name__ == '__main__':
    main()
