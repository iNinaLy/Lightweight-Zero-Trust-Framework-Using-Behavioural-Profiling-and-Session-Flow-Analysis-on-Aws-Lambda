"""Deploy the isolated portal using the baseline's existing Linux dependency bundle."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--stack-name', default='lzta-document-portal')
    parser.add_argument('--baseline-function', default='lzta-framework-dev-ZeroTrustAuthorizer-Ss5EKFxnfJoU')
    args = parser.parse_args()

    def aws(*command):
        output = subprocess.check_output(['aws', *command, '--region', args.region, '--output', 'json', '--no-cli-pager'])
        return json.loads(output) if output.strip() else {}

    account = aws('sts', 'get-caller-identity')['Account']
    existing = aws('lambda', 'get-function', '--function-name', args.baseline_function)
    with urllib.request.urlopen(existing['Code']['Location'], timeout=60) as stream:
        original = stream.read()
    # Reuse pinned Lambda-compatible native wheels; never package Windows crypto wheels.
    source = zipfile.ZipFile(io.BytesIO(original))
    for package, version in [('boto3', '1.43.36'), ('PyJWT', '2.13.0')]:
        assert any(name.lower().startswith(f'{package}-{version}.dist-info/'.lower()) for name in source.namelist()), \
            f'Deployed dependency bundle does not contain expected {package} version'
    bucket = f'lzta-portal-code-{account}-{args.region}'
    result = subprocess.run(['aws', 's3api', 'head-bucket', '--bucket', bucket, '--region', args.region],
                            capture_output=True, text=True)
    if result.returncode:
        if '404' not in result.stderr and 'Not Found' not in result.stderr:
            raise RuntimeError('Cannot inspect deployment bucket: ' + result.stderr)
        options = ['s3api', 'create-bucket', '--bucket', bucket]
        if args.region != 'us-east-1':
            options += ['--create-bucket-configuration', 'LocationConstraint=' + args.region]
        aws(*options)
    aws('s3api', 'put-public-access-block', '--bucket', bucket, '--public-access-block-configuration',
        'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true')
    with tempfile.TemporaryDirectory(prefix='lzta-portal-deploy-') as directory:
        bundle = Path(directory) / 'portal.zip'
        with zipfile.ZipFile(bundle, 'w', compression=zipfile.ZIP_DEFLATED) as target:
            for item in source.infolist():
                if not item.filename.startswith('lzta/'):
                    target.writestr(item, source.read(item.filename))
            for file in (ROOT / 'src/lzta').glob('*.py'):
                target.write(file, 'lzta/' + file.name)
        key = 'lambda/' + hashlib.sha256(bundle.read_bytes()).hexdigest() + '.zip'
        aws('s3api', 'put-object', '--bucket', bucket, '--key', key, '--body', str(bundle), '--server-side-encryption', 'AES256')
    env = existing['Configuration']['Environment']['Variables']
    identities = {subject: f'arn:aws:iam::{account}:user/lzta-portal-demo-{subject}'
                  for subject in json.loads(env['IDENTITY_MAP_JSON'])}
    parameters = {
        'PortalOrigin': args.origin, 'LambdaCodeBucket': bucket, 'LambdaCodeKey': key,
        'IdentityMapJson': json.dumps(identities, separators=(',', ':')),
        'JwtIssuer': env['JWT_ISSUER'], 'JwtAudience': env['JWT_AUDIENCE'], 'JwtJwksUrl': env['JWT_JWKS_URL'],
    }
    with tempfile.TemporaryDirectory(prefix='lzta-portal-params-') as directory:
        path = Path(directory) / 'parameters.json'
        path.write_text(json.dumps([{'ParameterKey': key, 'ParameterValue': value} for key, value in parameters.items()]), encoding='utf-8')
        print('Deploying isolated document portal stack. Existing baseline and CloudTrail are not updated.', flush=True)
        subprocess.run(['aws', 'cloudformation', 'deploy', '--stack-name', args.stack_name,
                        '--template-file', str(ROOT / 'infrastructure/portal.yaml'), '--parameter-overrides', 'file://' + str(path),
                        '--capabilities', 'CAPABILITY_IAM', 'CAPABILITY_AUTO_EXPAND', '--region', args.region,
                        '--no-fail-on-empty-changeset', '--no-cli-pager'], check=True)
    stack = aws('cloudformation', 'describe-stacks', '--stack-name', args.stack_name)['Stacks'][0]
    state = {'stack': args.stack_name, 'region': args.region, 'origin': args.origin,
             'outputs': {item['OutputKey']: item['OutputValue'] for item in stack['Outputs']},
             'identities': identities, 'artifact_bucket': bucket, 'artifact_key': key}
    (ROOT / 'reports/live-portal-deployment.json').write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
    config = {'apiBase': state['outputs']['ApiBaseUrl'], 'cognitoDomain': 'us-east-1nzxn9ulu0.auth.us-east-1.amazoncognito.com',
              'clientId': env['JWT_AUDIENCE'], 'issuer': env['JWT_ISSUER'], 'redirectUri': args.origin + '/'}
    (ROOT / 'sites/lzta-document-portal/dist/config.json').write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': stack['StackStatus'], 'outputs': state['outputs']}), flush=True)


if __name__ == '__main__':
    main()
