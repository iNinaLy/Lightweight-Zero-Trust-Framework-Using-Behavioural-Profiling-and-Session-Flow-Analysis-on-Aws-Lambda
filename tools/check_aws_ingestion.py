"""Deploy isolated ingestion resources and verify production ingestion plus replay safety."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.evaluate_hr_workload import learn_profiles


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('--region', default='us-east-1')
    args = parser.parse_args()
    data = json.loads(args.dataset.read_text(encoding='utf-8'))
    if data.get('dataset_version') != '3.0.0':
        raise ValueError('Use the AWS v3 workload')
    expected = learn_profiles(data)

    def aws(*command):
        raw = subprocess.check_output(['aws', *command, '--region', args.region, '--output', 'json', '--no-cli-pager'])
        return json.loads(raw) if raw.strip() else {}

    account = aws('sts', 'get-caller-identity')['Account']
    trail = 'lzta-framework-dev-trail'
    before = aws('cloudtrail', 'get-trail-status', '--name', trail)['IsLogging']
    if before:
        raise RuntimeError('Expected the existing trail to remain stopped; no changes made')
    stack = 'lzta-isolated-ingestion-test'
    bucket = f'lzta-ingestion-test-{account}-{args.region}'
    table = 'lzta-isolated-ingestion-profiles'
    function = 'lzta-isolated-ingestion-test'
    prefix = 'synthetic-aws/'
    existing = aws('lambda', 'get-function', '--function-name', 'lzta-framework-dev-ProcessBehavioralLogs-rb9cZO7k6y7w')
    with urllib.request.urlopen(existing['Code']['Location'], timeout=60) as response:
        original = zipfile.ZipFile(io.BytesIO(response.read()))
    artifact_bucket = f'lzta-portal-code-{account}-{args.region}'
    with tempfile.TemporaryDirectory(prefix='lzta-ingestion-') as directory:
        folder = Path(directory)
        bundle = folder / 'ingestion.zip'
        with zipfile.ZipFile(bundle, 'w', zipfile.ZIP_DEFLATED) as target:
            for item in original.infolist():
                if not item.filename.startswith('lzta/'):
                    target.writestr(item, original.read(item.filename))
            for source in (ROOT / 'src/lzta').glob('*.py'):
                target.write(source, 'lzta/' + source.name)
        key = 'isolated-ingestion/' + hashlib.sha256(bundle.read_bytes()).hexdigest() + '.zip'
        aws('s3api', 'put-object', '--bucket', artifact_bucket, '--key', key, '--body', str(bundle), '--server-side-encryption', 'AES256')
        template = {'AWSTemplateFormatVersion': '2010-09-09', 'Description': 'Isolated synthetic AWS ingestion verification; no CloudTrail resource.', 'Resources': {
            'Profiles': {'Type': 'AWS::DynamoDB::Table', 'Properties': {'TableName': table, 'BillingMode': 'PAY_PER_REQUEST', 'AttributeDefinitions': [{'AttributeName': 'userId', 'AttributeType': 'S'}], 'KeySchema': [{'AttributeName': 'userId', 'KeyType': 'HASH'}], 'SSESpecification': {'SSEEnabled': True}}},
            'Input': {'Type': 'AWS::S3::Bucket', 'Properties': {'BucketName': bucket, 'PublicAccessBlockConfiguration': {name: True for name in ('BlockPublicAcls', 'BlockPublicPolicy', 'IgnorePublicAcls', 'RestrictPublicBuckets')}, 'BucketEncryption': {'ServerSideEncryptionConfiguration': [{'ServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}}},
            'Role': {'Type': 'AWS::IAM::Role', 'Properties': {'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'lambda.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}, 'Policies': [{'PolicyName': 'isolated-ingestion', 'PolicyDocument': {'Version': '2012-10-17', 'Statement': [
                {'Effect': 'Allow', 'Action': ['s3:GetObject'], 'Resource': f'arn:aws:s3:::{bucket}/{prefix}*'},
                {'Effect': 'Allow', 'Action': ['dynamodb:GetItem', 'dynamodb:UpdateItem', 'dynamodb:PutItem'], 'Resource': {'Fn::GetAtt': ['Profiles', 'Arn']}},
                {'Effect': 'Allow', 'Action': ['logs:CreateLogStream', 'logs:PutLogEvents'], 'Resource': f'arn:aws:logs:{args.region}:{account}:log-group:/aws/lambda/{function}:*'}]}}]}},
            'Logs': {'Type': 'AWS::Logs::LogGroup', 'Properties': {'LogGroupName': '/aws/lambda/' + function, 'RetentionInDays': 7}},
            'Function': {'Type': 'AWS::Lambda::Function', 'DependsOn': 'Logs', 'Properties': {'FunctionName': function, 'Runtime': existing['Configuration']['Runtime'], 'Handler': 'lzta.baseline.lambda_handler', 'Role': {'Fn::GetAtt': ['Role', 'Arn']}, 'MemorySize': 512, 'Timeout': 300, 'Code': {'S3Bucket': artifact_bucket, 'S3Key': key}, 'Environment': {'Variables': {'PROFILES_TABLE': table, 'LOG_BUCKET': bucket, 'LOG_PREFIX': prefix}}}},
            'InvokePermission': {'Type': 'AWS::Lambda::Permission', 'Properties': {'FunctionName': {'Ref': 'Function'}, 'Action': 'lambda:InvokeFunction', 'Principal': 's3.amazonaws.com', 'SourceAccount': account, 'SourceArn': f'arn:aws:s3:::{bucket}'}}
        }}
        template_path = ROOT / 'infrastructure/isolated-ingestion.json'
        template_path.write_text(json.dumps(template, indent=2) + '\n', encoding='utf-8')
        print('Deploying isolated ingestion stack; existing stacks and CloudTrail are unchanged.', flush=True)
        subprocess.run(['aws', 'cloudformation', 'deploy', '--stack-name', stack, '--template-file', str(template_path), '--capabilities', 'CAPABILITY_IAM', '--region', args.region, '--no-fail-on-empty-changeset', '--no-cli-pager'], check=True)
        notification = folder / 'notification.json'
        notification.write_text(json.dumps({'LambdaFunctionConfigurations': [{'Id': 'synthetic-training', 'LambdaFunctionArn': f'arn:aws:lambda:{args.region}:{account}:function:{function}', 'Events': ['s3:ObjectCreated:*'], 'Filter': {'Key': {'FilterRules': [{'Name': 'prefix', 'Value': prefix}, {'Name': 'suffix', 'Value': '.json.gz'}]}}}]}))
        aws('s3api', 'put-bucket-notification-configuration', '--bucket', bucket, '--notification-configuration', 'file://' + str(notification))
        # Unique deterministic dataset prefix prevents collisions with other workloads.
        object_key = prefix + data['dataset_id'] + '.json.gz'
        training = folder / 'training.json.gz'
        training.write_bytes(gzip.compress(json.dumps({'Records': data['training']['records']}).encode(), mtime=0))
        aws('s3api', 'put-object', '--bucket', bucket, '--key', object_key, '--body', str(training), '--server-side-encryption', 'AES256')

        def snapshot():
            result = {}
            for identity in expected:
                item = aws('dynamodb', 'get-item', '--table-name', table, '--consistent-read', '--key', json.dumps({'userId': {'S': identity}})).get('Item')
                if not item:
                    return None
                result[identity] = {'userId': item['userId']['S'], 'knownIPs': sorted(item.get('knownIPs', {}).get('SS', [])), 'userAgents': sorted(item.get('userAgents', {}).get('SS', [])),
                    'hourHistogram': {k: int(v['N']) for k, v in item.get('hourHistogram', {'M': {}})['M'].items()}, 'actionCounts': {k: int(v['N']) for k, v in item.get('actionCounts', {'M': {}})['M'].items()}}
            return result

        deadline = time.monotonic() + 360
        while True:
            learned = snapshot()
            if learned == expected:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('S3-triggered ingestion did not match expected profiles within six minutes')
            count = sum(sum(p['actionCounts'].values()) for p in (learned or {}).values())
            print(f'Waiting for S3-triggered ingestion: {count}/{len(data["training"]["records"])} observations visible.', flush=True)
            time.sleep(10)
        print('All four AWS profiles match the local training-only profiles. Checking replay.', flush=True)
        event = folder / 'event.json'
        event.write_text(json.dumps({'Records': [{'eventSource': 'aws:s3', 'eventName': 'ObjectCreated:Put', 's3': {'bucket': {'name': bucket}, 'object': {'key': object_key}}}]}))
        response = folder / 'response.json'
        invocation = aws('lambda', 'invoke', '--function-name', function, '--cli-binary-format', 'raw-in-base64-out', '--payload', 'file://' + str(event), '--cli-read-timeout', '360', str(response))
        replay = json.loads(response.read_text())
        if invocation.get('FunctionError') or replay != {'files': 1, 'observations': 0, 'skipped': 0}:
            raise RuntimeError('Replay did not complete as an exact no-op: ' + json.dumps(replay))
        after_profiles = snapshot()
        if after_profiles != expected:
            raise RuntimeError('Profiles changed during replay')
        after = aws('cloudtrail', 'get-trail-status', '--name', trail)['IsLogging']
        if after != before:
            raise RuntimeError('CloudTrail state changed externally during the experiment')
        report = {'status': 'passed', 'stack': stack, 'bucket': bucket, 'table': table, 'function': function, 'object_key': object_key, 'artifact_bucket': artifact_bucket, 'artifact_key': key,
                  'dataset_id': data['dataset_id'], 'training_records': len(data['training']['records']), 'profiles_matched': len(expected), 'replay': replay, 'profiles_unchanged_after_replay': True, 'cloudtrail_logging_before': before, 'cloudtrail_logging_after': after,
                  'note': 'Synthetic AWS activity; real S3 notification, Lambda and DynamoDB. Not direct AWS-operation enforcement. Resources remain deployed.', 'profiles': after_profiles}
        path = ROOT / 'reports/live-aws-ingestion-result.json'
        path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({k: v for k, v in report.items() if k != 'profiles'}), flush=True)


if __name__ == '__main__':
    main()
