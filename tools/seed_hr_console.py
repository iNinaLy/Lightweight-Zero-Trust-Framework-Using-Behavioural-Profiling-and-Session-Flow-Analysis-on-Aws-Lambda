"""Seed a fictional company register and explicitly grant the isolated demo account an HR role."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COMPANY = 'hr#synthetic-company'
PEOPLE = [
    ('Aisha Rahman', 'Product & Design', 'Product Designer', 620000),
    ('Marcus Tan', 'Engineering', 'Software Engineer', 840000),
    ('Nadia Aziz', 'Finance', 'Finance Analyst', 710000),
    ('Ethan Lim', 'Engineering', 'Platform Engineer', 920000),
    ('Sofia Lee', 'Product & Design', 'Product Manager', 980000),
    ('Daniel Wong', 'Operations', 'Operations Manager', 890000),
    ('Amir Hassan', 'Sales', 'Account Executive', 650000),
    ('Chloe Ng', 'People & Culture', 'HR Specialist', 670000),
    ('Farah Ismail', 'Finance', 'Payroll Specialist', 730000),
    ('Ryan Teo', 'Engineering', 'Security Engineer', 1050000),
    ('Mei Ling Tan', 'Operations', 'Operations Coordinator', 520000),
    ('Adam Zain', 'Sales', 'Sales Manager', 910000),
    ('Leah Chan', 'Product & Design', 'UX Researcher', 740000),
    ('Zara Omar', 'People & Culture', 'People Partner', 810000),
    ('Noah Lee', 'Engineering', 'QA Engineer', 680000),
    ('Sarah Tan', 'People & Culture', 'HR Operations Lead', 960000),
]


def fixtures(now):
    period = (now.date().replace(day=1) - timedelta(days=1)).strftime('%Y-%m')
    for index, (name, department, title, basic) in enumerate(PEOPLE, 1):
        employee_id = f'NS-{1000 + index}'
        gross = basic + 30000
        deductions = {'Retirement contribution (example)': gross * 11 // 100,
                      'Tax withholding (example)': gross * 5 // 100, 'Other deductions (example)': 4200}
        yield {'ownerId': COMPANY, 'entryId': 'employee#' + employee_id, 'employeeId': employee_id,
               'name': name, 'department': department, 'jobTitle': title, 'period': period, 'status': 'Prepared',
               'grossPayCents': gross, 'netPayCents': gross - sum(deductions.values()),
               'basicPayCents': basic, 'allowanceCents': 30000, 'deductionsCents': deductions,
               'bankName': 'DEMO BANK - NO REAL ACCOUNT', 'bankAccount': f'DEMO-BANK-{index:04d}-NOT-VALID',
               'taxId': f'DEMO-TAX-{index:04d}', 'nationalId': f'DEMO-ID-{index:04d}',
               'homeAddress': f'DEMO ONLY: {index} Fictional Lane, Example District, Malaysia (not a real address)',
               'email': name.lower().replace(' ', '.') + '@northstar.example',
               'synthetic': True, 'fixtureVersion': 'hr-confidential-v1'}
        yield {'ownerId': COMPANY, 'entryId': 'review#' + employee_id, 'employeeId': employee_id,
               'name': name, 'department': department, 'period': str(now.year) + ' H2', 'rating': (index % 3) + 3,
               'reviewStatus': 'Confidential', 'reviewer': 'DEMO: People Leadership Team',
               'managerNotes': 'SYNTHETIC CASE: ' + ('Development support and follow-up are recommended.' if index % 5 == 0 else 'Consistent contribution and positive collaboration; discuss the next development goal.'),
               'disciplinaryRecord': 'DEMO ONLY: fictional coaching plan; no real disciplinary case.' if index % 5 == 0 else 'DEMO ONLY: no fictional case recorded.',
               'backgroundCheck': 'SYNTHETIC PLACEHOLDER - no real background screening performed.',
               'synthetic': True, 'fixtureVersion': 'hr-confidential-v1'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--grant-demo-hr', action='store_true', required=True,
                        help='Explicitly grant HR access to the configured isolated synthetic demo account')
    args = parser.parse_args()
    state = json.loads((ROOT / 'reports/live-portal-deployment.json').read_text())
    from boto3.dynamodb.types import TypeSerializer
    serialize = TypeSerializer().serialize

    def aws(*command, allow_existing=False):
        result = subprocess.run(['aws', *command, '--region', state['region'], '--output', 'json', '--no-cli-pager'], capture_output=True, text=True)
        if result.returncode:
            if allow_existing and 'ConditionalCheckFailedException' in result.stderr:
                return {'alreadyExists': True}
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else {}

    created = skipped = 0
    with tempfile.TemporaryDirectory(prefix='lzta-confidential-') as directory:
        path = Path(directory) / 'item.json'
        for record in fixtures(datetime.now(timezone.utc)):
            path.write_text(json.dumps({key: serialize(value) for key, value in record.items()}), encoding='utf-8')
            result = aws('dynamodb', 'put-item', '--table-name', state['outputs']['DocumentsTable'], '--item', 'file://' + str(path),
                         '--condition-expression', 'attribute_not_exists(entryId)', allow_existing=True)
            skipped += bool(result.get('alreadyExists'))
            created += not result.get('alreadyExists', False)
        for owner in state['identities'].values():
            aws('dynamodb', 'update-item', '--table-name', state['outputs']['DocumentsTable'],
                '--key', json.dumps({'ownerId': {'S': owner}, 'entryId': {'S': 'employee#profile'}}),
                '--update-expression', 'SET portalRole = :hr, consoleDisplayName = :name, consoleJobTitle = :title',
                '--condition-expression', '#synthetic = :true', '--expression-attribute-names', '{"#synthetic":"synthetic"}',
                '--expression-attribute-values', json.dumps({':hr': {'S': 'hr'}, ':name': {'S': 'Sarah Tan'},
                    ':title': {'S': 'HR Operations Lead'}, ':true': {'BOOL': True}}))
            actions = ['hr:ViewCompanySummary', 'hr:ViewPayrollRegister', 'hr:ExportPayroll', 'hr:ReadEmployeeRecords',
                       'hr:ListConfidentialReviews', 'hr:ReadConfidentialReview', 'hr:ViewAudit']
            names = {'#actions': 'actionCounts', '#synthetic': 'synthetic'}
            names.update({'#a' + str(i): action for i, action in enumerate(actions)})
            expression = 'SET ' + ', '.join(f'#actions.#a{i} = if_not_exists(#actions.#a{i}, :one)' for i in range(len(actions)))
            aws('dynamodb', 'update-item', '--table-name', state['outputs']['ProfilesTable'], '--key', json.dumps({'userId': {'S': owner}}),
                '--update-expression', expression, '--condition-expression', '#synthetic = :true',
                '--expression-attribute-names', json.dumps(names), '--expression-attribute-values', '{":one":{"N":"1"},":true":{"BOOL":true}}')
    print(json.dumps({'synthetic_records_created': created, 'existing_records_preserved': skipped,
                      'company_employee_count': len(PEOPLE), 'demo_portal_role': 'hr', 'aws_iam_roles_changed': False}))


if __name__ == '__main__':
    main()
