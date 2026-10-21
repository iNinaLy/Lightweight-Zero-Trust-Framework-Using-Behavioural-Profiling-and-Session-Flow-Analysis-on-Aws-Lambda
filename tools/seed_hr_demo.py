"""Provision explicitly synthetic HR fixtures without overwriting existing records."""
import argparse
from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def fixtures(owner, now):
    employee = {"ownerId": owner, "entryId": "employee#profile", "name": "Aisha Rahman", "employeeId": "NS-1042",
                "jobTitle": "Product Designer", "department": "Product & Design", "manager": "Daniel Wong",
                "office": "Kuala Lumpur, Malaysia", "workArrangement": "Hybrid", "email": "aisha.rahman@northstar.example",
                "joinedAt": "2024-08-12", "employmentType": "Full-time", "employmentStatus": "Active",
                "timezone": "Asia/Kuala_Lumpur (UTC+08:00)", "annualLeaveEntitlement": 20, "annualLeaveUsedDays": 6,
                "synthetic": True, "fixtureVersion": "hr-demo-v1"}
    records = [employee]
    first = now.date().replace(day=1)
    for offset in range(3):
        previous = first - timedelta(days=1)
        period = previous.strftime("%Y-%m")
        records.append({"ownerId": owner, "entryId": "payslip#" + period, "id": period, "period": period,
                        "periodLabel": previous.strftime("%B %Y"), "paymentDate": previous.replace(day=25).isoformat(),
                        "currency": "MYR", "status": "Issued", "basicPayCents": 620000, "allowanceCents": 30000,
                        "deductionsCents": {"Retirement contribution (example)": 71500, "Social protection (example)": 3000,
                                            "Employment insurance (example)": 1200, "Tax withholding (example)": 18000},
                        "netPayCents": 556300, "synthetic": True, "fixtureVersion": "hr-demo-v1"})
        first = previous.replace(day=1)
    previous_month = (now.date().replace(day=1) - timedelta(days=1)).replace(day=1)
    past_start = previous_month + timedelta(days=(7 - previous_month.weekday()) % 7)
    future_start = now.date() + timedelta(days=14)
    while future_start.weekday() > 4:
        future_start += timedelta(days=1)
    future_end = future_start + timedelta(days=1)
    while future_end.weekday() > 4:
        future_end += timedelta(days=1)
    for suffix, start, end, days, status, reason in [
        ("approved", past_start, past_start + timedelta(days=7), 6, "Approved", "Family holiday · synthetic historical record"),
        ("pending", future_start, future_end, 2, "Pending", "A little time with family")]:
        record_id = "demo-" + now.strftime("%Y-%m") + "-" + suffix
        records.append({"ownerId": owner, "entryId": "leave#" + record_id, "id": record_id,
                        "type": "Annual leave", "startDate": start.isoformat(), "endDate": end.isoformat(), "days": days,
                        "status": status, "reason": reason, "createdAt": (now - timedelta(days=30 if status == "Approved" else 3)).isoformat(),
                        "updatedAt": now.isoformat(), "synthetic": True, "fixtureVersion": "hr-demo-v1"})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment', type=Path, default=ROOT / 'reports/live-portal-deployment.json')
    args = parser.parse_args()
    state = json.loads(args.deployment.read_text(encoding='utf-8'))
    from boto3.dynamodb.types import TypeSerializer
    serialize = TypeSerializer().serialize

    def aws(*command, allow_existing=False):
        result = subprocess.run(['aws', *command, '--region', state['region'], '--output', 'json', '--no-cli-pager'],
                                capture_output=True, text=True)
        if result.returncode:
            if allow_existing and 'ConditionalCheckFailedException' in result.stderr:
                return {'alreadyExists': True}
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else {}

    inserted = skipped = 0
    with tempfile.TemporaryDirectory(prefix='lzta-hr-seed-') as directory:
        path = Path(directory) / 'item.json'
        for owner in state['identities'].values():
            for item in fixtures(owner, datetime.now(timezone.utc)):
                path.write_text(json.dumps({key: serialize(value) for key, value in item.items()}), encoding='utf-8')
                result = aws('dynamodb', 'put-item', '--table-name', state['outputs']['DocumentsTable'],
                             '--item', 'file://' + str(path), '--condition-expression', 'attribute_not_exists(entryId)',
                             allow_existing=True)
                skipped += bool(result.get('alreadyExists'))
                inserted += not result.get('alreadyExists', False)
            actions = ['hr:ViewEmployee', 'hr:ViewPayslips', 'hr:ReadPayslip', 'hr:DownloadPayslip', 'hr:ViewPolicies',
                       'hr:ReadPolicy', 'hr:ViewLeave', 'hr:SubmitLeave', 'hr:UpdateLeave', 'hr:CancelLeave']
            names = {'#actions': 'actionCounts', '#synthetic': 'synthetic'}
            values = {':one': {'N': '1'}, ':true': {'BOOL': True}}
            for index, action in enumerate(actions):
                names['#a' + str(index)] = action
            expression = 'SET ' + ', '.join(f'#actions.#a{i} = if_not_exists(#actions.#a{i}, :one)' for i in range(len(actions)))
            aws('dynamodb', 'update-item', '--table-name', state['outputs']['ProfilesTable'],
                '--key', json.dumps({'userId': {'S': owner}}), '--update-expression', expression,
                '--condition-expression', '#synthetic = :true', '--expression-attribute-names', json.dumps(names),
                '--expression-attribute-values', json.dumps(values))
    print(json.dumps({'synthetic_records_created': inserted, 'existing_records_preserved': skipped,
                      'note': 'Payroll and leave data are fictional fixtures. Existing IP, device, and hour baselines are unchanged.'}))


if __name__ == '__main__':
    main()
