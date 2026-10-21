"""HR-only company records; role checks are independent of behavioural familiarity."""
import base64
import csv
from datetime import datetime, timezone
import io
import re
import uuid

from lzta.logging import emit

COMPANY_PARTITION = "hr#synthetic-company"
ROUTES = {
    "/api/v1/hr/summary", "/api/v1/hr/payroll", "/api/v1/hr/payroll/export",
    "/api/v1/hr/employees/{employeeId}", "/api/v1/hr/reviews", "/api/v1/hr/reviews/{employeeId}",
    "/api/v1/hr/audit",
}


def identity(table, owner):
    item = table.get_item(Key={"ownerId": owner, "entryId": "employee#profile"}, ConsistentRead=True).get("Item") or {}
    return {"role": item.get("portalRole", "employee"),
            "staffName": item.get("consoleDisplayName", item.get("name", "Portal user")),
            "staffTitle": item.get("consoleJobTitle", "")}


def public(item):
    return {key: value for key, value in item.items() if key not in ("ownerId", "entryId")}


def csv_value(value):
    text = str(value)
    return "'" + text if text.lstrip().startswith(("=", "+", "-", "@")) else text


def payroll_csv(records):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["data_classification", "employee_id", "name", "department", "pay_period", "gross_pay_myr",
                     "net_pay_myr", "bank_account", "tax_identifier", "home_address"])
    for item in records:
        def amount(key):
            cents = int(item[key])
            return f"{cents // 100}.{cents % 100:02d}"
        writer.writerow([csv_value(value) for value in ["DEMO ONLY - SYNTHETIC CONFIDENTIAL DATA", item["employeeId"],
                         item["name"], item["department"], item["period"], amount("grossPayCents"), amount("netPayCents"),
                         item["bankAccount"], item["taxId"], item["homeAddress"]]])
    return output.getvalue().encode("utf-8-sig")


def handle(event, table, owner, origin):
    from lzta.portal import response
    context = event.get("requestContext", {})
    method, route = event.get("httpMethod"), event.get("resource")
    actor = identity(table, owner)
    now = datetime.now(timezone.utc).isoformat()

    def audit(action, verdict, count=0, record_id="", reason=""):
        item = {"ownerId": COMPANY_PARTITION, "entryId": f"audit#{now}#{uuid.uuid4().hex}",
                "id": uuid.uuid4().hex, "time": now, "actor": actor["staffName"], "principal": owner,
                "role": actor["role"], "action": action, "verdict": verdict, "recordCount": count,
                "recordId": record_id, "reason": reason, "requestId": context.get("requestId", ""),
                "sourceIp": context.get("identity", {}).get("sourceIp", "unavailable")}
        table.put_item(Item=item)
        emit("hr_access", user=owner, role=actor["role"], action=action, verdict=verdict,
             recordCount=count, reason=reason, requestId=context.get("requestId"))

    # No role from request headers, query parameters, or request bodies is trusted.
    # Check before reading any shared confidential partition.
    if actor["role"] != "hr":
        audit(f"{method} {route}", "Deny", reason="hr_role_required")
        return response(403, {"message": "An HR staff role is required for company-wide confidential records.",
                              "reason": "hr_role_required"}, origin)

    def query(prefix, limit=None):
        items, start = [], None
        while True:
            options = {"KeyConditionExpression": "ownerId = :owner AND begins_with(entryId, :prefix)",
                       "ExpressionAttributeValues": {":owner": COMPANY_PARTITION, ":prefix": prefix},
                       "ConsistentRead": True, "ScanIndexForward": prefix != "audit#"}
            if limit:
                options["Limit"] = limit - len(items)
            if start:
                options["ExclusiveStartKey"] = start
            page = table.query(**options)
            items.extend(page.get("Items", []))
            start = page.get("LastEvaluatedKey")
            if not start or (limit and len(items) >= limit):
                return items

    if method == "GET" and route == "/api/v1/hr/audit":
        return response(200, {"items": [public(item) for item in query("audit#", 100)],
                              "coverage": "Requests reaching the HR service; behavioural denials remain in authorizer logs."}, origin)
    if method == "GET" and route == "/api/v1/hr/reviews":
        items = query("review#")
        fields = ("employeeId", "name", "department", "period", "rating", "reviewStatus", "synthetic")
        audit("reviews_list", "Allow", len(items))
        return response(200, {"items": [{key: item[key] for key in fields} for item in items]}, origin)
    if method == "GET" and route in ("/api/v1/hr/employees/{employeeId}", "/api/v1/hr/reviews/{employeeId}"):
        employee_id = (event.get("pathParameters") or {}).get("employeeId", "")
        if not re.fullmatch(r"NS-[0-9]{4}", employee_id):
            return response(404, {"message": "Confidential record not found"}, origin)
        prefix = "employee#" if "/employees/" in route else "review#"
        item = table.get_item(Key={"ownerId": COMPANY_PARTITION, "entryId": prefix + employee_id}, ConsistentRead=True).get("Item")
        if not item:
            return response(404, {"message": "Confidential record not found"}, origin)
        audit("employee_record_view" if prefix == "employee#" else "review_record_view", "Allow", 1, employee_id)
        return response(200, {"record": public(item)}, origin)
    if (method == "GET" and route in ("/api/v1/hr/summary", "/api/v1/hr/payroll")) or (method == "POST" and route == "/api/v1/hr/payroll/export"):
        records = sorted(query("employee#"), key=lambda item: item["employeeId"])
        if route == "/api/v1/hr/summary":
            audit("hr_overview", "Allow", len(records))
            return response(200, {"employeeCount": len(records), "departmentCount": len({item["department"] for item in records}),
                                  "grossPayrollCents": sum(int(item["grossPayCents"]) for item in records),
                                  "netPayrollCents": sum(int(item["netPayCents"]) for item in records),
                                  "period": records[0]["period"] if records else None,
                                  "classification": "Confidential / synthetic demonstration"}, origin)
        if route == "/api/v1/hr/payroll":
            fields = ("employeeId", "name", "department", "jobTitle", "period", "grossPayCents", "netPayCents", "status", "synthetic")
            audit("payroll_register_view", "Allow", len(records))
            return response(200, {"items": [{key: item[key] for key in fields} for item in records]}, origin)
        export_id = uuid.uuid4().hex
        audit("payroll_export", "Allow", len(records), export_id)
        return response(200, {"name": "DEMO-Confidential-Payroll.csv", "contentType": "text/csv;charset=utf-8",
                              "contentBase64": base64.b64encode(payroll_csv(records)).decode(), "recordCount": len(records),
                              "exportId": export_id, "synthetic": True}, origin)
    return response(404, {"message": "HR route not found"}, origin)
