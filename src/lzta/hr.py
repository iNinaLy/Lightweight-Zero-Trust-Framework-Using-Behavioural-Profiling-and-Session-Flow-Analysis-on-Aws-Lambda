"""Synthetic employee self-service with owner-scoped payroll and leave records."""
import base64
from datetime import date, datetime, timedelta, timezone
import json
import re
import uuid

from lzta.logging import emit

POLICIES = [
    {"id": "flexible-working", "title": "Flexible working", "category": "Working here", "updatedAt": "2026-09-01",
     "summary": "A shared rhythm, with room for real life.", "readMinutes": 3,
     "sections": [
         {"title": "Our working rhythm", "text": "Our demonstration office is in Kuala Lumpur (UTC+08:00). Teams normally work Monday to Friday, 09:00–18:00 local time. Agree any alternative arrangements with your manager."},
         {"title": "Working remotely", "text": "Use your approved device and network. A new network or browser can trigger an access denial even after a successful sign-in. Contact your workspace operator if a legitimate change needs reviewing."},
         {"title": "Keep your team in the loop", "text": "Share your availability, keep handover notes current, and make time for focused work. This is a fictional company policy for the LZTA demonstration."}]},
    {"id": "leave-and-time-off", "title": "Leave & time off", "category": "Your wellbeing", "updatedAt": "2026-10-01",
     "summary": "Take a pause. Come back with a little more energy.", "readMinutes": 2,
     "sections": [
         {"title": "Plan your time away", "text": "Submit annual, medical, or personal leave through this portal. Your request starts as Pending. You may edit or cancel your own pending requests. Approved requests cannot be changed here."},
         {"title": "Your balance", "text": "The demonstration uses a fictional annual allowance of 20 days. Weekdays are counted; public holidays and half-days are not modelled. Pending requests do not reduce the displayed approved-leave balance."},
         {"title": "About approvals", "text": "This employee demonstration does not include a manager approval workflow. Historical approved records are synthetic fixtures; new requests remain Pending until an operator handles them."}]},
    {"id": "payroll-guide", "title": "Understanding your payslip", "category": "Pay & benefits", "updatedAt": "2026-09-25",
     "summary": "The details behind your monthly pay, made clearer.", "readMinutes": 4,
     "sections": [
         {"title": "Your monthly statement", "text": "Payslips show illustrative basic pay, allowances, deductions, and net pay. You can view and download only the payslips linked to your authenticated employee identity."},
         {"title": "For demonstration only", "text": "Every person, amount, deduction, and payroll document in this portal is synthetic. Amounts are examples, not statutory calculations, tax guidance, or real salary information."},
         {"title": "Keep payroll private", "text": "Download statements only to a trusted device. Payroll downloads are classified as sensitive actions and are evaluated by the behavioural authorizer before any file is returned."}]},
    {"id": "information-security", "title": "Keeping information safe", "category": "Company essentials", "updatedAt": "2026-10-12",
     "summary": "Small, everyday habits that protect everyone.", "readMinutes": 3,
     "sections": [
         {"title": "Your account is personal", "text": "Do not share sign-in credentials or tokens. Access to payroll and leave records is limited to the signed-in employee. A successful login does not bypass behavioural access checks."},
         {"title": "When access changes", "text": "An unfamiliar network, browser, access hour, or sensitive action can cause a denial. The Session & access screen shows your actual observed context and baseline outcome."},
         {"title": "Demonstration scope", "text": "The current deployment uses the strict binary baseline. Stage 2 session-flow detection is planned and is not active. Application telemetry is collected separately from AWS CloudTrail."}]}]


def public(item):
    return {key: value for key, value in item.items() if key not in ("ownerId", "entryId")}


def leave_values(body):
    if not isinstance(body, dict) or set(body) != {"type", "startDate", "endDate", "reason"}:
        raise ValueError("Supply only leave type, start date, end date, and reason")
    if body["type"] not in ("Annual leave", "Medical leave", "Personal leave"):
        raise ValueError("Choose a valid leave type")
    for key in ("startDate", "endDate"):
        if not isinstance(body[key], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", body[key]):
            raise ValueError("Use YYYY-MM-DD dates")
    start, end = date.fromisoformat(body["startDate"]), date.fromisoformat(body["endDate"])
    if end < start:
        raise ValueError("End date must be on or after the start date")
    if start < datetime.now(timezone(timedelta(hours=8))).date():
        raise ValueError("New or updated leave must start today or later in Malaysia time")
    weeks, remaining = divmod((end - start).days + 1, 7)
    days = weeks * 5 + sum((start.weekday() + offset) % 7 < 5 for offset in range(remaining))
    if not days:
        raise ValueError("Choose dates that include at least one weekday")
    reason = body["reason"]
    if not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 500:
        raise ValueError("Add a reason between 5 and 500 characters")
    return {"type": body["type"], "startDate": start.isoformat(), "endDate": end.isoformat(),
            "days": days, "reason": reason.strip()}


def payroll_pdf(employee, payslip):
    def money(amount):
        return f"RM {int(amount) / 100:,.2f}"
    lines = ["NORTHSTAR / PEOPLE", "SYNTHETIC PAYSLIP - DEMONSTRATION ONLY", "", payslip["periodLabel"],
             f"Employee: {employee['name']}", f"Employee ID: {employee['employeeId']}",
             f"Department: {employee['department']}", f"Payment date: {payslip['paymentDate']}", "",
             "EARNINGS", "Basic salary: " + money(payslip["basicPayCents"]),
             "Allowances: " + money(payslip["allowanceCents"]), "",
             "DEDUCTIONS (ILLUSTRATIVE)", *[name + ": " + money(amount) for name, amount in payslip["deductionsCents"].items()],
             "", "NET PAY: " + money(payslip["netPayCents"]), "",
             "All names and amounts are fictional. Not a real payroll or tax calculation.",
             "This document was returned through the protected LZTA payroll API."]
    commands = ["BT", "/F1 11 Tf", "50 790 Td", "19 TL"]
    for index, text in enumerate(lines):
        safe = text.encode("latin-1", "replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        safe = safe.replace("\n", " ").replace("\r", " ")
        if index:
            commands.append("T*")
        commands.append("(" + safe + ") Tj")
    commands.append("ET")
    content = "\n".join(commands).encode("latin-1")
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
               f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"\nendstream"]
    document = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(document))
        document.extend(f"{number} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(document)
    document.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        document.extend(f"{offset:010d} 00000 n \n".encode())
    document.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(document)


def handle(event, table, owner, origin):
    from lzta.portal import response
    context = event.get("requestContext", {})
    method, resource = event.get("httpMethod"), event.get("resource", "")
    parameters = event.get("pathParameters") or {}
    now = datetime.now(timezone.utc).isoformat()

    def record(action, name, record_id=""):
        table.put_item(Item={"ownerId": owner, "entryId": f"activity#{now}#{uuid.uuid4().hex}",
                             "action": action, "name": name, "documentId": record_id, "time": now,
                             "requestId": context.get("requestId", "")})

    def query(prefix):
        items, start = [], None
        while True:
            options = {"KeyConditionExpression": "ownerId = :owner AND begins_with(entryId, :prefix)",
                       "ExpressionAttributeValues": {":owner": owner, ":prefix": prefix}, "ConsistentRead": True}
            if start:
                options["ExclusiveStartKey"] = start
            result = table.query(**options)
            items.extend(result.get("Items", []))
            start = result.get("LastEvaluatedKey")
            if not start:
                return items

    def get(prefix, record_id):
        if not isinstance(record_id, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", record_id):
            return None
        return table.get_item(Key={"ownerId": owner, "entryId": prefix + record_id}, ConsistentRead=True).get("Item")

    emit("portal_activity", user=owner, action=f"{method} {resource}", requestId=context.get("requestId"),
         sourceIp=context.get("identity", {}).get("sourceIp"))
    employee = table.get_item(Key={"ownerId": owner, "entryId": "employee#profile"}, ConsistentRead=True).get("Item")
    if not employee:
        return response(404, {"message": "An employee profile has not been provisioned for this account"}, origin)
    if method == "GET" and resource == "/employee":
        return response(200, {"employee": public(employee)}, origin)
    if method == "GET" and resource == "/policies":
        return response(200, {"items": [{key: value for key, value in policy.items() if key != "sections"} for policy in POLICIES]}, origin)
    if method == "GET" and resource == "/policies/{policyId}":
        policy = next((item for item in POLICIES if item["id"] == parameters.get("policyId")), None)
        return response(200, {"policy": policy}, origin) if policy else response(404, {"message": "Policy not found"}, origin)
    if method == "GET" and resource == "/payslips":
        fields = ("id", "period", "periodLabel", "paymentDate", "netPayCents", "currency", "status")
        return response(200, {"items": sorted([{key: item[key] for key in fields if key in item} for item in query("payslip#")], key=lambda item: item["period"], reverse=True)}, origin)
    if method == "GET" and resource == "/payslips/{payslipId}":
        payslip = get("payslip#", parameters.get("payslipId"))
        if not payslip:
            return response(404, {"message": "Payslip not found"}, origin)
        record("payroll_viewed", payslip["periodLabel"] + " payslip", payslip["id"])
        return response(200, {"payslip": public(payslip)}, origin)
    if method == "GET" and resource == "/payslips/{payslipId}/download":
        payslip = get("payslip#", parameters.get("payslipId"))
        if not payslip:
            return response(404, {"message": "Payslip not found"}, origin)
        content = payroll_pdf(employee, payslip)
        record("payroll_download", payslip["periodLabel"] + " payslip", payslip["id"])
        return response(200, {"name": "Payslip-" + payslip["period"] + ".pdf", "contentType": "application/pdf",
                              "contentBase64": base64.b64encode(content).decode()}, origin)
    if method == "GET" and resource == "/leave-requests":
        return response(200, {"items": sorted([public(item) for item in query("leave#")], key=lambda item: item["createdAt"], reverse=True)}, origin)
    if resource == "/leave-requests" and method == "POST":
        try:
            values = leave_values(json.loads(event.get("body") or "{}"))
        except (ValueError, TypeError, KeyError) as error:
            return response(400, {"message": str(error)}, origin)
        record_id = uuid.uuid4().hex
        item = {"ownerId": owner, "entryId": "leave#" + record_id, "id": record_id, **values,
                "status": "Pending", "createdAt": now, "updatedAt": now}
        table.put_item(Item=item, ConditionExpression="attribute_not_exists(entryId)")
        record("leave_submitted", item["type"], record_id)
        return response(201, {"request": public(item)}, origin)
    if resource == "/leave-requests/{leaveId}" and method in ("PATCH", "DELETE"):
        item = get("leave#", parameters.get("leaveId"))
        if not item:
            return response(404, {"message": "Leave request not found"}, origin)
        if item["status"] != "Pending":
            return response(403, {"message": "Only your pending leave requests can be edited or cancelled"}, origin)
        if method == "PATCH":
            try:
                changes = leave_values(json.loads(event.get("body") or "{}"))
            except (ValueError, TypeError, KeyError) as error:
                return response(400, {"message": str(error)}, origin)
        else:
            changes = {"status": "Cancelled"}
        updated = {**item, **changes, "updatedAt": now}
        try:
            table.put_item(Item=updated, ConditionExpression="#status = :pending AND updatedAt = :previous",
                           ExpressionAttributeNames={"#status": "status"},
                           ExpressionAttributeValues={":pending": "Pending", ":previous": item["updatedAt"]})
        except Exception as error:
            if getattr(error, "response", {}).get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return response(409, {"message": "This request changed. Refresh before trying again."}, origin)
            raise
        record("leave_updated" if method == "PATCH" else "leave_cancelled", updated["type"], item["id"])
        return response(200, {"request": public(updated)}, origin)
    return response(404, {"message": "HR route not found"}, origin)
