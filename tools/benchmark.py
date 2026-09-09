"""Opt-in live endpoint measurement. Reads JWT from LZTA_JWT; never prints it."""
import argparse
import json
import os
from pathlib import Path
import statistics
import time
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Do not forward a bearer credential to another endpoint.


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--requests", type=int, default=30)
    parser.add_argument("--user-agent", required=True)
    parser.add_argument("--output", type=Path, default=Path("reports/live-latency.json"))
    args = parser.parse_args()
    if urlparse(args.url).scheme != "https" or args.requests < 1:
        parser.error("Use an HTTPS endpoint and a positive request count")
    token = os.environ["LZTA_JWT"]
    opener = build_opener(NoRedirect())
    samples = []
    for _ in range(args.requests):
        request = Request(args.url, headers={"Authorization": f"Bearer {token}", "User-Agent": args.user_agent})
        started = time.perf_counter()
        try:
            with opener.open(request, timeout=30) as response:
                status = response.status
                response.read()
        except HTTPError as exc:
            status = exc.code
            exc.close()
        samples.append({"status": status, "clientRoundTripMs": (time.perf_counter() - started) * 1000})
    values = [row["clientRoundTripMs"] for row in samples]
    report = {"metric": "client_round_trip_not_lambda_duration", "requests": len(samples),
              "averageMs": statistics.mean(values), "maxMs": max(values), "firstRequestMs": values[0],
              "note": "First request is not proof of a Lambda cold start; inspect CloudWatch REPORT init duration.",
              "samples": samples}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
