"""Validate explicit deployment inputs and invoke SAM without shell interpolation."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from lzta.scoring import Rules


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--parameters", type=Path, required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--stack-name", default="lzta-framework-dev")
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    values = json.loads(args.parameters.read_text())
    if not isinstance(values, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in values.items()):
        parser.error("Parameter file must be a string-to-string JSON object")
    if "REPLACE" in json.dumps(values):
        parser.error("Replace all deployment placeholders first")
    required = {"LogBucketName", "SensitiveActionsJson", "IdentityMapJson",
                "RouteActionMapJson", "JwtIssuer", "JwtAudience", "JwtJwksUrl", "CaptureDataEvents"}
    if not required <= values.keys():
        parser.error("Missing required parameters: " + ", ".join(sorted(required - values.keys())))
    if {"RiskWeightsJson", "DenyThreshold"} & values.keys():
        parser.error("Remove RiskWeightsJson and DenyThreshold: this baseline has no scores")
    Rules.from_dict({"decision_policy": "deny_on_any_anomaly",
                     "sensitive_actions": json.loads(values["SensitiveActionsJson"])})
    if args.validate_only:
        print("Deployment binary-policy parameters validated; no AWS action performed.")
        return
    sam = shutil.which("sam")
    if not sam:
        parser.error("Install AWS SAM CLI first")
    workdir = ROOT / "infrastructure"
    subprocess.run([sam, "validate", "--lint", "--region", args.region, "--template-file", "template.yaml"], cwd=workdir, check=True)
    subprocess.run([sam, "build", "--use-container", "--template-file", "template.yaml"], cwd=workdir, check=True)
    # SAM 1.169+ supports YAML parameter files. JSON is valid YAML, so preserve
    # the values verbatim without passing embedded quotes through Windows/SAM.
    with tempfile.TemporaryDirectory(prefix="lzta-deploy-") as directory:
        parameter_file = Path(directory) / "parameters.yaml"
        parameter_file.write_text(json.dumps(values), encoding="utf-8")
        subprocess.run([sam, "deploy", "--region", args.region, "--stack-name", args.stack_name,
                        "--resolve-s3", "--capabilities", "CAPABILITY_IAM", "--confirm-changeset",
                        "--parameter-overrides", "file://" + parameter_file.as_posix()], cwd=workdir, check=True)


if __name__ == "__main__":
    main()
