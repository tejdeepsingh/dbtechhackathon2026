import json
import os
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from git import Repo


DEFAULT_TIMEOUT_SECONDS = int(os.getenv("TRIVY_TIMEOUT_SECONDS", "300"))
DEFAULT_SEVERITY = os.getenv("TRIVY_SEVERITY", "LOW,MEDIUM,HIGH,CRITICAL")
SCAN_INPUT_ROOT = Path(os.getenv("SCAN_INPUT_ROOT", "/scan-input")).resolve()


def run_trivy(args: list[str], timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, output_format: str = "json") -> dict[str, Any]:
    command = [
        "trivy",
        *args,
        "--format",
        output_format,
        "--quiet",
    ]
    if output_format == "json":
        command.extend(["--severity", DEFAULT_SEVERITY])
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    if not stdout:
        raise RuntimeError(stderr or f"trivy exited with code {result.returncode}")

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"trivy returned invalid JSON: {stderr or stdout[:500]}") from error

    if result.returncode not in (0, 1):
        raise RuntimeError(stderr or data.get("Error") or f"trivy exited with code {result.returncode}")

    return data


def clone_repo(repo_url: str, branch: str | None = None) -> str:
    temp_dir = TemporaryDirectory()
    clone_args = {"depth": 1}
    if branch:
        clone_args["branch"] = branch

    try:
        Repo.clone_from(repo_url, temp_dir.name, **clone_args)
    except Exception:
        temp_dir.cleanup()
        raise

    return temp_dir.name


def resolve_scan_path(path: str) -> str:
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = SCAN_INPUT_ROOT / candidate

    resolved = candidate.resolve()
    if not str(resolved).startswith(str(SCAN_INPUT_ROOT)):
        raise ValueError(f"filesystem scan path must stay under {SCAN_INPUT_ROOT}")
    if not resolved.exists():
        raise FileNotFoundError(f"scan path does not exist: {resolved}")

    return str(resolved)


def cleanup_path(path: str | None) -> None:
    if path and Path(path).exists():
        shutil.rmtree(path, ignore_errors=True)


def normalize_vulnerability(vulnerability: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    cve = vulnerability.get("VulnerabilityID")
    severity = str(vulnerability.get("Severity") or "UNKNOWN").lower()
    package_name = vulnerability.get("PkgName")
    fixed_versions = vulnerability.get("FixedVersion")

    return {
        "cve": cve,
        "id": cve,
        "vulnerabilityId": cve,
        "severity": severity,
        "package": package_name,
        "packageName": package_name,
        "installedVersion": vulnerability.get("InstalledVersion"),
        "installed_version": vulnerability.get("InstalledVersion"),
        "fixedVersion": fixed_versions,
        "fixed_version": fixed_versions,
        "title": vulnerability.get("Title"),
        "description": vulnerability.get("Description"),
        "primaryUrl": vulnerability.get("PrimaryURL"),
        "target": result.get("Target"),
        "type": result.get("Type"),
        "class": result.get("Class"),
        "scanner": "trivy",
        "references": vulnerability.get("References") or [],
        "cvss": vulnerability.get("CVSS") or {},
        "publishedDate": vulnerability.get("PublishedDate"),
        "lastModifiedDate": vulnerability.get("LastModifiedDate"),
    }


def extract_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in data.get("Results", []) or []:
        for vulnerability in result.get("Vulnerabilities", []) or []:
            findings.append(normalize_vulnerability(vulnerability, result))
        for misconfig in result.get("Misconfigurations", []) or []:
            findings.append(
                {
                    "cve": misconfig.get("ID"),
                    "id": misconfig.get("ID"),
                    "severity": str(misconfig.get("Severity") or "UNKNOWN").lower(),
                    "package": result.get("Target"),
                    "title": misconfig.get("Title"),
                    "description": misconfig.get("Description"),
                    "target": result.get("Target"),
                    "type": result.get("Type"),
                    "class": result.get("Class"),
                    "scanner": "trivy",
                    "references": misconfig.get("References") or [],
                }
            )
    return findings


def summarize(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "unknown").lower()
        summary[severity if severity in summary else "unknown"] += 1
    return summary


def response_payload(scan_type: str, target: str, data: dict[str, Any]) -> dict[str, Any]:
    findings = extract_findings(data)
    return {
        "status": "success",
        "tool": "trivy_scan_tool",
        "scanner": "trivy",
        "scanType": scan_type,
        "target": target,
        "totalFindings": len(findings),
        "summary": summarize(findings),
        "findings": findings,
        "data": {
            "findings": findings,
            "rawResultCount": len(data.get("Results", []) or []),
        },
    }
