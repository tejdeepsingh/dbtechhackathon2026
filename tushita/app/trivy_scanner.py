import json
import subprocess


def run_trivy(path):

    result = subprocess.run(
        [
            "trivy",
            "fs",
            "--scanners",
            "vuln",
            "--format",
            "json",
            path
        ],
        capture_output=True,
        text=True
    )

    data = json.loads(result.stdout)

    findings = []

    for target in data.get("Results", []):

        for vuln in target.get("Vulnerabilities", []):

            findings.append({
                "cve": vuln.get("VulnerabilityID"),
                "severity": vuln.get("Severity"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "title": vuln.get("Title")
            })

    return findings