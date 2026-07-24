import json
import os
import shutil
import subprocess
from pathlib import Path
from tempfile import mkdtemp
from typing import Any

from fastapi import FastAPI, HTTPException
from git import Repo
from pydantic import BaseModel, Field


app = FastAPI(title="AVRC Semgrep Scan Tool", version="1.0.0")

DEFAULT_CONFIG = os.getenv("SEMGREP_CONFIG", "p/default")
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("SEMGREP_TIMEOUT_SECONDS", "300"))
SCAN_INPUT_ROOT = Path(os.getenv("SCAN_INPUT_ROOT", "/scan-input")).resolve()


class ToolEnvelope(BaseModel):
    operation: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)


def unwrap(body: ToolEnvelope | dict[str, Any]) -> dict[str, Any]:
    return body.params if isinstance(body, ToolEnvelope) else body.get("params") or body


def target_from(params: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def normalize_repo_url(value: str) -> str:
    return value.replace("http://localhost:3001/", "http://forgejo:3000/")


def looks_like_repo(target: str | None) -> bool:
    return bool(target and (target.startswith("http://") or target.startswith("https://") or target.startswith("git@") or target.endswith(".git")))


def clone_repo(repo_url: str, branch: str | None = None) -> str:
    temp_dir = mkdtemp(prefix="avrc-semgrep-")
    clone_args = {"depth": 1}
    if branch:
        clone_args["branch"] = branch
    try:
        Repo.clone_from(normalize_repo_url(repo_url), temp_dir, **clone_args)
    except Exception:
        cleanup_path(temp_dir)
        raise
    return temp_dir


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


def run_semgrep(path: str, config: str = DEFAULT_CONFIG, autofix: bool = False) -> dict[str, Any]:
    command = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        "--metrics",
        "off",
        path,
    ]
    if autofix:
        command.insert(2, "--autofix")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=DEFAULT_TIMEOUT_SECONDS,
        check=False,
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    if not stdout:
        raise RuntimeError(stderr or f"semgrep exited with code {result.returncode}")

    data = json.loads(stdout)
    if result.returncode not in (0, 1):
        raise RuntimeError(stderr or data.get("errors") or f"semgrep exited with code {result.returncode}")
    return data


def normalize_finding(result: dict[str, Any]) -> dict[str, Any]:
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    references = metadata.get("references") or []
    cwe = metadata.get("cwe") or metadata.get("cwe2022-top25")

    return {
        "id": result.get("check_id"),
        "ruleId": result.get("check_id"),
        "severity": str(extra.get("severity") or "INFO").lower(),
        "message": extra.get("message"),
        "title": metadata.get("shortlink") or result.get("check_id"),
        "path": result.get("path"),
        "start": result.get("start"),
        "end": result.get("end"),
        "package": result.get("path"),
        "scanner": "semgrep",
        "cwe": cwe if isinstance(cwe, list) else [cwe] if cwe else [],
        "owasp": metadata.get("owasp") or [],
        "references": references if isinstance(references, list) else [references],
        "metadata": metadata,
    }


def response_payload(scan_type: str, target: str, data: dict[str, Any]) -> dict[str, Any]:
    findings = [normalize_finding(result) for result in data.get("results", []) or []]
    return {
        "status": "success",
        "tool": "semgrep_scan_tool",
        "scanner": "semgrep",
        "scanType": scan_type,
        "target": target,
        "totalFindings": len(findings),
        "findings": findings,
        "errors": data.get("errors", []),
        "data": {
            "findings": findings,
            "errors": data.get("errors", []),
        },
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "tool": "semgrep_scan_tool", "scanner": "semgrep", "config": DEFAULT_CONFIG}


@app.post("/semgrep/scan")
@app.post("/scan")
def scan(body: ToolEnvelope | dict[str, Any]) -> dict[str, Any]:
    params = unwrap(body)
    target = target_from(params, "repo", "repository", "target", "path")
    if not target:
        raise HTTPException(status_code=400, detail="repo, repository, target, or path is required.")

    temp_path = None
    try:
        if looks_like_repo(target):
            temp_path = clone_repo(target, params.get("branch") or params.get("baseBranch"))
            scan_path = temp_path
            scan_type = "repo"
        else:
            scan_path = resolve_scan_path(target)
            scan_type = "filesystem"
        data = run_semgrep(scan_path, params.get("config") or DEFAULT_CONFIG)
        return response_payload(scan_type, target, data)
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error
    finally:
        cleanup_path(temp_path)


@app.post("/semgrep/autofix")
def autofix(body: ToolEnvelope | dict[str, Any]) -> dict[str, Any]:
    params = unwrap(body)
    target = target_from(params, "repo", "repository", "target", "path")
    if not target:
        raise HTTPException(status_code=400, detail="repo, repository, target, or path is required.")

    temp_path = None
    try:
        if looks_like_repo(target):
            temp_path = clone_repo(target, params.get("branch") or params.get("baseBranch"))
            scan_path = temp_path
            scan_type = "repo"
        else:
            scan_path = resolve_scan_path(target)
            scan_type = "filesystem"
        data = run_semgrep(scan_path, params.get("config") or DEFAULT_CONFIG, autofix=True)
        payload = response_payload(scan_type, target, data)
        payload["autofixAppliedLocally"] = True
        payload["message"] = "Semgrep autofix ran in the scanner workspace. Use GitOps/LLM flow to create reviewed repo changes."
        return payload
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error
    finally:
        cleanup_path(temp_path)
