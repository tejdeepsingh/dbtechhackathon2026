from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .trivy_runner import cleanup_path, clone_repo, response_payload, resolve_scan_path, run_trivy


app = FastAPI(title="AVRC Trivy Scan Tool", version="1.0.0")


class ToolEnvelope(BaseModel):
    operation: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    repo_url: str | None = None
    repo: str | None = None
    repository: str | None = None
    image: str | None = None
    target: str | None = None
    path: str | None = None
    branch: str | None = None
    scan_type: str | None = None


def unwrap(body: ToolEnvelope | ScanRequest | dict[str, Any]) -> dict[str, Any]:
    if isinstance(body, ToolEnvelope):
        return body.params or {}
    if isinstance(body, ScanRequest):
        return body.model_dump(exclude_none=True)
    return body.get("params") or body


def target_from(params: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = params.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def looks_like_repo(target: str | None) -> bool:
    return bool(target and (target.startswith("http://") or target.startswith("https://") or target.startswith("git@") or target.endswith(".git")))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "tool": "trivy_scan_tool", "scanner": "trivy"}


@app.post("/scan")
@app.post("/trivy/scan")
def scan(body: ToolEnvelope | ScanRequest | dict[str, Any]) -> dict[str, Any]:
    params = unwrap(body)
    requested_type = params.get("scan_type") or params.get("scanType")
    target = target_from(params, "repo_url", "repo", "repository", "image", "target", "path")

    if requested_type == "image" or target_from(params, "image"):
        return scan_image(body)
    if looks_like_repo(target) or target_from(params, "repo_url", "repo", "repository"):
        return scan_repo(body)
    if target:
        return scan_filesystem(body)

    raise HTTPException(status_code=400, detail="Provide repo_url, repo, repository, image, target, or path.")


@app.post("/trivy/repo")
def scan_repo(body: ToolEnvelope | ScanRequest | dict[str, Any]) -> dict[str, Any]:
    params = unwrap(body)
    repo_url = target_from(params, "repo_url", "repo", "repository", "target")
    if not repo_url:
        raise HTTPException(status_code=400, detail="repo_url, repo, repository, or target is required.")

    temp_path = None
    try:
        temp_path = clone_repo(repo_url, params.get("branch") or params.get("baseBranch"))
        data = run_trivy(["fs", "--scanners", "vuln,secret,misconfig", temp_path])
        return response_payload("repo", repo_url, data)
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error
    finally:
        cleanup_path(temp_path)


@app.post("/trivy/image")
def scan_image(body: ToolEnvelope | ScanRequest | dict[str, Any]) -> dict[str, Any]:
    params = unwrap(body)
    image = target_from(params, "image", "target")
    if not image:
        raise HTTPException(status_code=400, detail="image or target is required.")

    try:
        data = run_trivy(["image", "--scanners", "vuln,secret,misconfig", image])
        return response_payload("image", image, data)
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error


@app.post("/trivy/config")
def scan_config(body: ToolEnvelope | ScanRequest | dict[str, Any]) -> dict[str, Any]:
    params = unwrap(body)
    path = target_from(params, "path", "target") or "."

    try:
        scan_path = resolve_scan_path(path)
        data = run_trivy(["config", scan_path])
        return response_payload("config", path, data)
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error


@app.post("/trivy/sbom")
def scan_sbom(body: ToolEnvelope | ScanRequest | dict[str, Any]) -> dict[str, Any]:
    params = unwrap(body)
    target = target_from(params, "image", "target", "repo_url", "repo", "repository")
    if not target:
        raise HTTPException(status_code=400, detail="image, target, repo_url, repo, or repository is required.")

    temp_path = None
    try:
        if looks_like_repo(target):
            temp_path = clone_repo(target, params.get("branch") or params.get("baseBranch"))
            data = run_trivy(["fs", temp_path], output_format="cyclonedx")
        else:
            data = run_trivy(["image", target], output_format="cyclonedx")
        return {
            "status": "success",
            "tool": "trivy_scan_tool",
            "scanner": "trivy",
            "scanType": "sbom",
            "target": target,
            "sbom": data,
            "data": {"findings": []},
        }
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error)) from error
    finally:
        cleanup_path(temp_path)
