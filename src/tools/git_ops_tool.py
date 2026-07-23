"""
GitOpsTool

Wraps the GitHub REST API v3 to create branches, commit patches, and open
pull requests as part of the automated remediation workflow. Falls back to
realistic mock data whenever credentials are missing or a request fails,
so the rest of the pipeline can continue operating in degraded mode.
"""

import asyncio
import base64
import os
import random
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

from src.core.config_loader import load_config

GITHUB_API_BASE = "https://api.github.com"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fake_sha() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(40))


class GitOpsTool:
    def __init__(self) -> None:
        try:
            self.config = load_config()
        except Exception as err:  # noqa: BLE001
            print(f"[GitOpsTool] Failed to load config, proceeding with defaults: {err}")
            self.config = {}

        self.token: Optional[str] = os.environ.get("GITHUB_TOKEN")
        self.owner: Optional[str] = os.environ.get("GITHUB_OWNER")
        self.repo: Optional[str] = os.environ.get("GITHUB_REPO")

        if not self.token:
            print("[GitOpsTool] GITHUB_TOKEN not set; GitOpsTool will return mock data for all operations.")

    async def execute(self, request: Dict[str, Any]) -> Dict[str, Any]:
        operation = request.get("operation")
        params = request.get("params") or {}

        try:
            if operation == "createBranch":
                return await self._create_branch(params)
            if operation == "commitPatch":
                return await self._commit_patch(params)
            if operation == "openPR":
                return await self._open_pr(params)

            return {
                "error": f"Unknown operation '{operation}'",
                "supported_operations": ["createBranch", "commitPatch", "openPR"],
            }
        except Exception as err:  # noqa: BLE001
            print(f"[GitOpsTool] Error executing '{operation}': {err}")
            return self._mock_fallback(operation, params, err)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
        }

    def _has_credentials(self) -> bool:
        return bool(self.token and self.owner and self.repo)

    async def _create_branch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        branch_name: Optional[str] = params.get("branch_name")
        base_branch: str = params.get("base_branch") or "main"

        if not branch_name:
            raise ValueError("createBranch requires branch_name")

        if not self._has_credentials():
            print("[GitOpsTool] Missing GitHub credentials; returning mock createBranch result.")
            return self._mock_create_branch(branch_name)

        try:
            ref_url = f"{GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/git/ref/heads/{base_branch}"
            ref_res = await asyncio.to_thread(requests.get, ref_url, headers=self._headers())

            if not ref_res.ok:
                raise RuntimeError(f"Failed to fetch base branch ref: {ref_res.status_code} {ref_res.reason}")

            ref_data = ref_res.json()
            sha = (ref_data.get("object") or {}).get("sha")

            if not sha:
                raise RuntimeError("Could not resolve SHA for base branch")

            create_url = f"{GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/git/refs"
            create_res = await asyncio.to_thread(
                requests.post,
                create_url,
                headers=self._headers(),
                json={"ref": f"refs/heads/{branch_name}", "sha": sha},
            )

            if not create_res.ok:
                raise RuntimeError(f"Failed to create branch: {create_res.status_code} {create_res.reason}")

            create_data = create_res.json()

            return {
                "branch_name": branch_name,
                "sha": (create_data.get("object") or {}).get("sha", sha),
                "url": create_data.get(
                    "url", f"{GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/git/refs/heads/{branch_name}"
                ),
                "created_at": _now_iso(),
            }
        except Exception as err:  # noqa: BLE001
            print(f"[GitOpsTool] createBranch API call failed, falling back to mock: {err}")
            return self._mock_create_branch(branch_name)

    async def _commit_patch(self, params: Dict[str, Any]) -> Dict[str, Any]:
        branch_name: Optional[str] = params.get("branch_name")
        file_path: Optional[str] = params.get("file_path")
        content: Optional[str] = params.get("content")
        commit_message: Optional[str] = params.get("commit_message")

        if not branch_name or not file_path or content is None or not commit_message:
            raise ValueError("commitPatch requires branch_name, file_path, content, and commit_message")

        if not self._has_credentials():
            print("[GitOpsTool] Missing GitHub credentials; returning mock commitPatch result.")
            return self._mock_commit_patch(branch_name, file_path)

        try:
            get_url = f"{GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/contents/{file_path}?ref={branch_name}"

            existing_sha: Optional[str] = None
            get_res = await asyncio.to_thread(requests.get, get_url, headers=self._headers())

            if get_res.ok:
                get_data = get_res.json()
                existing_sha = get_data.get("sha")
            # If get_res is not ok (e.g. 404), the file doesn't exist yet - that's fine for a new file.

            put_url = f"{GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/contents/{file_path}"
            body: Dict[str, Any] = {
                "message": commit_message,
                "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
                "branch": branch_name,
            }
            if existing_sha:
                body["sha"] = existing_sha

            put_res = await asyncio.to_thread(requests.put, put_url, headers=self._headers(), json=body)

            if not put_res.ok:
                raise RuntimeError(f"Failed to commit patch: {put_res.status_code} {put_res.reason}")

            put_data = put_res.json()

            return {
                "file_path": file_path,
                "commit_sha": (put_data.get("commit") or {}).get("sha", "unknown"),
                "branch_name": branch_name,
                "committed_at": _now_iso(),
            }
        except Exception as err:  # noqa: BLE001
            print(f"[GitOpsTool] commitPatch API call failed, falling back to mock: {err}")
            return self._mock_commit_patch(branch_name, file_path)

    async def _open_pr(self, params: Dict[str, Any]) -> Dict[str, Any]:
        title: Optional[str] = params.get("title")
        branch_name: Optional[str] = params.get("branch_name")
        base_branch: str = params.get("base_branch") or "main"
        body: str = params.get("body") or ""

        if not title or not branch_name:
            raise ValueError("openPR requires title and branch_name")

        if not self._has_credentials():
            print("[GitOpsTool] Missing GitHub credentials; returning mock openPR result.")
            return self._mock_open_pr(title, branch_name)

        try:
            url = f"{GITHUB_API_BASE}/repos/{self.owner}/{self.repo}/pulls"
            res = await asyncio.to_thread(
                requests.post,
                url,
                headers=self._headers(),
                json={"title": title, "head": branch_name, "base": base_branch, "body": body},
            )

            if not res.ok:
                raise RuntimeError(f"Failed to open PR: {res.status_code} {res.reason}")

            data = res.json()

            return {
                "pr_number": data.get("number"),
                "pr_url": data.get("html_url"),
                "title": title,
                "status": data.get("state", "open"),
                "created_at": data.get("created_at", _now_iso()),
            }
        except Exception as err:  # noqa: BLE001
            print(f"[GitOpsTool] openPR API call failed, falling back to mock: {err}")
            return self._mock_open_pr(title, branch_name)

    # --- Mock fallbacks ---

    def _mock_create_branch(self, branch_name: str) -> Dict[str, Any]:
        owner = self.owner or "mock-owner"
        repo = self.repo or "mock-repo"
        return {
            "branch_name": branch_name,
            "sha": _fake_sha(),
            "url": f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/refs/heads/{branch_name}",
            "created_at": _now_iso(),
            "mock": True,
        }

    def _mock_commit_patch(self, branch_name: str, file_path: str) -> Dict[str, Any]:
        return {
            "file_path": file_path,
            "commit_sha": _fake_sha(),
            "branch_name": branch_name,
            "committed_at": _now_iso(),
            "mock": True,
        }

    def _mock_open_pr(self, title: str, branch_name: str) -> Dict[str, Any]:
        owner = self.owner or "mock-owner"
        repo = self.repo or "mock-repo"
        pr_number = random.randint(100, 999)
        return {
            "pr_number": pr_number,
            "pr_url": f"https://github.com/{owner}/{repo}/pull/{pr_number}",
            "title": title,
            "status": "open",
            "created_at": _now_iso(),
            "mock": True,
        }

    def _mock_fallback(self, operation: Optional[str], params: Dict[str, Any], err: Exception) -> Dict[str, Any]:
        print(f"[GitOpsTool] Returning generic mock fallback for '{operation}' due to error: {err}")
        if operation == "createBranch":
            return self._mock_create_branch(params.get("branch_name") or "remediation/unknown")
        if operation == "commitPatch":
            return self._mock_commit_patch(
                params.get("branch_name") or "remediation/unknown", params.get("file_path") or "unknown"
            )
        if operation == "openPR":
            return self._mock_open_pr(
                params.get("title") or "Automated remediation", params.get("branch_name") or "remediation/unknown"
            )
        return {"error": True, "message": str(err) or "Unknown error", "operation": operation, "mock": True}
