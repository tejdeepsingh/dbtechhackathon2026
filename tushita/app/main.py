from tempfile import TemporaryDirectory

from fastapi import FastAPI, HTTPException
from git import Repo
from pydantic import BaseModel

from trivy_scanner import run_trivy

app = FastAPI(
    title="OSS Vulnerability Scanner",
    version="1.0.0"
)


class ScanRequest(BaseModel):
    repo_url: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scan")
def scan(request: ScanRequest):

    try:

        with TemporaryDirectory() as temp_dir:

            Repo.clone_from(
                request.repo_url,
                temp_dir
            )

            findings = run_trivy(temp_dir)

            critical = len(
                [f for f in findings if f["severity"] == "CRITICAL"]
            )

            high = len(
                [f for f in findings if f["severity"] == "HIGH"]
            )

            medium = len(
                [f for f in findings if f["severity"] == "MEDIUM"]
            )

            low = len(
                [f for f in findings if f["severity"] == "LOW"]
            )

            return {
                "repository": request.repo_url,
                "total_findings": len(findings),
                "summary": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low
                },
                "findings": findings
            }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )