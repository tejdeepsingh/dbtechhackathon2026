from typing import List, Literal, Optional
from pydantic import BaseModel, Field


class Change(BaseModel):
    operation: Literal["create", "update", "delete"]
    path: str
    content: Optional[str] = None


class ChangeRequest(BaseModel):
    github_token: str = Field(..., min_length=1)
    workspace: str = Field(..., min_length=1)

    repo: str
    base_branch: str
    new_branch: str

    commit_message: str

    pr_title: str
    pr_body: str

    changes: List[Change]


class PullRequestResponse(BaseModel):
    success: bool
    number: int
    url: str
    branch: str
    sha: str