from pathlib import Path

from models import ChangeRequest
from utils import ensure_parent


class ChangeProcessor:
    def __init__(self, repo_dir: Path):
        self.repo_dir = Path(repo_dir)

    def apply(self, request: ChangeRequest):
        for change in request.changes:
            target = self.repo_dir / change.path

            if change.operation == "create":
                ensure_parent(target)
                target.write_text(change.content or "", encoding="utf-8")

            elif change.operation == "update":
                ensure_parent(target)
                target.write_text(change.content or "", encoding="utf-8")

            elif change.operation == "delete":
                if target.exists():
                    target.unlink()

            else:
                raise ValueError(f"Unknown operation: {change.operation}")