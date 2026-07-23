import json
from pathlib import Path

from models import ChangeRequest


def load_request(path: str) -> ChangeRequest:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return ChangeRequest.model_validate(data)


def ensure_parent(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)