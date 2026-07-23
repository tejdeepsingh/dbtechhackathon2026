#!/usr/bin/env python3
"""
Local Ollama filesystem agent for Windows.

This script gives an Ollama model tool access to the local filesystem through
explicit Python functions. By default, write/delete/move/copy actions ask for
confirmation in the terminal. Use --yes to allow writes without prompting.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_MODEL = "qwen2.5-coder:7b"
DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_SYSTEM_PROMPT = (
    "You are Qwen Coder running locally through Ollama on Windows. You are "
    "a practical coding agent with filesystem tools already available. "
    "For coding tasks, inspect the relevant files first, make focused "
    "edits with the tools, preserve existing project style, and explain "
    "what changed. Prefer absolute Windows paths in tool calls. For risky "
    "delete, move, or overwrite actions, be careful and brief."
)


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a UTF-8 text file from any absolute or relative path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "max_chars": {
                        "type": "integer",
                        "description": "Maximum number of characters to return.",
                        "default": 20000,
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Create or replace a UTF-8 text file at any path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "create_parent_dirs": {"type": "boolean", "default": True},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "append_file",
            "description": "Append UTF-8 text to a file at any path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                    "create_parent_dirs": {"type": "boolean", "default": True},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_dir",
            "description": "List files and directories at any path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "default": "."},
                    "recursive": {"type": "boolean", "default": False},
                    "max_entries": {"type": "integer", "default": 200},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "make_dir",
            "description": "Create a directory at any path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "parents": {"type": "boolean", "default": True},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_path",
            "description": "Delete a file or directory at any path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "recursive": {"type": "boolean", "default": False},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "move_path",
            "description": "Move or rename a file or directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "destination": {"type": "string"},
                },
                "required": ["source", "destination"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "copy_path",
            "description": "Copy a file or directory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string"},
                    "destination": {"type": "string"},
                    "recursive": {"type": "boolean", "default": False},
                },
                "required": ["source", "destination"],
            },
        },
    },
]


def parse_scalar(value: str) -> Any:
    cleaned = value.strip()
    lower = cleaned.lower()
    if lower in {"true", "yes", "on"}:
        return True
    if lower in {"false", "no", "off"}:
        return False
    if lower in {"null", "none", "~"}:
        return None
    if (
        (cleaned.startswith('"') and cleaned.endswith('"'))
        or (cleaned.startswith("'") and cleaned.endswith("'"))
    ):
        return cleaned[1:-1]
    try:
        return int(cleaned)
    except ValueError:
        return cleaned


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    config: dict[str, Any] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    index = 0

    while index < len(lines):
        raw = lines[index]
        stripped = raw.strip()
        index += 1

        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue

        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()

        if value in {"|", ">"}:
            block_lines = []
            while index < len(lines):
                next_line = lines[index]
                if next_line and not next_line.startswith((" ", "\t")):
                    break
                block_lines.append(next_line[2:] if next_line.startswith("  ") else "")
                index += 1
            separator = "\n" if value == "|" else " "
            config[key] = separator.join(block_lines).strip()
            continue

        if value.startswith("[") and value.endswith("]"):
            items = value[1:-1].strip()
            config[key] = [
                parse_scalar(item.strip())
                for item in items.split(",")
                if item.strip()
            ]
            continue

        config[key] = parse_scalar(value)

    return config


def configured_tools(enabled_names: list[str] | None) -> list[dict[str, Any]]:
    if not enabled_names:
        return TOOLS

    enabled = set(enabled_names)
    return [tool for tool in TOOLS if tool["function"]["name"] in enabled]


class FsTools:
    def __init__(self, cwd: Path, auto_yes: bool) -> None:
        self.cwd = cwd
        self.auto_yes = auto_yes

    def resolve(self, raw_path: str) -> Path:
        expanded = os.path.expandvars(os.path.expanduser(raw_path))
        path = Path(expanded)
        if not path.is_absolute():
            path = self.cwd / path
        return path.resolve()

    def confirm(self, action: str, *paths: Path) -> None:
        if self.auto_yes:
            return

        print("\nTool wants filesystem write access:")
        print(f"  action: {action}")
        for path in paths:
            print(f"  path:   {path}")
        answer = input("Allow? Type yes to continue: ").strip().lower()
        if answer != "yes":
            raise PermissionError("User denied filesystem write action.")

    def read_file(self, path: str, max_chars: int = 20000) -> dict[str, Any]:
        target = self.resolve(path)
        content = target.read_text(encoding="utf-8", errors="replace")
        truncated = len(content) > max_chars
        return {
            "path": str(target),
            "content": content[:max_chars],
            "truncated": truncated,
            "size_chars": len(content),
        }

    def write_file(
        self, path: str, content: str, create_parent_dirs: bool = True
    ) -> dict[str, Any]:
        target = self.resolve(path)
        self.confirm("write_file", target)
        if create_parent_dirs:
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"path": str(target), "bytes_written": target.stat().st_size}

    def append_file(
        self, path: str, content: str, create_parent_dirs: bool = True
    ) -> dict[str, Any]:
        target = self.resolve(path)
        self.confirm("append_file", target)
        if create_parent_dirs:
            target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(content)
        return {"path": str(target), "size_bytes": target.stat().st_size}

    def list_dir(
        self, path: str = ".", recursive: bool = False, max_entries: int = 200
    ) -> dict[str, Any]:
        target = self.resolve(path)
        if not target.exists():
            raise FileNotFoundError(str(target))
        if not target.is_dir():
            raise NotADirectoryError(str(target))

        iterator = target.rglob("*") if recursive else target.iterdir()
        entries = []
        for item in iterator:
            if len(entries) >= max_entries:
                break
            stat = item.stat()
            entries.append(
                {
                    "path": str(item),
                    "type": "directory" if item.is_dir() else "file",
                    "size_bytes": stat.st_size,
                    "modified_time": stat.st_mtime,
                }
            )

        return {
            "path": str(target),
            "entries": entries,
            "truncated": len(entries) >= max_entries,
        }

    def make_dir(self, path: str, parents: bool = True) -> dict[str, Any]:
        target = self.resolve(path)
        self.confirm("make_dir", target)
        target.mkdir(parents=parents, exist_ok=True)
        return {"path": str(target), "created": True}

    def delete_path(self, path: str, recursive: bool = False) -> dict[str, Any]:
        target = self.resolve(path)
        self.confirm("delete_path", target)
        if target.is_dir():
            if recursive:
                shutil.rmtree(target)
            else:
                target.rmdir()
        else:
            target.unlink()
        return {"path": str(target), "deleted": True}

    def move_path(self, source: str, destination: str) -> dict[str, Any]:
        src = self.resolve(source)
        dst = self.resolve(destination)
        self.confirm("move_path", src, dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return {"source": str(src), "destination": str(dst), "moved": True}

    def copy_path(
        self, source: str, destination: str, recursive: bool = False
    ) -> dict[str, Any]:
        src = self.resolve(source)
        dst = self.resolve(destination)
        self.confirm("copy_path", src, dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            if not recursive:
                raise IsADirectoryError("Set recursive=true to copy a directory.")
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)
        return {"source": str(src), "destination": str(dst), "copied": True}

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if not hasattr(self, name):
            raise ValueError(f"Unknown tool: {name}")
        method = getattr(self, name)
        return method(**args)


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach Ollama at {url}: {exc}") from exc


def normalize_tool_args(raw_args: Any) -> dict[str, Any]:
    if raw_args is None:
        return {}
    if isinstance(raw_args, dict):
        return raw_args
    if isinstance(raw_args, str):
        return json.loads(raw_args)
    raise TypeError(f"Unsupported tool argument type: {type(raw_args).__name__}")


def chat_once(
    base_url: str,
    model: str,
    messages: list[dict[str, Any]],
    fs_tools: FsTools,
    tools: list[dict[str, Any]],
    max_tool_rounds: int,
) -> str:
    chat_url = base_url.rstrip("/") + "/api/chat"

    for _ in range(max_tool_rounds):
        response = post_json(
            chat_url,
            {
                "model": model,
                "messages": messages,
                "tools": tools,
                "stream": False,
            },
        )
        message = response.get("message", {})
        messages.append(message)

        tool_calls = message.get("tool_calls") or []
        if not tool_calls:
            return message.get("content", "")

        for call in tool_calls:
            function = call.get("function", {})
            name = function.get("name")
            args = normalize_tool_args(function.get("arguments"))
            try:
                result = fs_tools.call(name, args)
                content = json.dumps({"ok": True, "result": result}, indent=2)
            except Exception as exc:
                content = json.dumps(
                    {"ok": False, "error": f"{type(exc).__name__}: {exc}"},
                    indent=2,
                )

            messages.append(
                {
                    "role": "tool",
                    "content": content,
                    "tool_name": name,
                }
            )

    return "Stopped after too many tool-call rounds."


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Give a local Ollama model filesystem tools on Windows."
    )
    parser.add_argument("prompt", nargs="*", help="Prompt to send to Ollama.")
    parser.add_argument(
        "--config",
        default="config.yml",
        help="YAML config path. Defaults to config.yml beside the agent.",
    )
    parser.add_argument("--model", default=None, help="Ollama model name.")
    parser.add_argument("--url", default=None, help="Ollama base URL.")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Allow write/delete/move/copy actions without confirmation.",
    )
    parser.add_argument(
        "--cwd",
        default=None,
        help="Base directory for relative paths. Absolute paths can still access anywhere.",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = script_dir / config_path
    config = load_config(config_path)

    model = args.model or str(config.get("model", DEFAULT_MODEL))
    url = args.url or str(config.get("url", DEFAULT_OLLAMA_URL))
    cwd = Path(args.cwd or str(config.get("cwd", os.getcwd()))).resolve()
    auto_yes = args.yes or bool(config.get("auto_yes", False))
    max_tool_rounds = int(config.get("max_tool_rounds", 12))
    enabled_tools = config.get("enabled_tools")
    tools = configured_tools(enabled_tools if isinstance(enabled_tools, list) else None)
    system = str(config.get("system_prompt", DEFAULT_SYSTEM_PROMPT))

    fs_tools = FsTools(cwd, auto_yes)

    messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
    first_prompt = " ".join(args.prompt).strip()

    def respond() -> str:
        return chat_once(
            url,
            model,
            messages,
            fs_tools,
            tools,
            max_tool_rounds,
        )

    if first_prompt:
        messages.append({"role": "user", "content": first_prompt})
        print(respond())
        return 0

    print("Ollama filesystem agent. Type exit to quit.")
    print(f"Model:  {model}")
    print(f"CWD:    {fs_tools.cwd}")
    print(f"URL:    {url}")
    print(f"Config: {config_path}")
    print(
        "Tools:  "
        + ", ".join(tool["function"]["name"] for tool in tools)
    )
    print()

    while True:
        try:
            prompt = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if prompt.lower() in {"exit", "quit"}:
            return 0
        if not prompt:
            continue

        messages.append({"role": "user", "content": prompt})
        print(respond())


if __name__ == "__main__":
    sys.exit(main())
