# Ollama Windows Filesystem Tool

This project includes a local Python agent that gives `qwen2.5-coder:7b` filesystem tools on Windows.
The default behavior is controlled by `config.yml`.

## Requirements

- Ollama running locally
- Python 3.10 or newer
- `qwen2.5-coder:7b`

Install and pull the recommended coding model:

```powershell
.\setup-qwen-coder-ollama-tools.ps1
```

If Ollama is not already running, start it in another terminal:

```powershell
ollama serve
```

## Run

Interactive mode:

```powershell
.\start-qwen-coder-tools.ps1
```

Use a specific config:

```powershell
.\start-qwen-coder-tools.ps1 -Config .\config.yml
```

One-shot mode:

```powershell
.\start-qwen-coder-tools.ps1 "Create C:\Temp\hello.txt with the text hello"
```

By default, the agent asks before write, delete, move, and copy operations.

To allow writes without prompts:

```powershell
.\start-qwen-coder-tools.ps1 -Yes "Create C:\Temp\hello.txt with the text hello"
```

You can still use a different model:

```powershell
.\run-ollama-fs-agent.ps1 -Model llama3.1
```

## Config

```yaml
model: qwen2.5-coder:7b
url: http://localhost:11434
cwd: .
auto_yes: false
max_tool_rounds: 12
enabled_tools: [read_file, write_file, append_file, list_dir, make_dir, delete_path, move_path, copy_path]
system_prompt: |
  You are Qwen Coder running locally through Ollama on Windows.
  You are a practical coding agent with filesystem tools already available.
  For coding tasks, inspect files before editing, make focused changes, preserve existing project style, and explain what changed.
```

Set `auto_yes: true` if you want write/delete/move/copy tool calls to run without terminal confirmation.

## Available Tools

- `read_file`
- `write_file`
- `append_file`
- `list_dir`
- `make_dir`
- `delete_path`
- `move_path`
- `copy_path`

Relative paths use the current terminal directory. Absolute Windows paths can access the whole filesystem.

## Notes

This is intentionally powerful. Run it only with models and prompts you trust, especially when using `-Yes`.
