$ErrorActionPreference = "Stop"

$Model = "qwen2.5-coder:7b"

Write-Host "Checking Ollama..."
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
  throw "Ollama was not found on PATH. Install Ollama for Windows first: https://ollama.com/download"
}

Write-Host "Checking Python..."
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
  throw "Python was not found on PATH. Install Python 3.10+ and try again."
}

Write-Host "Pulling $Model..."
ollama pull $Model

Write-Host ""
Write-Host "Setup complete."
Write-Host "Run this coding agent with:"
Write-Host "  .\start-qwen-coder-tools.ps1"
Write-Host ""
Write-Host "For no-prompt filesystem writes:"
Write-Host "  .\start-qwen-coder-tools.ps1 -Yes"
