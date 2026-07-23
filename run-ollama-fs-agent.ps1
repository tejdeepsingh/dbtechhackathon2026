param(
  [string]$Model = "qwen2.5-coder:7b",
  [string]$Config = "config.yml",
  [switch]$Yes,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$Prompt
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Agent = Join-Path $ScriptDir "ollama_fs_agent.py"
$ArgsList = @($Agent, "--config", $Config, "--model", $Model)

if ($Yes) {
  $ArgsList += "--yes"
}

if ($Prompt.Count -gt 0) {
  $ArgsList += $Prompt
}

python @ArgsList
