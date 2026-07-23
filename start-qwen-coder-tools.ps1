param(
  [string]$Config = "config.yml",
  [switch]$Yes,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$Prompt
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Runner = Join-Path $ScriptDir "run-ollama-fs-agent.ps1"
$ArgsList = @("-Model", "qwen2.5-coder:7b", "-Config", $Config)

if ($Yes) {
  $ArgsList += "-Yes"
}

if ($Prompt.Count -gt 0) {
  $ArgsList += $Prompt
}

& $Runner @ArgsList
