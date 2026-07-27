param(
  [string]$TextFile = ".\\voiceover-script.txt",
  [string]$OutputFile = ".\\voiceover.wav",
  [int]$Rate = 0,
  [int]$Volume = 100
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Speech

if (-not (Test-Path $TextFile)) {
  throw "Text file not found: $TextFile"
}

$text = Get-Content -Path $TextFile -Raw
if ([string]::IsNullOrWhiteSpace($text)) {
  throw "Text file is empty: $TextFile"
}

$dest = Resolve-Path -Path (Split-Path -Parent $OutputFile) -ErrorAction SilentlyContinue
if (-not $dest) {
  New-Item -ItemType Directory -Path (Split-Path -Parent $OutputFile) -Force | Out-Null
}

$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$synth.Rate = [Math]::Max(-10, [Math]::Min(10, $Rate))
$synth.Volume = [Math]::Max(0, [Math]::Min(100, $Volume))

# Prefer an English voice when available.
$englishVoice = $synth.GetInstalledVoices() |
  ForEach-Object { $_.VoiceInfo } |
  Where-Object { $_.Culture.Name -like "en-*" } |
  Select-Object -First 1

if ($englishVoice) {
  $synth.SelectVoice($englishVoice.Name)
}

$synth.SetOutputToWaveFile($OutputFile)
$synth.Speak($text)
$synth.Dispose()

Write-Host "Voiceover generated: $OutputFile"
