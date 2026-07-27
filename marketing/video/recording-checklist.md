# Screen Recording + Voiceover Checklist

## 1) Generate voiceover

Open PowerShell in this folder and run:

```powershell
.\generate-voiceover.ps1
```

Neural quality options (recommended):

```powershell
python .\generate-voiceover-neural.py --output .\voiceover-neural.mp3 --voice en-US-AndrewNeural --rate=-6%
python .\generate-voiceover-neural.py --output .\voiceover-neural-jenny.mp3 --voice en-US-JennyNeural --rate=-5%
python .\generate-voiceover-neural.py --output .\voiceover-neural-aria.mp3 --voice en-US-AriaNeural --rate=-4%
```

Optional pacing:

```powershell
.\generate-voiceover.ps1 -Rate -1
```

## 2) Record screen (OBS suggested)

- Resolution: 1920x1080
- FPS: 30
- Capture: browser app flow + key screens
- Keep each scene 4 to 8 seconds

## 3) Quick shot sequence

1. Alert-heavy dashboard (problem)
2. Manual triage friction (pain)
3. AVRC flow: scan -> dedupe -> enrich -> remediate (solution)
4. Semgrep and Renovate evidence (proof)
5. Executive outcome cards: lower MTTR, faster closure (value)
6. Demo CTA screen (close)

## 4) Merge in editor

- Import screen recording and your selected neural file
- Preferred order: voiceover-neural.mp3, voiceover-neural-jenny.mp3, voiceover-neural-aria.mp3
- Align scene cuts to sentence changes
- Add on-screen keywords from the script
- Add light background music at low volume

## 5) Studio polish chain

- Apply a high-pass filter around 80 Hz
- Use light compression (ratio around 3:1)
- Reduce harsh frequencies slightly around 3 kHz to 5 kHz if needed
- Normalize final loudness near -16 LUFS for social video
- Keep background music 18 dB to 22 dB below voice

## 6) Export settings

- Format: MP4 (H.264)
- Resolution: 1080p
- Bitrate: 10 to 16 Mbps
- Audio: AAC, 320 kbps
