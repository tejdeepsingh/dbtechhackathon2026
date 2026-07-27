import argparse
import asyncio
from pathlib import Path

import edge_tts


def clean_script(text: str) -> str:
    lines = [line.strip() for line in text.splitlines()]
    cleaned = []
    for line in lines:
        if not line:
            cleaned.append("")
            continue
        if line.lower().startswith("avrc voiceover script"):
            continue
        cleaned.append(line)

    # Collapse excessive blank lines for smoother pacing.
    output = []
    blank = False
    for line in cleaned:
        is_blank = line == ""
        if is_blank and blank:
            continue
        output.append(line)
        blank = is_blank

    return "\n".join(output).strip()


async def synthesize(text: str, voice: str, rate: str, pitch: str, output: Path) -> None:
    communicate = edge_tts.Communicate(text=text, voice=voice, rate=rate, pitch=pitch)
    await communicate.save(str(output))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate neural voiceover using Microsoft Edge TTS")
    parser.add_argument("--text-file", default="voiceover-script.txt", help="Path to narration text file")
    parser.add_argument("--output", default="voiceover-neural.mp3", help="Output audio file path")
    parser.add_argument("--voice", default="en-US-JennyNeural", help="Neural voice name")
    parser.add_argument("--rate", default="-4%", help="Speech rate, e.g. -8%%, +5%%")
    parser.add_argument("--pitch", default="+0Hz", help="Pitch, e.g. -20Hz, +0Hz")
    args = parser.parse_args()

    text_path = Path(args.text_file)
    if not text_path.exists():
        raise FileNotFoundError(f"Text file not found: {text_path}")

    raw = text_path.read_text(encoding="utf-8")
    text = clean_script(raw)
    if not text:
        raise ValueError("No narration text found after cleanup")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    asyncio.run(synthesize(text, args.voice, args.rate, args.pitch, output_path))
    print(f"Neural voiceover generated: {output_path}")


if __name__ == "__main__":
    main()
