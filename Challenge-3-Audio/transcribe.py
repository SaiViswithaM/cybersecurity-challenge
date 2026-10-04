from faster_whisper import WhisperModel

audio_file = "speech_0_90_final.wav"

model = WhisperModel(
    "base",
    device="cpu",
    compute_type="int8"
)

segments, info = model.transcribe(
    audio_file,
    language="en",
    task="transcribe",
    beam_size=5,
    vad_filter=False,
    condition_on_previous_text=False,
    temperature=0
)

print("Detected language:", info.language)
print("Language probability:", info.language_probability)
print("\n--- FINAL 0-90 SECOND TRANSCRIPT ---\n")

with open("final_transcript.txt", "w", encoding="utf-8") as f:
    for segment in segments:
        line = f"[{segment.start:.2f}s - {segment.end:.2f}s] {segment.text.strip()}"
        print(line)
        f.write(line + "\n")

print("\nTranscript saved to final_transcript.txt")