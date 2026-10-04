import numpy as np
from scipy.io import wavfile
from scipy.signal import stft, istft

speech_file = "speech_gentle_0_90.wav"
noise_file = "noise_profile_exact.wav"
output_file = "speech_buzzer_removed.wav"

# Read audio
sr, speech = wavfile.read(speech_file)
sr_noise, noise = wavfile.read(noise_file)

speech = speech.astype(np.float32) / 32768.0
noise = noise.astype(np.float32) / 32768.0

# STFT
nperseg = 2048
noverlap = 1536

freq, time, Z = stft(
    speech,
    fs=sr,
    nperseg=nperseg,
    noverlap=noverlap
)

_, _, N = stft(
    noise,
    fs=sr_noise,
    nperseg=nperseg,
    noverlap=noverlap
)

# Estimate noise power
noise_power = np.mean(np.abs(N) ** 2, axis=1, keepdims=True)

# Speech power
speech_power = np.abs(Z) ** 2

# Wiener-style suppression
gain = speech_power / (
    speech_power + 1.5 * noise_power + 1e-10
)

# Don't completely destroy speech
gain = np.maximum(gain, 0.20)

# Apply gain
Z_clean = Z * gain

# Reconstruct
_, cleaned = istft(
    Z_clean,
    fs=sr,
    nperseg=nperseg,
    noverlap=noverlap
)

cleaned = cleaned[:len(speech)]

# Normalize safely
peak = np.max(np.abs(cleaned))

if peak > 0:
    cleaned = cleaned / peak * 0.90

# Save
wavfile.write(
    output_file,
    sr,
    (cleaned * 32767).astype(np.int16)
)

print("Created:", output_file)