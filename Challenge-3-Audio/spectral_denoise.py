import numpy as np
from scipy.io import wavfile
from scipy.signal import stft, istft

# Input files
speech_file = "original_0_90.wav"
noise_file = "noise_profile_exact.wav"

# Output file
output_file = "speech_denoised_scipy.wav"

# Read audio
sr, speech = wavfile.read(speech_file)
sr_noise, noise = wavfile.read(noise_file)

print("Sample rate:", sr)
print("Noise sample rate:", sr_noise)

# Convert to float
speech = speech.astype(np.float32)
noise = noise.astype(np.float32)

# Normalize
speech = speech / 32768.0
noise = noise / 32768.0

# STFT settings
nperseg = 1024
noverlap = 768

# STFT of speech and noise
freq, time, Z_speech = stft(
    speech,
    fs=sr,
    nperseg=nperseg,
    noverlap=noverlap
)

_, _, Z_noise = stft(
    noise,
    fs=sr_noise,
    nperseg=nperseg,
    noverlap=noverlap
)

# Estimate average noise magnitude
noise_magnitude = np.mean(np.abs(Z_noise), axis=1, keepdims=True)

# Speech magnitude and phase
speech_magnitude = np.abs(Z_speech)
speech_phase = np.angle(Z_speech)

# Spectral subtraction
clean_magnitude = speech_magnitude - 1.5 * noise_magnitude

# Don't allow negative values
clean_magnitude = np.maximum(clean_magnitude, 0.05 * speech_magnitude)

# Reconstruct complex spectrum
Z_clean = clean_magnitude * np.exp(1j * speech_phase)

# Convert back to audio
_, cleaned = istft(
    Z_clean,
    fs=sr,
    nperseg=nperseg,
    noverlap=noverlap
)

# Limit length
cleaned = cleaned[:len(speech)]

# Normalize safely
peak = np.max(np.abs(cleaned))

if peak > 0:
    cleaned = cleaned / peak * 0.95

# Convert to 16-bit PCM
cleaned_int16 = (cleaned * 32767).astype(np.int16)

# Save
wavfile.write(
    output_file,
    sr,
    cleaned_int16
)

print()
print("Denoising completed!")
print("Output:", output_file)