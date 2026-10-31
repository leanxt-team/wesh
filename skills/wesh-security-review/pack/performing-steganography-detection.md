---
name: performing-steganography-detection
description: Detects and extracts hidden data embedded in images, audio, and other media files using steganalysis tools such as StegDetect, zsteg, stegsolve, binwalk, steghide, and OpenStego to uncover covert communication channels.
subdomain: digital-forensics
facing: defense
mitre_attack:
- T1005
- T1074
- T1119
- T1070
- T1059
nist_csf:
- RS.AN-03
- DE.AE-02
- RS.MA-01
upstream: performing-steganography-detection@54a7988 Apache-2.0, modified by wesh
---
## Prerequisites
- StegDetect, zsteg, stegsolve, binwalk for analysis
- steghide, OpenStego for extraction attempts
- ExifTool for metadata analysis
- Python with Pillow, numpy for custom analysis
- Understanding of common steganographic techniques (LSB, DCT, spread spectrum)
- Sample files for comparison and statistical analysis

## Workflow

### Step 1: Initial File Assessment and Metadata Analysis

```bash
# Install steganography detection tools
sudo apt-get install steghide stegsnow
pip install zsteg
pip install stegoveritas
gem install zsteg  # Ruby-based tool for PNG/BMP
# Examine file metadata for anomalies
exiftool /cases/case-2024-001/media/suspect_image.jpg | tee /cases/case-2024-001/analysis/metadata.txt
# Check for unusual file size (larger than expected for resolution/format)
identify -verbose /cases/case-2024-001/media/suspect_image.jpg | head -30
# Verify file type matches extension
file /cases/case-2024-001/media/suspect_image.jpg
# Confirm JPEG signature vs actual content
# Check for appended data after file footer
python3 << 'PYEOF'
import os
filepath = '/cases/case-2024-001/media/suspect_image.jpg'
filesize = os.path.getsize(filepath)
with open(filepath, 'rb') as f:
    data = f.read()
# JPEG files end with FF D9
jpeg_end = data.rfind(b'\xff\xd9')
if jpeg_end > 0:
    trailing_bytes = filesize - jpeg_end - 2
    if trailing_bytes > 0:
        print(f"WARNING: {trailing_bytes} bytes of data after JPEG end marker!")
        print(f"  File size: {filesize} bytes")
        print(f"  JPEG data: {jpeg_end + 2} bytes")
        print(f"  Hidden data: {trailing_bytes} bytes")
        # Extract trailing data
        with open('/cases/case-2024-001/analysis/trailing_data.bin', 'wb') as out:
            out.write(data[jpeg_end + 2:])
    else:
        print("No trailing data detected after JPEG end marker")
# Check for embedded ZIP/RAR archives
zip_offset = data.find(b'PK\x03\x04')
rar_offset = data.find(b'Rar!\x1a\x07')
if zip_offset > 0:
    print(f"ZIP archive found at offset {zip_offset}")
if rar_offset > 0:
    print(f"RAR archive found at offset {rar_offset}")
PYEOF
```

### Step 2: Run Automated Steganalysis Tools

```bash
# Use binwalk to detect embedded files and data
binwalk /cases/case-2024-001/media/suspect_image.jpg | tee /cases/case-2024-001/analysis/binwalk_scan.txt
# Extract embedded files
binwalk --extract --directory /cases/case-2024-001/analysis/binwalk_extracted/ \
   /cases/case-2024-001/media/suspect_image.jpg
# Use zsteg for PNG and BMP analysis (LSB detection)
zsteg /cases/case-2024-001/media/suspect_image.png | tee /cases/case-2024-001/analysis/zsteg_results.txt
# zsteg with all checks
zsteg -a /cases/case-2024-001/media/suspect_image.png
# Use stegoveritas for comprehensive analysis
stegoveritas /cases/case-2024-001/media/suspect_image.jpg \
   -out /cases/case-2024-001/analysis/stegoveritas/
# Stegoveritas performs:
# - Metadata extraction
# - LSB analysis (multiple bit planes)
# - Color map analysis
# - Trailing data detection
# - Embedded file extraction
# - Image transformation analysis
# Use steghide for JPEG/BMP/WAV/AU extraction attempts
# Try with empty password
steghide extract -sf /cases/case-2024-001/media/suspect_image.jpg -p "" \
   -xf /cases/case-2024-001/analysis/steghide_extract.bin 2>&1
# Try with common passwords
for pwd in password secret hidden stego test 123456 admin; do
    result=$(steghide extract -sf /cases/case-2024-001/media/suspect_image.jpg \
       -p "$pwd" -xf "/cases/case-2024-001/analysis/steghide_$pwd.bin" 2>&1)
    if echo "$result" | grep -q "extracted"; then
        echo "SUCCESS with password: $pwd"
    fi
done
```

### Step 3: Perform LSB (Least Significant Bit) Analysis

```bash
# Custom LSB analysis with Python
python3 << 'PYEOF'
from PIL import Image
import numpy as np
img = Image.open('/cases/case-2024-001/media/suspect_image.png')
pixels = np.array(img)
# Extract LSB from each color channel
for channel, name in enumerate(['Red', 'Green', 'Blue']):
    if channel >= pixels.shape[2]:
        break
    lsb_data = pixels[:, :, channel] & 1
    # Count distribution (should be ~50/50 for natural images)
    zeros = np.sum(lsb_data == 0)
    ones = np.sum(lsb_data == 1)
    total = zeros + ones
    ratio = ones / total
    print(f"{name} channel LSB: 0s={zeros} ({zeros/total*100:.1f}%), 1s={ones} ({ones/total*100:.1f}%)")
    if abs(ratio - 0.5) < 0.01:
        print(f"  NEUTRAL - Close to random (could be stego or natural)")
    elif ratio > 0.55 or ratio < 0.45:
        print(f"  ANOMALY - Significant deviation from expected distribution")
# Extract LSB data as bytes
lsb_bits = (pixels[:, :, 0] & 1).flatten()
lsb_bytes = np.packbits(lsb_bits)
# Check if extracted data has structure
with open('/cases/case-2024-001/analysis/lsb_extracted.bin', 'wb') as f:
    f.write(lsb_bytes.tobytes())
# Check for known file signatures in extracted data
import struct
header = bytes(lsb_bytes[:16])
print(f"\nLSB extracted header (hex): {header.hex()}")
if header[:4] == b'PK\x03\x04':
    print("  DETECTED: ZIP archive in LSB data!")
elif header[:3] == b'GIF':
    print("  DETECTED: GIF image in LSB data!")
elif header[:4] == b'\x89PNG':
    print("  DETECTED: PNG image in LSB data!")
elif header[:2] == b'\xff\xd8':
    print("  DETECTED: JPEG image in LSB data!")
# Generate LSB visualization
lsb_img = Image.fromarray((lsb_data * 255).astype(np.uint8))
lsb_img.save('/cases/case-2024-001/analysis/lsb_visualization.png')
print("\nLSB visualization saved to lsb_visualization.png")
PYEOF
```

### Step 4: Analyze Audio and Video Steganography

```bash
# Spectral analysis of audio files
python3 << 'PYEOF'
import wave
import numpy as np
# Analyze WAV file for audio steganography
with wave.open('/cases/case-2024-001/media/suspect_audio.wav', 'r') as wav:
    frames = wav.readframes(wav.getnframes())
    samples = np.frombuffer(frames, dtype=np.int16)
    # LSB analysis of audio samples
    lsb = samples & 1
    zeros = np.sum(lsb == 0)
    ones = np.sum(lsb == 1)
    total = len(lsb)
    print(f"Audio LSB Analysis:")
    print(f"  Samples: {total}")
    print(f"  LSB 0s: {zeros} ({zeros/total*100:.1f}%)")
    print(f"  LSB 1s: {ones} ({ones/total*100:.1f}%)")
    # Extract LSB data
    lsb_bytes = np.packbits(lsb)
    with open('/cases/case-2024-001/analysis/audio_lsb.bin', 'wb') as f:
        f.write(lsb_bytes.tobytes())
    # Chi-square test for randomness
    from scipy import stats
    chi2, p_value = stats.chisquare([zeros, ones])
    print(f"  Chi-square: {chi2:.4f}, p-value: {p_value:.4f}")
    if p_value < 0.05:
        print(f"  ANOMALY: LSB distribution is not random (potential stego)")
PYEOF
# Use steghide on audio files
steghide info /cases/case-2024-001/media/suspect_audio.wav
# Analyze with sonic-visualiser or audacity for spectral anomalies
# (Check spectrogram for hidden images encoded in frequency domain)
```

### Step 5: Generate Steganalysis Report

```bash
# Compile findings
python3 << 'PYEOF'
import os, json
report = {
    "case": "2024-001",
    "files_analyzed": [],
    "findings": []
}
analysis_dir = '/cases/case-2024-001/analysis/'
for f in os.listdir(analysis_dir):
    if f.endswith('.txt'):
        with open(os.path.join(analysis_dir, f)) as fh:
            content = fh.read()
            if 'DETECTED' in content or 'SUCCESS' in content or 'WARNING' in content:
                report["findings"].append({
                    "source": f,
                    "content": content[:500]
                })
with open('/cases/case-2024-001/analysis/steg_report.json', 'w') as f:
    json.dump(report, f, indent=2)
print("Steganalysis report generated")
print(f"Total findings: {len(report['findings'])}")
PYEOF
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| LSB (Least Significant Bit) | Embedding data in lowest-order bits of pixel or sample values |
| DCT steganography | Hiding data in JPEG discrete cosine transform coefficients |
| Spread spectrum | Distributing hidden data across entire carrier signal |
| Steganalysis | science of detecting presence of hidden information |
| Chi-square attack | Statistical test detecting non-random LSB distributions |
| Cover medium | original file used to carry hidden data (image, audio, video) |
| Stego medium | resulting file after hidden data has been embedded |
| Capacity | Maximum amount of data that can be hidden without visible distortion |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| steghide | Embed/extract data in JPEG, BMP, WAV, AU files |
| zsteg | Detect LSB steganography in PNG and BMP files |
| binwalk | Detect embedded files and data within binary files |
| stegoveritas | Comprehensive steganalysis tool with multiple detection methods |
| StegSolve | Java GUI tool for image bit plane and filter analysis |
| OpenStego | Open-source steganography and watermarking tool |
| ExifTool | Metadata extraction and analysis for media files |
| stegseek | Fast steghide password cracker for JPEG stego extraction |

Not vendored (scripts/, references/): https://github.com/mukul975/Anthropic-Cybersecurity-Skills/tree/54a798831d2266a3ca61ce68a7acb80b81160d57/skills/performing-steganography-detection
