# Video Container Steganography — Educational Notes

## Why Video Is Different

Video steganography is fundamentally more complex than image or PDF
steganography because of how video codecs work.

### The Core Problem: Lossy Compression

| Format | Compression | LSB Steganography? |
| -------- | ------------ | ------------------- |
| PNG | Lossless | ✅ Works perfectly |
| BMP | None | ✅ Works perfectly |
| JPEG | Lossy (DCT) | ⚠️ Fragile — quantization destroys LSBs |
| MP4/H.264 | Lossy (DCT + inter-frame) | ❌ Impractical in pixel domain |
| AVI (raw) | Depends on codec | ✅ If uncompressed |
| MKV/WebM | Lossy (VP9/AV1) | ❌ Same problem as H.264 |

### How Video Compression Destroys Hidden Data

1. **Spatial compression** (DCT/wavelet):
   Each frame is divided into blocks (e.g., 8×8 for H.264).  A Discrete
   Cosine Transform converts pixel values to frequency coefficients.
   Quantization rounds these coefficients, destroying fine-grained pixel
   changes like LSB modifications.

2. **Temporal compression** (inter-frame prediction):
   Most frames are stored as *differences* from reference frames (I/P/B
   frames).  Only keyframes (I-frames) store full image data.  Modifying
   a pixel in one frame affects predictions for subsequent frames,
   potentially causing visible artifacts.

3. **Re-encoding**:
   Every time a video is re-encoded (e.g., uploaded to YouTube, converted
   to a different format), the compression process runs again and
   destroys any pixel-level modifications.

## Where Data CAN Be Hidden in Video

### 1. Container Metadata

Video containers (MP4, MKV, AVI) support metadata fields:

- Title, author, description
- Custom tags (MKV supports arbitrary key-value pairs)
- Chapters and comments

**Detection:** Easy — metadata is readable with `ffprobe`, `mediainfo`,
or `exiftool`.

### 2. Subtitle Tracks

Containers can include text subtitle tracks (SRT, ASS) that may be
invisible if the viewer doesn't enable them.

**Detection:** Easy — `ffprobe -show_streams` reveals all tracks.

### 3. Additional Audio/Data Streams

MKV and MP4 support arbitrary attachment streams.

**Detection:** `ffprobe -show_streams` or `mkvinfo` for Matroska.

### 4. DCT Coefficient Modification

Instead of modifying pixels directly, modify the quantized DCT
coefficients. This requires:

- Decoding the video to coefficient domain (not pixel domain)
- Modifying coefficients carefully
- Re-encoding without re-quantization

This is an active research area (e.g., "HUGO", "WOW" algorithms for
images adapted to video).

### 5. Frame Timing / Motion Vector Manipulation

Hide data in the choice of motion vectors or in subtle frame timing.
Very stealthy but low capacity and research-grade.

## Practical Experiments (Without Modifying Pixels)

Since pixel-level video steganography requires deep codec integration,
here are safe experiments you can do:

### Experiment 1: Inspect Container Structure

```bash
# Install ffprobe (part of ffmpeg)
sudo pacman -S ffmpeg

# Inspect a video file
ffprobe -v quiet -show_format -show_streams video.mp4

# List all metadata
ffprobe -v quiet -show_entries format_tags video.mp4
```

### Experiment 2: Add Metadata

```bash
# Add custom metadata to an MP4
ffmpeg -i input.mp4 -c copy -metadata comment="hidden message" output.mp4

# Read it back
ffprobe -v quiet -show_entries format_tags=comment output.mp4
```

### Experiment 3: Attach a File to MKV

```bash
# Attach a text file to a Matroska container
mkvmerge -o output.mkv input.mkv \
  --attachment-mime-type text/plain \
  --attach-file secret.txt

# List attachments
mkvinfo output.mkv | grep -A5 "Attached"

# Extract attachments
mkvextract attachments output.mkv 1:extracted.txt
```

### Experiment 4: Extract Individual Frames

```bash
# Extract all I-frames (keyframes) as PNG
ffmpeg -i video.mp4 -vf "select=eq(pict_type\\,I)" \
  -vsync vfr frame_%04d.png

# Now you can apply PNG LSB steganography to individual frames
# (but re-encoding into video would destroy the changes)
```

## Comparison: Steganography vs Related Techniques

| Technique | Goal | Detection |
| ----------- | ------ | ----------- |
| **Steganography** | Hide data *within* a file | Statistical analysis, steganalysis |
| **Encryption** | Make data unreadable | Visible as encrypted; detectable |
| **Compression** | Reduce file size | Standard; not suspicious |
| **File concatenation** | Append one file to another | File size anomaly, trailing data |
| **Polyglot files** | Valid in multiple formats | Format-specific parsing |

### File Concatenation Example

```bash
# Create a polyglot: valid JPEG + appended ZIP
cat photo.jpg secret.zip > polyglot.jpg

# The file opens as a normal JPEG (viewers stop at JPEG EOF)
# But it also opens as a ZIP (ZIP finds its header from the end)
unzip polyglot.jpg  # This actually works!

# Detection:
file polyglot.jpg          # Reports JPEG
binwalk polyglot.jpg       # Reveals both JPEG and ZIP signatures
```

## Recoverability After Conversion

| Operation | PNG LSB | PDF Comment | Video Metadata |
| ----------- | --------- | ------------- | ---------------- |
| Copy/move | ✅ Preserved | ✅ Preserved | ✅ Preserved |
| PNG → PNG (re-save) | ✅ Preserved | N/A | N/A |
| PNG → JPEG | ❌ Destroyed | N/A | N/A |
| JPEG → PNG | ❌ Already lost | N/A | N/A |
| PDF → PDF (print) | ❌ Destroyed | ❌ Destroyed | N/A |
| Video re-encode | N/A | N/A | ⚠️ May be stripped |
| Upload to social media | ❌ Re-encoded | N/A | ❌ Metadata stripped |
| Screenshot | ❌ Destroyed | N/A | N/A |

## Security Implications

1. **Steganography alone is NOT secure.**
   It provides obscurity (hiding the existence of a message), not
   confidentiality.  Always encrypt the message *before* embedding.

2. **Detection is an arms race.**
   As embedding techniques improve, so do steganalysis tools.  Machine
   learning-based detectors can now identify LSB steganography with
   high accuracy.

3. **Metadata is the first place defenders look.**
   Any serious data-hiding attempt should avoid container metadata,
   which is trivially inspectable.

4. **Video is inherently hostile to steganography.**
   The aggressive compression used by modern codecs makes robust
   video steganography an open research problem.
