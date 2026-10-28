"""
Forensic Detection Tools
========================
Analyze files for signs of steganographic embedding, suspicious metadata,
and structural anomalies.

Capabilities:
    - File entropy analysis (high entropy → possible hidden data)
    - LSB statistical analysis for PNG images
    - PDF comment/structure inspection
    - File type verification (magic bytes vs extension)
    - Binary content pattern scanning
    - Comparative analysis between files

Educational Goals:
    - Understand how defenders detect steganography
    - Learn about file entropy and statistical analysis
    - See the difference between encrypted, compressed, and normal data
    - Practice forensic file inspection techniques

Dependencies:
    Python stdlib for all analysis
    Pillow (optional, for advanced PNG analysis)

Usage:
    python -m stego.detection --analyze file.png
    python -m stego.detection --entropy file.png
    python -m stego.detection --magic file.pdf
    python -m stego.detection --lsb-stats image.png
"""

import math
import os
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from PIL import Image

    _HAS_PILLOW = True
except ImportError:
    _HAS_PILLOW = False


# ═══════════════════════════════════════════════════════════════
#  MAGIC BYTES DATABASE
# ═══════════════════════════════════════════════════════════════

# Common file signatures (magic bytes) for type verification
MAGIC_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n": "PNG image",
    b"\xff\xd8\xff": "JPEG image",
    b"GIF87a": "GIF image (87a)",
    b"GIF89a": "GIF image (89a)",
    b"%PDF": "PDF document",
    b"PK\x03\x04": "ZIP archive (or DOCX/XLSX/JAR)",
    b"\x1f\x8b": "GZIP compressed",
    b"BM": "BMP image",
    b"\x00\x00\x01\x00": "ICO icon",
    b"RIFF": "RIFF container (WAV/AVI)",
    b"\x1aE\xdf\xa3": "Matroska/WebM video",
    b"\x00\x00\x00\x18ftypmp4": "MP4 video",
    b"\x00\x00\x00\x1cftypisom": "MP4 video (ISOM)",
    b"\x7fELF": "ELF executable (Linux)",
    b"MZ": "PE executable (Windows)",
}


# ═══════════════════════════════════════════════════════════════
#  ENTROPY ANALYSIS
# ═══════════════════════════════════════════════════════════════


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data.

    Entropy ranges from 0 (all identical bytes) to 8 (uniformly random).

    Interpretation:
        0.0 – 1.0:  Very low — likely null-filled or repetitive
        1.0 – 4.0:  Low — plain text, simple data
        4.0 – 6.0:  Medium — structured binary, some patterns
        6.0 – 7.5:  High — compressed data, executables
        7.5 – 8.0:  Very high — encrypted or random data

    Args:
        data: Raw binary data

    Returns:
        Shannon entropy in bits per byte (0.0 to 8.0)
    """
    if not data:
        return 0.0

    freq = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def entropy_analysis(file_path: str, block_size: int = 4096) -> dict[str, Any]:
    """Analyze a file's entropy, both overall and per-block.

    High-entropy regions within a low-entropy file may indicate
    hidden encrypted/compressed data.

    Args:
        file_path:  Path to the file
        block_size: Size of each analysis block in bytes

    Returns:
        Dict with overall and per-block entropy statistics
    """
    data = Path(file_path).read_bytes()
    overall = calculate_entropy(data)

    # Per-block analysis
    blocks = []
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        blocks.append(
            {
                "offset": i,
                "size": len(block),
                "entropy": round(calculate_entropy(block), 4),
            }
        )

    # Find anomalous blocks (high entropy in otherwise lower file)
    avg_entropy = sum(b["entropy"] for b in blocks) / len(blocks) if blocks else 0
    anomalous = [b for b in blocks if b["entropy"] > avg_entropy + 1.5]

    # Classify overall entropy
    if overall < 1.0:
        classification = "VERY LOW — likely padding or empty"
    elif overall < 4.0:
        classification = "LOW — plain text or simple structure"
    elif overall < 6.0:
        classification = "MEDIUM — structured binary data"
    elif overall < 7.5:
        classification = "HIGH — compressed or encoded data"
    else:
        classification = "VERY HIGH — possibly encrypted or random"

    return {
        "file": file_path,
        "file_size": len(data),
        "overall_entropy": round(overall, 4),
        "classification": classification,
        "block_size": block_size,
        "block_count": len(blocks),
        "avg_block_entropy": round(avg_entropy, 4),
        "min_block_entropy": round(min(b["entropy"] for b in blocks), 4) if blocks else 0,
        "max_block_entropy": round(max(b["entropy"] for b in blocks), 4) if blocks else 0,
        "anomalous_blocks": len(anomalous),
        "anomalous_offsets": [b["offset"] for b in anomalous],
    }


# ═══════════════════════════════════════════════════════════════
#  FILE TYPE VERIFICATION
# ═══════════════════════════════════════════════════════════════


def identify_file_type(file_path: str) -> dict[str, Any]:
    """Identify a file's type by its magic bytes, independent of extension.

    A mismatch between magic bytes and file extension is suspicious:
    it may indicate a polyglot file or deliberate disguise.

    Args:
        file_path: Path to the file

    Returns:
        Dict with extension, detected type, and mismatch flag
    """
    data = Path(file_path).read_bytes()
    extension = Path(file_path).suffix.lower()

    detected_type = "unknown"
    detected_magic = None

    for magic, file_type in MAGIC_SIGNATURES.items():
        if data[: len(magic)] == magic:
            detected_type = file_type
            detected_magic = magic.hex()
            break

    # Check for extension/content mismatch
    extension_types = {
        ".png": "PNG image",
        ".jpg": "JPEG image",
        ".jpeg": "JPEG image",
        ".gif": "GIF image",
        ".pdf": "PDF document",
        ".zip": "ZIP archive",
        ".gz": "GZIP compressed",
        ".bmp": "BMP image",
        ".mp4": "MP4 video",
        ".avi": "RIFF container",
        ".exe": "PE executable",
    }

    expected_type = extension_types.get(extension, "unknown")

    # Simple mismatch detection
    mismatch = (
        expected_type != "unknown"
        and detected_type != "unknown"
        and expected_type.split()[0] != detected_type.split()[0]
    )

    # Check for appended data after the expected file end
    trailing_data = _check_trailing_data(data, detected_type)

    return {
        "file": file_path,
        "file_size": len(data),
        "extension": extension,
        "expected_type": expected_type,
        "detected_type": detected_type,
        "magic_bytes": detected_magic,
        "type_mismatch": mismatch,
        "trailing_data": trailing_data,
    }


def _check_trailing_data(data: bytes, file_type: str) -> dict[str, Any]:
    """Check if there is data appended after the expected file end."""
    result = {"has_trailing": False, "trailing_bytes": 0}

    if file_type == "PNG image":
        # PNG ends with IEND chunk
        iend_pos = data.rfind(b"IEND")
        if iend_pos != -1:
            # IEND chunk = 4 len + 4 type + 0 data + 4 CRC = 12 bytes
            expected_end = iend_pos + 8  # after IEND + CRC
            if expected_end < len(data):
                trailing = len(data) - expected_end
                if trailing > 4:  # Allow small padding
                    result["has_trailing"] = True
                    result["trailing_bytes"] = trailing

    elif file_type == "PDF document":
        # PDF ends with %%EOF
        eof_pos = data.rfind(b"%%EOF")
        if eof_pos != -1:
            expected_end = eof_pos + 6  # %%EOF + newline
            if expected_end < len(data) - 2:
                trailing = len(data) - expected_end
                if trailing > 2:
                    result["has_trailing"] = True
                    result["trailing_bytes"] = trailing

    return result


# ═══════════════════════════════════════════════════════════════
#  PNG LSB STATISTICAL ANALYSIS
# ═══════════════════════════════════════════════════════════════


def lsb_analysis(image_path: str) -> dict[str, Any]:
    """Perform statistical analysis on the LSBs of a PNG image.

    Chi-squared test intuition:
        In a natural image, LSBs tend to follow patterns correlated with
        the image content.  After LSB embedding, the distribution becomes
        more uniform (each bit equally likely to be 0 or 1).

    Args:
        image_path: Path to a PNG image

    Returns:
        Dict with LSB statistics and suspicion indicators
    """
    if not _HAS_PILLOW:
        return {"error": "Pillow is required for LSB analysis", "available": False}

    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())

    # Collect LSBs per channel
    r_lsb, g_lsb, b_lsb = [], [], []
    for r, g, b in pixels:
        r_lsb.append(r & 1)
        g_lsb.append(g & 1)
        b_lsb.append(b & 1)

    def analyze_lsb_channel(lsbs: list, name: str) -> dict:
        total = len(lsbs)
        ones = sum(lsbs)
        zeros = total - ones
        ratio = ones / total if total > 0 else 0

        # A perfectly uniform distribution would have ratio ≈ 0.50
        # Natural images often have biased LSBs
        # After steganography, the ratio moves closer to 0.50
        deviation = abs(ratio - 0.5)

        # Simple chi-squared approximation
        expected = total / 2
        chi_sq = (ones - expected) ** 2 / expected + (zeros - expected) ** 2 / expected

        return {
            "channel": name,
            "total_bits": total,
            "ones": ones,
            "zeros": zeros,
            "ratio_ones": round(ratio, 6),
            "deviation_from_uniform": round(deviation, 6),
            "chi_squared": round(chi_sq, 4),
            "suspicious": deviation < 0.005,  # Very close to 0.5 → likely embedded
        }

    r_stats = analyze_lsb_channel(r_lsb, "Red")
    g_stats = analyze_lsb_channel(g_lsb, "Green")
    b_stats = analyze_lsb_channel(b_lsb, "Blue")

    # Overall assessment
    suspicious_channels = sum(1 for s in [r_stats, g_stats, b_stats] if s["suspicious"])

    # Check for our specific embedding marker
    all_lsb = []
    for r, g, b in pixels:
        all_lsb.extend([r & 1, g & 1, b & 1])

    has_sl_marker = False
    if len(all_lsb) >= 48:
        # Try to read our magic bytes
        first_bytes = bytearray()
        for i in range(0, 16, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | all_lsb[i + j]
            first_bytes.append(byte)
        if first_bytes == b"\x53\x4c":  # "SL" marker
            has_sl_marker = True

    return {
        "file": image_path,
        "image_size": f"{img.size[0]}×{img.size[1]}",
        "total_pixels": len(pixels),
        "channels": {
            "red": r_stats,
            "green": g_stats,
            "blue": b_stats,
        },
        "suspicious_channels": suspicious_channels,
        "has_sl_marker": has_sl_marker,
        "assessment": (
            "LIKELY EMBEDDED DATA"
            if suspicious_channels >= 2 or has_sl_marker
            else "POSSIBLY EMBEDDED DATA"
            if suspicious_channels == 1
            else "NO OBVIOUS EMBEDDING DETECTED"
        ),
        "note": (
            "This is a simplified analysis. Professional steganalysis tools "
            "use RS analysis, chi-squared attacks, and machine learning "
            "for more accurate detection."
        ),
    }


# ═══════════════════════════════════════════════════════════════
#  COMPREHENSIVE FILE ANALYSIS
# ═══════════════════════════════════════════════════════════════


def full_analysis(file_path: str) -> dict[str, Any]:
    """Run all available analyses on a file.

    Combines: file type, entropy, and format-specific analysis.
    """
    result = {
        "file": file_path,
        "file_size": os.path.getsize(file_path),
    }

    # File type
    result["type_analysis"] = identify_file_type(file_path)

    # Entropy
    result["entropy_analysis"] = entropy_analysis(file_path)

    # Format-specific
    detected = result["type_analysis"]["detected_type"]

    if "PNG" in detected and _HAS_PILLOW:
        result["lsb_analysis"] = lsb_analysis(file_path)

    if "PDF" in detected:
        # Import here to avoid circular deps
        try:
            from stego.pdf_stego import inspect_pdf

            result["pdf_analysis"] = inspect_pdf(file_path)
        except ImportError:
            pass

    # Overall suspicion score
    suspicion_factors = []

    if result["type_analysis"]["type_mismatch"]:
        suspicion_factors.append("File type / extension mismatch")

    if result["type_analysis"]["trailing_data"]["has_trailing"]:
        suspicion_factors.append(
            f"Trailing data: {result['type_analysis']['trailing_data']['trailing_bytes']} bytes"
        )

    entropy = result["entropy_analysis"]["overall_entropy"]
    if entropy > 7.5:
        suspicion_factors.append(f"Very high entropy ({entropy:.2f})")

    if result["entropy_analysis"]["anomalous_blocks"] > 0:
        suspicion_factors.append(
            f"Anomalous entropy blocks: {result['entropy_analysis']['anomalous_blocks']}"
        )

    if "lsb_analysis" in result:
        if result["lsb_analysis"].get("has_sl_marker"):
            suspicion_factors.append("SecurityLab LSB marker detected")
        if result["lsb_analysis"].get("suspicious_channels", 0) >= 2:
            suspicion_factors.append("LSB distribution anomaly (≥2 channels)")

    if "pdf_analysis" in result and result["pdf_analysis"].get("has_sl_embed"):
        suspicion_factors.append("SecurityLab PDF embed marker found")

    result["suspicion_factors"] = suspicion_factors
    result["suspicion_level"] = (
        "HIGH"
        if len(suspicion_factors) >= 2
        else "MEDIUM"
        if len(suspicion_factors) == 1
        else "LOW"
    )

    return result


# ═══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Forensic detection — analyze files for hidden data",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--analyze", metavar="FILE", help="Full analysis of a file")
    group.add_argument("--entropy", metavar="FILE", help="Entropy analysis only")
    group.add_argument("--magic", metavar="FILE", help="File type identification")
    group.add_argument("--lsb-stats", metavar="FILE", help="PNG LSB statistical analysis")

    args = parser.parse_args()

    if args.analyze:
        result = full_analysis(args.analyze)
    elif args.entropy:
        result = entropy_analysis(args.entropy)
    elif args.magic:
        result = identify_file_type(args.magic)
    elif args.lsb_stats:
        result = lsb_analysis(args.lsb_stats)
    else:
        result = {}

    print(json.dumps(result, indent=2, default=str))
