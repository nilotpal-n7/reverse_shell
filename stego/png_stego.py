"""
PNG LSB Steganography
=====================
Embed and extract hidden text messages in PNG image pixel data using
Least Significant Bit (LSB) substitution.

How It Works:
    A PNG image stores pixels as RGB (or RGBA) colour channels, each
    valued 0–255 (8 bits).  The *least significant bit* of each channel
    contributes minimally to the visible colour.  By replacing the LSB
    of successive colour-channel bytes with the bits of a secret message,
    we embed data that is visually imperceptible.

    Encoding:
        1. Convert the message to a byte string.
        2. Prepend a 4-byte big-endian length header.
        3. Iterate over pixel channels; replace each channel's LSB with
           one bit of the message.
        4. Save as PNG (lossless — JPEG would destroy LSB data).

    Decoding:
        1. Read the first 32 channel LSBs → 4-byte length header.
        2. Read (length × 8) more LSBs → message bytes.
        3. Decode UTF-8.

Security Note:
    This is an educational demonstration.  LSB steganography is well-known
    and detectable by statistical analysis (chi-squared, RS analysis).
    It is NOT a secure covert channel.

Dependencies: Pillow (PIL)

Usage:
    python -m stego.png_stego --demo                # Run full demo
    python -m stego.png_stego --embed -i in.png -o out.png -m "Hello"
    python -m stego.png_stego --extract -i out.png
    python -m stego.png_stego --compare -a in.png -b out.png
"""

import os
import struct
from pathlib import Path

try:
    from PIL import Image

    _HAS_PILLOW = True
except ImportError:
    _HAS_PILLOW = False


# ═══════════════════════════════════════════════════════════════
#  CORE FUNCTIONS
# ═══════════════════════════════════════════════════════════════

# Magic bytes prepended before the length header for validation ("SL" = Security Lab)
_MAGIC = b"\x53\x4c"


def embed_message(image_path: str, output_path: str, message: str) -> dict:
    """Embed a text message into a PNG image using LSB substitution.

    Args:
        image_path:  Path to the input PNG image
        output_path: Path for the output PNG (with embedded message)
        message:     UTF-8 text message to embed

    Returns:
        Dict with stats: pixels_used, capacity, message_bytes, etc.

    Raises:
        ValueError:  If the image is too small for the message
        ImportError: If Pillow is not installed
    """
    _require_pillow()

    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    width, height = img.size
    total_channels = len(pixels) * 3  # R, G, B per pixel

    # Prepare payload:  MAGIC (2 bytes) + LENGTH (4 bytes) + MESSAGE
    msg_bytes = message.encode("utf-8")
    payload = _MAGIC + struct.pack("!I", len(msg_bytes)) + msg_bytes
    payload_bits = _bytes_to_bits(payload)

    # Check capacity
    if len(payload_bits) > total_channels:
        raise ValueError(
            f"Message too large: needs {len(payload_bits)} channel bits, "
            f"image has {total_channels} ({width}×{height} pixels). "
            f"Max message ≈ {(total_channels - 48) // 8} bytes."
        )

    # Embed bits into LSBs
    modified_pixels = list(pixels)  # shallow copy of tuples
    bit_idx = 0

    for px_idx in range(len(modified_pixels)):
        r, g, b = modified_pixels[px_idx]
        channels = [r, g, b]

        for ch in range(3):
            if bit_idx < len(payload_bits):
                # Clear LSB, set to message bit
                channels[ch] = (channels[ch] & 0xFE) | payload_bits[bit_idx]
                bit_idx += 1

        modified_pixels[px_idx] = tuple(channels)

        if bit_idx >= len(payload_bits):
            break

    # Create output image
    out_img = Image.new("RGB", (width, height))
    out_img.putdata(modified_pixels)
    out_img.save(output_path, "PNG")

    return {
        "input": image_path,
        "output": output_path,
        "image_size": f"{width}×{height}",
        "message_bytes": len(msg_bytes),
        "payload_bits": len(payload_bits),
        "total_channels": total_channels,
        "capacity_bytes": (total_channels - 48) // 8,
        "utilization_pct": round(len(payload_bits) / total_channels * 100, 2),
        "pixels_modified": (len(payload_bits) + 2) // 3,
    }


def extract_message(image_path: str) -> str | None:
    """Extract a hidden message from a PNG image.

    Args:
        image_path: Path to the PNG image with embedded data

    Returns:
        Extracted message string, or None if no valid message found

    Raises:
        ImportError: If Pillow is not installed
    """
    _require_pillow()

    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())

    # Extract all LSBs
    bits = []
    for r, g, b in pixels:
        bits.extend([r & 1, g & 1, b & 1])

    # Read magic (2 bytes = 16 bits)
    if len(bits) < 48:  # 2 magic + 4 length = 6 bytes = 48 bits minimum
        return None

    magic_bytes = _bits_to_bytes(bits[:16])
    if magic_bytes != _MAGIC:
        return None

    # Read length (4 bytes = 32 bits, starting at bit 16)
    length_bytes = _bits_to_bytes(bits[16:48])
    msg_length = struct.unpack("!I", length_bytes)[0]

    # Sanity check
    if msg_length <= 0 or msg_length > 10_000_000:
        return None

    # Read message
    msg_start = 48
    msg_end = msg_start + msg_length * 8

    if msg_end > len(bits):
        return None

    msg_bytes = _bits_to_bytes(bits[msg_start:msg_end])

    try:
        return msg_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def compare_images(original_path: str, modified_path: str) -> dict:
    """Compare original and modified images to quantify changes.

    Returns:
        Dict with channel-level difference statistics.
    """
    _require_pillow()

    orig = Image.open(original_path).convert("RGB")
    mod = Image.open(modified_path).convert("RGB")

    if orig.size != mod.size:
        return {
            "error": f"Size mismatch: {orig.size} vs {mod.size}",
            "comparable": False,
        }

    orig_pixels = list(orig.getdata())
    mod_pixels = list(mod.getdata())

    total_pixels = len(orig_pixels)
    changed_pixels = 0
    max_diff = 0
    total_diff = 0
    channel_diffs = {"R": 0, "G": 0, "B": 0}

    for i in range(total_pixels):
        r1, g1, b1 = orig_pixels[i]
        r2, g2, b2 = mod_pixels[i]

        dr, dg, db = abs(r1 - r2), abs(g1 - g2), abs(b1 - b2)

        if dr > 0 or dg > 0 or db > 0:
            changed_pixels += 1

        channel_diffs["R"] += dr
        channel_diffs["G"] += dg
        channel_diffs["B"] += db

        pixel_diff = dr + dg + db
        total_diff += pixel_diff
        max_diff = max(max_diff, dr, dg, db)

    orig_size = os.path.getsize(original_path)
    mod_size = os.path.getsize(modified_path)

    return {
        "comparable": True,
        "image_size": f"{orig.size[0]}×{orig.size[1]}",
        "total_pixels": total_pixels,
        "changed_pixels": changed_pixels,
        "changed_pct": round(changed_pixels / total_pixels * 100, 4),
        "max_channel_diff": max_diff,
        "avg_channel_diff": round(total_diff / (total_pixels * 3), 6),
        "channel_total_diffs": channel_diffs,
        "original_file_bytes": orig_size,
        "modified_file_bytes": mod_size,
        "file_size_diff_bytes": mod_size - orig_size,
        "note": (
            "LSB changes are at most ±1 per channel, making them "
            "invisible to the human eye.  Statistical analysis (chi-squared, "
            "RS analysis) can detect the pattern."
        ),
    }


# ═══════════════════════════════════════════════════════════════
#  DEMO
# ═══════════════════════════════════════════════════════════════


def run_demo(output_dir: str = ".") -> None:
    """Run a complete embed → extract → compare demonstration.

    Creates a test image, embeds a message, extracts it, and compares.
    """
    _require_pillow()

    out = Path(output_dir)
    original = out / "demo_original.png"
    stego = out / "demo_stego.png"

    message = (
        "SECURITY LAB MARKER — This is a harmless test message for LSB steganography education."
    )

    # 1. Create a test image (gradient pattern)
    print("=" * 60)
    print("  PNG LSB STEGANOGRAPHY DEMO")
    print("=" * 60)

    print("\n[1/4] Creating test image …")
    img = Image.new("RGB", (200, 200))
    pixels = []
    for y in range(200):
        for x in range(200):
            r = int(x / 200 * 255)
            g = int(y / 200 * 255)
            b = int((x + y) / 400 * 255)
            pixels.append((r, g, b))
    img.putdata(pixels)
    img.save(str(original), "PNG")
    print(f"  Created: {original}  ({os.path.getsize(original)} bytes)")

    # 2. Embed message
    print(f"\n[2/4] Embedding message ({len(message)} chars) …")
    stats = embed_message(str(original), str(stego), message)
    print(f"  Output:  {stego}  ({os.path.getsize(stego)} bytes)")
    print(f"  Pixels modified: {stats['pixels_modified']} / {200 * 200}")
    print(f"  Capacity used:   {stats['utilization_pct']}%")

    # 3. Extract message
    print("\n[3/4] Extracting message …")
    extracted = extract_message(str(stego))
    if extracted == message:
        print("  \u2713 SUCCESS — Message extracted correctly!")
        print(f'  "{extracted}"')
    else:
        print("  \u2717 FAILURE — Extraction mismatch")
        print(f'  Expected: "{message}"')
        print(f'  Got:      "{extracted}"')

    # 4. Compare images
    print("\n[4/4] Comparing images …")
    diff = compare_images(str(original), str(stego))
    if diff["comparable"]:
        print(f"  Pixels changed:     {diff['changed_pixels']} / {diff['total_pixels']}")
        print(f"  Change percentage:  {diff['changed_pct']}%")
        print(f"  Max channel diff:   {diff['max_channel_diff']}  (LSB = max 1)")
        print(f"  Avg channel diff:   {diff['avg_channel_diff']}")
        print(f"  File size change:   {diff['file_size_diff_bytes']:+d} bytes")
    else:
        print(f"  Error: {diff['error']}")

    print("\n" + "=" * 60)
    print("  Key Takeaways:")
    print("  • LSB changes are at most ±1 per channel — invisible to eyes")
    print("  • PNG is required (lossless); JPEG would destroy the data")
    print("  • Statistical analysis CAN detect LSB steganography")
    print("  • Capacity depends on image dimensions (3 bits per pixel)")
    print("=" * 60)


# ═══════════════════════════════════════════════════════════════
#  BIT MANIPULATION HELPERS
# ═══════════════════════════════════════════════════════════════


def _bytes_to_bits(data: bytes) -> list:
    """Convert bytes to a list of individual bits (MSB first)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list) -> bytes:
    """Convert a list of bits back to bytes (MSB first)."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = byte << 1 | bits[i + j] if i + j < len(bits) else byte << 1
        result.append(byte)
    return bytes(result)


def _require_pillow() -> None:
    """Raise ImportError with install instructions if Pillow is missing."""
    if not _HAS_PILLOW:
        raise ImportError(
            "Pillow is required for PNG steganography.\n"
            "Install it with:\n"
            "  pip install Pillow\n"
            "Or, inside the project virtual environment:\n"
            "  pip install -r requirements.txt"
        )


# ═══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="PNG LSB Steganography — embed/extract hidden text in images",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--demo", action="store_true", help="Run the full demonstration")
    group.add_argument("--embed", action="store_true", help="Embed a message into an image")
    group.add_argument("--extract", action="store_true", help="Extract a message from an image")
    group.add_argument("--compare", action="store_true", help="Compare two images")

    parser.add_argument("-i", "--input", help="Input image path")
    parser.add_argument("-o", "--output", help="Output image path")
    parser.add_argument("-m", "--message", help="Message to embed")
    parser.add_argument("-a", "--image-a", help="First image (for compare)")
    parser.add_argument("-b", "--image-b", help="Second image (for compare)")
    parser.add_argument("--output-dir", default=".", help="Output directory for demo files")

    args = parser.parse_args()

    if args.demo:
        run_demo(args.output_dir)

    elif args.embed:
        if not args.input or not args.output or not args.message:
            parser.error("--embed requires -i INPUT -o OUTPUT -m MESSAGE")
        stats = embed_message(args.input, args.output, args.message)
        print("Message embedded successfully!")
        for k, v in stats.items():
            print(f"  {k}: {v}")

    elif args.extract:
        if not args.input:
            parser.error("--extract requires -i INPUT")
        result = extract_message(args.input)
        if result is not None:
            print(f'Extracted message: "{result}"')
        else:
            print("No embedded message found (or not a valid SL-format embed)")

    elif args.compare:
        if not args.image_a or not args.image_b:
            parser.error("--compare requires -a IMAGE_A -b IMAGE_B")
        diff = compare_images(args.image_a, args.image_b)
        import json as _json

        print(_json.dumps(diff, indent=2))
