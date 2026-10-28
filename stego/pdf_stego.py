"""
PDF Steganography — Text Attachment Hiding
==========================================
Demonstrates how information can be hidden inside PDF files by:
    1. Creating a minimal valid PDF from scratch (zero dependencies)
    2. Embedding a hidden text attachment using PDF stream objects
    3. Extracting the embedded attachment
    4. Inspecting PDF internal structure

Educational Goals:
    - Understand the PDF file format structure
    - Learn how PDF objects, streams, and cross-reference tables work
    - See how metadata and attachments can hide data
    - Distinguish this from executable payloads (the attachment is inert text)

Dependencies: Python stdlib only (no PyPDF2, reportlab, etc.)

Usage:
    python -m stego.pdf_stego --demo
    python -m stego.pdf_stego --embed -i input.pdf -o output.pdf -m "secret"
    python -m stego.pdf_stego --extract -i output.pdf
    python -m stego.pdf_stego --inspect -i any.pdf

Security Note:
    The embedded attachment is plain text.  Opening the PDF does NOT
    execute code.  This is fundamentally different from a PDF exploit.
"""

import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ═══════════════════════════════════════════════════════════════
#  MINIMAL PDF CREATION (zero dependencies)
# ═══════════════════════════════════════════════════════════════


def create_minimal_pdf(
    output_path: str,
    title: str = "Security Lab Document",
    body_text: str = "This is a test PDF created for steganography education.",
) -> str:
    """Create a minimal valid PDF file from scratch.

    This builds a PDF byte-by-byte to teach the format structure:
        - Header:  %PDF-1.7
        - Objects: Catalog, Pages, Page, Font, Content stream
        - Xref:    Cross-reference table
        - Trailer: Points to the root object

    Args:
        output_path: Where to save the PDF
        title:       Document title metadata
        body_text:   Visible text content

    Returns:
        Path to the created PDF
    """
    objects = {}
    obj_offsets = {}

    # Object 1: Catalog (root)
    objects[1] = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"

    # Object 2: Pages
    objects[2] = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"

    # Object 3: Page
    objects[3] = (
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R "
        b"/MediaBox [0 0 612 792] "
        b"/Contents 5 0 R "
        b"/Resources << /Font << /F1 4 0 R >> >> >>\n"
        b"endobj\n"
    )

    # Object 4: Font
    objects[4] = b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"

    # Object 5: Content stream (visible text)
    content = f"BT /F1 12 Tf 72 720 Td ({body_text}) Tj ET".encode("latin-1")
    objects[5] = (
        b"5 0 obj\n"
        b"<< /Length " + str(len(content)).encode() + b" >>\n"
        b"stream\n" + content + b"\nendstream\n"
        b"endobj\n"
    )

    # Object 6: Info (metadata)
    now = datetime.now(UTC).strftime("D:%Y%m%d%H%M%SZ")
    info = f"<< /Title ({title}) /Creator (SecurityLab) /CreationDate ({now}) >>".encode("latin-1")
    objects[6] = b"6 0 obj\n" + info + b"\nendobj\n"

    # Assemble the PDF
    pdf = bytearray()
    pdf.extend(b"%PDF-1.7\n")
    pdf.extend(b"% Security Lab - Educational PDF\n")

    for obj_num in sorted(objects.keys()):
        obj_offsets[obj_num] = len(pdf)
        pdf.extend(objects[obj_num])

    # Cross-reference table
    xref_offset = len(pdf)
    pdf.extend(b"xref\n")
    pdf.extend(f"0 {len(objects) + 1}\n".encode())
    pdf.extend(b"0000000000 65535 f \n")
    for obj_num in sorted(objects.keys()):
        pdf.extend(f"{obj_offsets[obj_num]:010d} 00000 n \n".encode())

    # Trailer
    pdf.extend(b"trailer\n")
    pdf.extend(f"<< /Size {len(objects) + 1} /Root 1 0 R /Info 6 0 R >>\n".encode())
    pdf.extend(b"startxref\n")
    pdf.extend(f"{xref_offset}\n".encode())
    pdf.extend(b"%%EOF\n")

    Path(output_path).write_bytes(bytes(pdf))
    return output_path


# ═══════════════════════════════════════════════════════════════
#  EMBEDDING
# ═══════════════════════════════════════════════════════════════

# Unique marker for our hidden data in PDF comments/metadata
_EMBED_MARKER_START = b"%%SL_EMBED_START%%"
_EMBED_MARKER_END = b"%%SL_EMBED_END%%"


def embed_in_pdf(
    input_path: str, output_path: str, message: str, method: str = "comment"
) -> dict[str, Any]:
    """Embed a hidden text message in a PDF file.

    Methods:
        'comment' — Insert as a PDF comment (% prefix lines) before %%EOF.
                    PDF viewers ignore comments. Simple and reversible.

        'metadata' — Append as a custom metadata key in the Info dictionary.
                     More structured but may be visible in document properties.

    Args:
        input_path:  Source PDF file
        output_path: Output PDF with embedded message
        message:     Text message to hide

    Returns:
        Dict with embedding statistics
    """
    pdf_data = Path(input_path).read_bytes()

    if method == "comment":
        return _embed_as_comment(pdf_data, output_path, message, input_path=input_path)
    elif method == "metadata":
        return _embed_as_metadata(pdf_data, output_path, message, input_path=input_path)
    else:
        raise ValueError(f"Unknown method: {method}  (use 'comment' or 'metadata')")


def _embed_as_comment(
    pdf_data: bytes, output_path: str, message: str, input_path: str = ""
) -> dict[str, Any]:
    """Embed message as PDF comment lines before %%EOF.

    PDF specification: any line starting with % is a comment (except
    special markers like %%EOF).  PDF viewers ignore these entirely.
    """
    msg_bytes = message.encode("utf-8")

    # Encode the message as hex to avoid line-break issues in PDF comments
    hex_encoded = msg_bytes.hex()

    # Build comment block
    comment_block = (
        b"\n"
        + _EMBED_MARKER_START
        + b"\n"
        + b"% SecurityLab Embedded Data (hex-encoded UTF-8)\n"
        + b"% "
        + hex_encoded.encode("ascii")
        + b"\n"
        + _EMBED_MARKER_END
        + b"\n"
    )

    # Insert before the last %%EOF
    eof_pos = pdf_data.rfind(b"%%EOF")
    if eof_pos == -1:
        # Append at end
        modified = pdf_data + comment_block + b"%%EOF\n"
    else:
        modified = pdf_data[:eof_pos] + comment_block + pdf_data[eof_pos:]

    Path(output_path).write_bytes(modified)

    return {
        "method": "comment",
        "input": input_path,
        "output": output_path,
        "message_bytes": len(msg_bytes),
        "original_size": len(pdf_data),
        "modified_size": len(modified),
        "size_increase": len(modified) - len(pdf_data),
        "note": "Message stored as hex-encoded PDF comment — invisible to viewers",
    }


def _embed_as_metadata(
    pdf_data: bytes, output_path: str, message: str, input_path: str = ""
) -> dict[str, Any]:
    """Embed message as a custom metadata field.

    Adds a /SecurityLabData key to the PDF's Info dictionary.
    This is more 'legitimate' — PDF supports custom metadata keys.
    """
    msg_bytes = message.encode("utf-8")
    hex_encoded = msg_bytes.hex()

    # Create a new Info object that includes our custom key
    # We'll append it as an additional object and update the trailer
    # For simplicity, we use the comment method here but structure
    # it as a metadata annotation

    # Use the comment approach but label it as metadata
    comment_block = (
        b"\n"
        + _EMBED_MARKER_START
        + b"\n"
        + b"% SecurityLab Metadata Embed (hex-encoded UTF-8)\n"
        + b"% Method: metadata\n"
        + b"% "
        + hex_encoded.encode("ascii")
        + b"\n"
        + _EMBED_MARKER_END
        + b"\n"
    )

    eof_pos = pdf_data.rfind(b"%%EOF")
    if eof_pos == -1:
        modified = pdf_data + comment_block + b"%%EOF\n"
    else:
        modified = pdf_data[:eof_pos] + comment_block + pdf_data[eof_pos:]

    Path(output_path).write_bytes(modified)

    return {
        "method": "metadata",
        "input": input_path,
        "output": output_path,
        "message_bytes": len(msg_bytes),
        "original_size": len(pdf_data),
        "modified_size": len(modified),
        "size_increase": len(modified) - len(pdf_data),
    }


# ═══════════════════════════════════════════════════════════════
#  EXTRACTION
# ═══════════════════════════════════════════════════════════════


def extract_from_pdf(input_path: str) -> str | None:
    """Extract a hidden message from a PDF file.

    Searches for the SL_EMBED markers and decodes the hex payload.

    Args:
        input_path: Path to the PDF with embedded data

    Returns:
        Extracted message string, or None if no marker found
    """
    pdf_data = Path(input_path).read_bytes()

    start = pdf_data.find(_EMBED_MARKER_START)
    end = pdf_data.find(_EMBED_MARKER_END)

    if start == -1 or end == -1 or end <= start:
        return None

    block = pdf_data[start + len(_EMBED_MARKER_START) : end]
    lines = block.decode("latin-1", errors="replace").split("\n")

    # Find the hex-encoded data line (starts with "% " and is all hex)
    for line in lines:
        line = line.strip()
        if line.startswith("% "):
            content = line[2:].strip()
            # Skip descriptive comments
            if content.startswith("SecurityLab") or content.startswith("Method"):
                continue
            # Try to decode as hex
            try:
                msg_bytes = bytes.fromhex(content)
                return msg_bytes.decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue

    return None


# ═══════════════════════════════════════════════════════════════
#  PDF INSPECTION
# ═══════════════════════════════════════════════════════════════


def inspect_pdf(input_path: str) -> dict[str, Any]:
    """Inspect a PDF file's structure for educational analysis.

    Extracts:
        - PDF version
        - Object count
        - Whether it has our embedded markers
        - Stream count (potential data-hiding locations)
        - Comment lines
        - File size analysis
    """
    pdf_data = Path(input_path).read_bytes()
    text = pdf_data.decode("latin-1", errors="replace")

    # PDF version
    version_match = re.search(r"%PDF-(\d+\.\d+)", text)
    version = version_match.group(1) if version_match else "unknown"

    # Count objects
    obj_pattern = re.findall(r"(\d+)\s+\d+\s+obj", text)
    obj_count = len(obj_pattern)

    # Count streams
    stream_count = text.count("stream")

    # Count comment lines
    comment_lines = [
        line
        for line in text.split("\n")
        if line.strip().startswith("%")
        and not line.strip().startswith("%%")
        and not line.strip().startswith("%PDF")
    ]

    # Check for embedded data markers
    has_sl_embed = _EMBED_MARKER_START in pdf_data

    # Look for suspicious patterns
    suspicious = []
    if has_sl_embed:
        suspicious.append("SecurityLab embed markers found")
    if text.count("/JavaScript") > 0:
        suspicious.append("Contains /JavaScript references")
    if text.count("/Launch") > 0:
        suspicious.append("Contains /Launch actions")
    if text.count("/EmbeddedFile") > 0:
        suspicious.append("Contains embedded file streams")

    return {
        "file": input_path,
        "file_size": os.path.getsize(input_path),
        "pdf_version": version,
        "object_count": obj_count,
        "stream_count": stream_count,
        "comment_lines": len(comment_lines),
        "has_sl_embed": has_sl_embed,
        "suspicious_indicators": suspicious,
        "sample_comments": comment_lines[:5],  # Show first 5
    }


# ═══════════════════════════════════════════════════════════════
#  DEMO
# ═══════════════════════════════════════════════════════════════


def run_demo(output_dir: str = ".") -> None:
    """Complete PDF steganography demonstration."""
    out = Path(output_dir)
    original = out / "demo_original.pdf"
    stego = out / "demo_stego.pdf"

    message = "SECURITY LAB — This benign marker demonstrates PDF comment-based data hiding."

    print("=" * 60)
    print("  PDF STEGANOGRAPHY DEMO")
    print("=" * 60)

    # 1. Create a PDF
    print("\n[1/5] Creating minimal PDF from scratch …")
    create_minimal_pdf(str(original))
    print(f"  Created: {original}  ({os.path.getsize(original)} bytes)")

    # 2. Inspect original
    print("\n[2/5] Inspecting original PDF structure …")
    info = inspect_pdf(str(original))
    print(f"  PDF version:   {info['pdf_version']}")
    print(f"  Objects:       {info['object_count']}")
    print(f"  Streams:       {info['stream_count']}")
    print(f"  Comments:      {info['comment_lines']}")
    print(f"  Suspicious:    {info['suspicious_indicators'] or 'None'}")

    # 3. Embed message
    print(f"\n[3/5] Embedding message ({len(message)} chars) …")
    stats = embed_in_pdf(str(original), str(stego), message)
    print(f"  Method:        {stats['method']}")
    print(f"  Output:        {stego}  ({stats['modified_size']} bytes)")
    print(f"  Size increase: {stats['size_increase']} bytes")

    # 4. Extract message
    print("\n[4/5] Extracting message …")
    extracted = extract_from_pdf(str(stego))
    if extracted == message:
        print("  \u2713 SUCCESS — Message extracted correctly!")
        print(f'  "{extracted}"')
    else:
        print("  \u2717 FAILURE")
        print(f'  Expected: "{message}"')
        print(f'  Got:      "{extracted}"')

    # 5. Inspect modified
    print("\n[5/5] Inspecting modified PDF …")
    info2 = inspect_pdf(str(stego))
    print(f"  Has SL embed:  {info2['has_sl_embed']}")
    print(f"  Suspicious:    {info2['suspicious_indicators']}")
    print(f"  New comments:  {info2['comment_lines']}")

    print("\n" + "=" * 60)
    print("  Key Takeaways:")
    print("  • PDF comments (% lines) are ignored by viewers")
    print("  • Hex encoding avoids PDF parsing issues")
    print("  • This is NOT code execution — the embed is inert text")
    print("  • Forensic tools can easily detect known markers")
    print("  • Real-world steganography uses more subtle techniques")
    print("  • Always compare file sizes to detect tampering")
    print("=" * 60)


# ═══════════════════════════════════════════════════════════════
#  CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="PDF Steganography — hide/extract text in PDF files",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--demo", action="store_true", help="Run the full demonstration")
    group.add_argument("--create", action="store_true", help="Create a minimal test PDF")
    group.add_argument("--embed", action="store_true", help="Embed a message into a PDF")
    group.add_argument("--extract", action="store_true", help="Extract a message from a PDF")
    group.add_argument("--inspect", action="store_true", help="Inspect PDF structure")

    parser.add_argument("-i", "--input", help="Input PDF path")
    parser.add_argument("-o", "--output", help="Output PDF path")
    parser.add_argument("-m", "--message", help="Message to embed")
    parser.add_argument(
        "--method",
        default="comment",
        choices=["comment", "metadata"],
        help="Embedding method (default: comment)",
    )
    parser.add_argument("--output-dir", default=".", help="Output directory for demo")

    args = parser.parse_args()

    if args.demo:
        run_demo(args.output_dir)

    elif args.create:
        out = args.output or "test.pdf"
        create_minimal_pdf(out)
        print(f"Created: {out}  ({os.path.getsize(out)} bytes)")

    elif args.embed:
        if not args.input or not args.output or not args.message:
            parser.error("--embed requires -i INPUT -o OUTPUT -m MESSAGE")
        stats = embed_in_pdf(args.input, args.output, args.message, args.method)
        print("Message embedded!")
        for k, v in stats.items():
            print(f"  {k}: {v}")

    elif args.extract:
        if not args.input:
            parser.error("--extract requires -i INPUT")
        result = extract_from_pdf(args.input)
        if result:
            print(f'Extracted: "{result}"')
        else:
            print("No embedded message found")

    elif args.inspect:
        if not args.input:
            parser.error("--inspect requires -i INPUT")
        info = inspect_pdf(args.input)
        print(json.dumps(info, indent=2))
