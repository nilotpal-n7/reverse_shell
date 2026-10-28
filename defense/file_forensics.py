"""
File Forensics & Embedded Data Detector
=======================================
Defensive forensic analysis tool to inspect files for hidden data,
steganographic anomalies, structural inconsistencies, and file disguise.

Educational Objectives:
    - Measure Shannon Entropy to distinguish plain, compressed, and encrypted data
    - Verify file extension against true binary header signatures (magic bytes)
    - Detect trailing overlay data appended beyond legitimate file format terminators
      (e.g., JPEG EOI marker, PNG IEND chunk, PDF %%EOF)
    - Extract printable strings and inspect for embedded indicators of compromise (IOCs)

Dependencies: Python stdlib only (os, sys, math, json, argparse, struct)

Usage:
    # Inspect a single file
    python -m defense.file_forensics --file path/to/sample.png

    # Scan an entire directory for anomalous files
    python -m defense.file_forensics --dir path/to/folder

    # Run self-contained educational demonstration
    python -m defense.file_forensics --demo

    # Output detailed report as JSON
    python -m defense.file_forensics --file sample.pdf --json
"""

import argparse
import json
import math
import os
from typing import Any

# Known file header signatures (magic bytes)
MAGIC_SIGNATURES: dict[str, tuple[bytes, str]] = {
    "png": (b"\x89PNG\r\n\x1a\n", "PNG Image"),
    "jpg": (b"\xff\xd8\xff", "JPEG Image"),
    "jpeg": (b"\xff\xd8\xff", "JPEG Image"),
    "gif": (b"GIF8", "GIF Image"),
    "pdf": (b"%PDF-", "PDF Document"),
    "zip": (b"PK\x03\x04", "ZIP Archive"),
    "elf": (b"\x7fELF", "Linux ELF Binary"),
    "exe": (b"MZ", "Windows PE Executable"),
    "dll": (b"MZ", "Windows PE DLL"),
    "gz": (b"\x1f\x8b", "Gzip Compressed File"),
}

# Known end-of-file (EOF) terminators for overlay detection
EOF_TERMINATORS: dict[str, bytes] = {
    "png": b"IEND\xaeB`\x82",  # PNG IEND chunk
    "jpg": b"\xff\xd9",  # JPEG EOI (End of Image)
    "jpeg": b"\xff\xd9",
    "pdf": b"%%EOF",  # PDF end marker
}


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon Entropy (0.0 to 8.0 bits per byte).
    - Plain text: ~3.5 - 5.0
    - Structured code/HTML: ~4.5 - 5.5
    - Compressed / packed data: ~7.0 - 7.9
    - Encrypted or uniform random: > 7.95
    """
    if not data:
        return 0.0

    length = len(data)
    frequencies: dict[int, int] = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def detect_file_type(header: bytes) -> tuple[str | None, str]:
    """Identify file type based on initial magic bytes."""
    for ext, (sig, desc) in MAGIC_SIGNATURES.items():
        if header.startswith(sig):
            return ext, desc
    return None, "Unknown Binary / Text"


def check_trailing_overlay(file_path: str, claimed_ext: str) -> tuple[bool, int, bytes]:
    """
    Detect if arbitrary payload data has been appended past the legitimate
    file format terminator (EOF).
    Returns (has_overlay, overlay_length, sample_overlay_bytes).
    """
    ext = claimed_ext.lower().lstrip(".")
    terminator = EOF_TERMINATORS.get(ext)
    if not terminator:
        return False, 0, b""

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        pos = data.rfind(terminator)
        if pos == -1:
            return False, 0, b""

        expected_end = pos + len(terminator)
        # Allow trailing whitespace / newlines (often present in valid PDFs)
        trailing = data[expected_end:].strip(b"\r\n\x00 ")

        if len(trailing) > 0:
            return True, len(trailing), trailing[:64]
    except OSError:
        pass

    return False, 0, b""


def extract_ascii_strings(data: bytes, min_length: int = 6) -> list[str]:
    """Extract printable ASCII string sequences from binary data."""
    result = []
    current: list[str] = []

    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII range
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                result.append("".join(current))
            current = []

    if len(current) >= min_length:
        result.append("".join(current))

    return result


def scan_file_forensics(file_path: str) -> dict[str, Any]:
    """Perform full forensic audit of a file."""
    if not os.path.exists(file_path):
        return {"error": f"File '{file_path}' does not exist"}

    file_size = os.path.getsize(file_path)
    filename = os.path.basename(file_path)
    claimed_ext = os.path.splitext(filename)[1].lower().lstrip(".")

    with open(file_path, "rb") as f:
        header = f.read(16)
        f.seek(0)
        full_data = f.read()

    entropy = calculate_entropy(full_data)
    detected_ext, detected_desc = detect_file_type(header)

    anomalies: list[str] = []
    suspicion_score = 0

    # 1. Extension vs Header Mismatch
    if claimed_ext in MAGIC_SIGNATURES:
        expected_sig, expected_desc = MAGIC_SIGNATURES[claimed_ext]
        # Special case: jpg / jpeg both match \xff\xd8\xff
        is_jpg = claimed_ext in ("jpg", "jpeg") and header.startswith(b"\xff\xd8\xff")
        if not header.startswith(expected_sig) and not is_jpg:
            anomalies.append(
                f"File extension mismatch: Extension is '.{claimed_ext}' ({expected_desc}) but header bytes do not match expected signature"
            )
            suspicion_score += 40
    elif detected_ext and claimed_ext and detected_ext != claimed_ext:
        if not (claimed_ext in ("jpg", "jpeg") and detected_ext in ("jpg", "jpeg")):
            anomalies.append(
                f"File extension mismatch: Extension is '.{claimed_ext}' but magic bytes indicate {detected_desc} (.{detected_ext})"
            )
            suspicion_score += 40

    # 2. Entropy assessment
    if entropy > 7.95:
        anomalies.append(
            f"Extremely high entropy ({entropy}/8.0) indicates encrypted or random hidden content"
        )
        suspicion_score += 25
    elif entropy > 7.5 and claimed_ext in ("txt", "csv", "log"):
        anomalies.append(f"Unusually high entropy ({entropy}) for plain text format")
        suspicion_score += 35

    # 3. Trailing Overlay Check
    has_overlay, overlay_len, _overlay_sample = check_trailing_overlay(file_path, claimed_ext)
    if has_overlay:
        anomalies.append(
            f"Detected {overlay_len} bytes of trailing overlay data appended beyond legitimate {claimed_ext.upper()} EOF terminator"
        )
        suspicion_score += 35

    # 4. Embedded Keywords Scan
    strings = extract_ascii_strings(full_data, min_length=5)
    flagged_keywords = [
        "eval(",
        "powershell",
        "cmd.exe",
        "/bin/sh",
        "BEGIN RSA",
        "token=",
        "http://",
        "https://",
    ]
    detected_keywords = []
    for s in strings:
        for kw in flagged_keywords:
            if kw.lower() in s.lower() and kw not in detected_keywords:
                detected_keywords.append(kw)

    if detected_keywords:
        anomalies.append(
            f"Identified sensitive or executable strings in file body: {', '.join(detected_keywords)}"
        )
        suspicion_score += 20

    return {
        "file_path": file_path,
        "file_name": filename,
        "file_size_bytes": file_size,
        "claimed_extension": claimed_ext,
        "detected_type": detected_desc,
        "detected_extension": detected_ext,
        "entropy": entropy,
        "has_overlay": has_overlay,
        "overlay_bytes_length": overlay_len,
        "suspicion_score": min(100, suspicion_score),
        "anomalies": anomalies,
        "sample_strings_count": len(strings),
    }


# ─── Scanner & Demonstration Class ───────────────────────────────


class FileForensicScanner:
    """Batch directory and file forensic scanner."""

    @staticmethod
    def scan_directory(dir_path: str, recursive: bool = False) -> list[dict[str, Any]]:
        results = []
        for root, _, files in os.walk(dir_path):
            for file in files:
                full_path = os.path.join(root, file)
                results.append(scan_file_forensics(full_path))
            if not recursive:
                break
        return results

    @staticmethod
    def run_educational_demo() -> None:
        """Run self-contained demonstration creating sample benign and tampered files."""
        print("=" * 70)
        print(" File Forensics Educational Demonstration ")
        print("=" * 70)

        demo_dir = "forensic_demo_temp"
        os.makedirs(demo_dir, exist_ok=True)

        clean_path = os.path.join(demo_dir, "clean_image.png")
        overlay_path = os.path.join(demo_dir, "overlay_tampered.png")
        disguised_path = os.path.join(demo_dir, "disguised_script.jpg")

        # 1. Create a minimal valid 1x1 PNG
        # Minimal valid 1x1 PNG binary data
        png_1x1 = (
            b"\x89PNG\r\n\x1a\n"
            b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
            b"\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        with open(clean_path, "wb") as f:
            f.write(png_1x1)

        # 2. Create tampered PNG with appended overlay data
        with open(overlay_path, "wb") as f:
            f.write(png_1x1 + b"\n--- SECRET ATTACHED DATA: 12345 ---\n")

        # 3. Create a disguised text script claiming to be a JPEG
        with open(disguised_path, "wb") as f:
            f.write(b"#!/bin/bash\necho 'This is an executable script renamed to .jpg'\n")

        print("Created test files:")
        print(f"  1. Clean PNG:          {clean_path}")
        print(f"  2. PNG with Overlay:   {overlay_path}")
        print(f"  3. Disguised Script:   {disguised_path}\n")

        for p in [clean_path, overlay_path, disguised_path]:
            res = scan_file_forensics(p)
            print("-" * 65)
            print(f"File: {res['file_name']} (Claimed: .{res['claimed_extension']})")
            print(f"  Detected Type:   {res['detected_type']}")
            print(f"  Entropy:         {res['entropy']} / 8.0")
            print(f"  Suspicion Score: {res['suspicion_score']}/100")
            if res["anomalies"]:
                print("  Flags Raised:")
                for a in res["anomalies"]:
                    print(f"    └── ⚠️  {a}")
            else:
                print("  Flags Raised:    None (Normal)")

        # Cleanup
        for p in [clean_path, overlay_path, disguised_path]:
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(demo_dir)
        except OSError:
            pass
        print("-" * 65)
        print("Demo completed and temporary artifacts cleaned up.")


# ─── CLI Entrypoint ──────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="File Forensics & Anomaly Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--file", type=str, default=None, help="Path to single file for analysis")
    parser.add_argument("--dir", type=str, default=None, help="Directory to scan")
    parser.add_argument("--recursive", action="store_true", help="Recursively scan subdirectories")
    parser.add_argument("--demo", action="store_true", help="Run educational demonstration")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    if args.demo:
        FileForensicScanner.run_educational_demo()
        return

    if args.file:
        report = scan_file_forensics(args.file)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("=" * 65)
            print(f" Forensic Report: {report['file_name']} ")
            print("=" * 65)
            print(f"Path:            {report['file_path']}")
            print(f"Size:            {report['file_size_bytes']} bytes")
            print(f"Claimed Ext:     .{report['claimed_extension']}")
            print(f"Detected Type:   {report['detected_type']}")
            print(f"Shannon Entropy: {report['entropy']} / 8.0")
            print(
                f"Overlay Data:    {'YES (' + str(report['overlay_bytes_length']) + ' bytes)' if report['has_overlay'] else 'None'}"
            )
            print(f"Suspicion Score: {report['suspicion_score']} / 100")
            print("\nAnomalies & Flags:")
            if report["anomalies"]:
                for a in report["anomalies"]:
                    print(f"  • {a}")
            else:
                print("  • No forensic anomalies detected.")
        return

    if args.dir:
        results = FileForensicScanner.scan_directory(args.dir, recursive=args.recursive)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print("=" * 75)
            print(f" Directory Forensics Scan ({len(results)} files examined) ")
            print("=" * 75)
            flagged = [r for r in results if r["suspicion_score"] > 20]
            for r in results:
                status = (
                    f"⚠️ [{r['suspicion_score']}/100]" if r["suspicion_score"] > 20 else "[CLEAN]"
                )
                print(
                    f"{status:<12} {r['file_name']:<25} Entropy: {r['entropy']:<6} Type: {r['detected_type']}"
                )
            print("-" * 75)
            print(f"Summary: {len(flagged)} flagged file(s) out of {len(results)} scanned.")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
