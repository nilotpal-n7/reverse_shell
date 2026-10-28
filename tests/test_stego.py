"""
Tests for Steganography & Detection Modules
===========================================
Validates PNG LSB embedding/extraction, PDF text hiding, and forensic entropy detection.
"""

import os
import tempfile
import unittest

from stego.detection import calculate_entropy, identify_file_type
from stego.pdf_stego import create_minimal_pdf, embed_in_pdf, extract_from_pdf

# Check Pillow availability for PNG tests
try:
    from PIL import Image

    from stego.png_stego import embed_message, extract_message

    _HAS_PILLOW = True
except ImportError:
    _HAS_PILLOW = False


class TestSteganography(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = self.temp_dir.name

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pdf_creation_and_extraction(self):
        """Test minimal PDF creation, comment embedding, and extraction."""
        pdf_path = os.path.join(self.dir_path, "test_doc.pdf")
        stego_pdf_path = os.path.join(self.dir_path, "test_stego.pdf")

        create_minimal_pdf(pdf_path, title="Unit Test PDF", body_text="Test Content")
        self.assertTrue(os.path.exists(pdf_path))

        secret_text = "SecurityLab-Hidden-Payload-987654"
        embed_stats = embed_in_pdf(pdf_path, stego_pdf_path, secret_text, method="comment")
        self.assertEqual(embed_stats["method"], "comment")
        self.assertTrue(os.path.exists(stego_pdf_path))

        extracted = extract_from_pdf(stego_pdf_path)
        self.assertEqual(extracted, secret_text)

    def test_pdf_metadata_method(self):
        """Test embedding and extraction using metadata mode."""
        pdf_path = os.path.join(self.dir_path, "test_meta.pdf")
        stego_pdf_path = os.path.join(self.dir_path, "test_meta_stego.pdf")

        create_minimal_pdf(pdf_path)
        secret_text = "Metadata-Secret-Tokens-4321"
        embed_in_pdf(pdf_path, stego_pdf_path, secret_text, method="metadata")

        extracted = extract_from_pdf(stego_pdf_path)
        self.assertEqual(extracted, secret_text)

    @unittest.skipUnless(_HAS_PILLOW, "Pillow library is not installed")
    def test_png_lsb_embedding_and_extraction(self):
        """Test PNG LSB embedding and exact recovery."""
        png_path = os.path.join(self.dir_path, "base.png")
        stego_path = os.path.join(self.dir_path, "embedded.png")

        # Create a small 50x50 RGB image
        img = Image.new("RGB", (50, 50), color=(128, 64, 200))
        img.save(png_path, "PNG")

        secret_msg = "Hello LSB Steganography World!"
        stats = embed_message(png_path, stego_path, secret_msg)
        self.assertGreater(stats["pixels_modified"], 0)

        extracted = extract_message(stego_path)
        self.assertEqual(extracted, secret_msg)

    def test_entropy_calculation(self):
        """Test Shannon entropy calculation extremes."""
        # Low entropy: all uniform zeroes
        uniform_data = b"\x00" * 1000
        entropy_low = calculate_entropy(uniform_data)
        self.assertEqual(entropy_low, 0.0)

        # High entropy: all 256 byte values uniformly distributed
        uniform_all_bytes = bytes(range(256)) * 10
        entropy_high = calculate_entropy(uniform_all_bytes)
        self.assertAlmostEqual(entropy_high, 8.0, delta=0.05)

    def test_magic_byte_verification(self):
        """Test verification of magic signatures."""
        png_path = os.path.join(self.dir_path, "dummy.png")
        # Write valid PNG header
        with open(png_path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...")

        res = identify_file_type(png_path)
        self.assertFalse(res["type_mismatch"])
        self.assertEqual(res["detected_type"], "PNG image")


if __name__ == "__main__":
    unittest.main()
