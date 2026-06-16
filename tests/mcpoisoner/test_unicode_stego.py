"""Tests for Unicode steganography encoder/decoder."""

import pytest

from mcpoisoner.payloads.unicode_stego import UnicodeSteganoEncoder


@pytest.fixture
def encoder():
    return UnicodeSteganoEncoder()


class TestUnicodeStego:
    def test_encode_decode_roundtrip(self, encoder):
        original = "Hello, World!"
        encoded = encoder.encode_zero_width(original)
        decoded = encoder.decode_zero_width(encoded)
        assert decoded == original

    def test_encoded_invisible_in_text(self, encoder):
        hidden = encoder.encode_zero_width("secret")
        visible = f"Normal text{hidden}"
        assert visible.startswith("Normal text")
        printable = "".join(c for c in visible if c.isprintable())
        assert printable == "Normal text"

    def test_detect_invisible_chars(self, encoder):
        text = f"Hello{encoder.ZERO_WIDTH_SPACE * 5} World"
        found = encoder.detect_invisible_chars(text)
        assert found.get("zero_width_space", 0) == 5

    def test_detect_homoglyphs(self, encoder):
        text = "Hеllo"  # Cyrillic е
        findings = encoder.detect_homoglyphs(text)
        assert len(findings) == 1
        assert findings[0]["looks_like"] == "e"

    def test_rtl_injection(self, encoder):
        result = encoder.inject_rtl_override("visible", "hidden")
        assert "visible" in result
        assert "hidden" in result

    def test_empty_string(self, encoder):
        encoded = encoder.encode_zero_width("")
        decoded = encoder.decode_zero_width(encoded)
        assert decoded == ""

    def test_unicode_content(self, encoder):
        original = "日本語テスト"
        encoded = encoder.encode_zero_width(original)
        decoded = encoder.decode_zero_width(encoded)
        assert decoded == original
