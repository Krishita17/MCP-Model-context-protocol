"""Unicode steganography encoder for embedding hidden instructions in text."""

from __future__ import annotations


class UnicodeSteganoEncoder:
    ZERO_WIDTH_SPACE = "​"
    ZERO_WIDTH_NON_JOINER = "‌"
    ZERO_WIDTH_JOINER = "‍"
    LEFT_TO_RIGHT_MARK = "‎"

    BIT_CHARS = {
        "0": ZERO_WIDTH_SPACE,
        "1": ZERO_WIDTH_NON_JOINER,
    }

    SEPARATOR = ZERO_WIDTH_JOINER

    HOMOGLYPH_MAP = {
        "a": "а",  # Cyrillic а
        "c": "с",  # Cyrillic с
        "e": "е",  # Cyrillic е
        "o": "о",  # Cyrillic о
        "p": "р",  # Cyrillic р
        "x": "х",  # Cyrillic х
        "y": "у",  # Cyrillic у (visually similar)
        "s": "ѕ",  # Cyrillic ѕ
        "i": "і",  # Cyrillic і
    }

    def encode_zero_width(self, hidden_text: str) -> str:
        binary = "".join(format(b, "08b") for b in hidden_text.encode("utf-8"))
        encoded_chars = [self.BIT_CHARS[bit] for bit in binary]
        return self.SEPARATOR + "".join(encoded_chars) + self.SEPARATOR

    def decode_zero_width(self, text: str) -> str:
        bits: list[str] = []
        for char in text:
            if char == self.ZERO_WIDTH_SPACE:
                bits.append("0")
            elif char == self.ZERO_WIDTH_NON_JOINER:
                bits.append("1")

        if len(bits) % 8 != 0:
            bits = bits[: len(bits) - (len(bits) % 8)]

        byte_values = [int("".join(bits[i : i + 8]), 2) for i in range(0, len(bits), 8)]
        return bytes(byte_values).decode("utf-8", errors="replace")

    def inject_homoglyph_instructions(self, visible_text: str, hidden_text: str) -> str:
        encoded_hidden = self.encode_zero_width(hidden_text)
        mid = len(visible_text) // 2
        return visible_text[:mid] + encoded_hidden + visible_text[mid:]

    def inject_rtl_override(self, visible_text: str, hidden_text: str) -> str:
        rtl_override = "‮"
        pop_directional = "‬"
        return f"{visible_text}{rtl_override}{hidden_text}{pop_directional}"

    def detect_invisible_chars(self, text: str) -> dict[str, int]:
        invisible_ranges = {
            "zero_width_space": "​",
            "zero_width_non_joiner": "‌",
            "zero_width_joiner": "‍",
            "left_to_right_mark": "‎",
            "right_to_left_mark": "‏",
            "rtl_override": "‮",
            "ltr_override": "‭",
            "pop_directional": "‬",
            "word_joiner": "⁠",
            "zero_width_no_break": "﻿",
        }
        counts: dict[str, int] = {}
        for name, char in invisible_ranges.items():
            count = text.count(char)
            if count > 0:
                counts[name] = count
        return counts

    def detect_homoglyphs(self, text: str) -> list[dict[str, str | int]]:
        findings: list[dict[str, str | int]] = []
        reverse_map = {v: k for k, v in self.HOMOGLYPH_MAP.items()}
        for i, char in enumerate(text):
            if char in reverse_map:
                findings.append({
                    "position": i,
                    "char": char,
                    "looks_like": reverse_map[char],
                    "unicode": f"U+{ord(char):04X}",
                })
        return findings
