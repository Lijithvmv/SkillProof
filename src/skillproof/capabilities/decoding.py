"""Reversing hiding techniques (zero-width and lookalike characters, escapes, character codes, split strings,
Base64 and hex runs) until the text stops changing, recording each step."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata


from skillproof.capabilities.positions import BASE64_RUN, CHR_CHAIN, CONFUSABLES, ESCAPES, FROM_CHAR_CODE, HEX_RUN, QUOTED, SPLIT_LITERALS, ZERO_WIDTH


# --------------------------------------------------------------------------------------------- decoding

def _printable(text: str, min_length: int = 6) -> bool:
    if len(text) < min_length:
        return False
    good = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return good / len(text) > 0.95 and sum(ch.isalpha() for ch in text) >= min(3, min_length)


def _try_base64(run: str) -> str | None:
    if run.isdigit() or run.isalpha() and (run.islower() or run.isupper()):
        return None  # plain words and numbers are not encodings
    try:
        decoded = base64.b64decode(run + "=" * (-len(run) % 4), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return decoded if _printable(decoded) else None


def decode_text(text: str, location: str, trail: list[dict[str, str]], max_rounds: int = 5) -> str:
    """Return the text with hidden content revealed. Decoded payloads are appended, not substituted, so the original
    stays visible and line references for the original text stay valid."""
    revealed: list[str] = []

    def note(technique: str, before: str, after: str) -> None:
        trail.append({"location": location, "technique": technique, "before": before[:120], "after": after[:200]})

    if ZERO_WIDTH.search(text):
        stripped = ZERO_WIDTH.sub("", text)
        joined = [w for w in re.findall(r"\S*[​-‏⁠-⁤﻿­]\S*", text)][:3]
        note("zero-width characters", " ".join(joined), ZERO_WIDTH.sub("", " ".join(joined)))
        text = stripped

    def fold(match: re.Match[str]) -> str:
        word = match.group(0)
        if word.isascii():  # nothing to fold; the check below would find no character above 127
            return word
        # Only words that mix plain Latin letters with lookalike letters (e.g. a Cyrillic "і" in "gіthub.com").
        # Math and typographic symbols such as "²" or "ℝ" are ordinary text, not disguise.
        if re.search(r"[A-Za-z]", word) and any(ord(ch) > 127 and ch.isalpha() for ch in word):
            plain = unicodedata.normalize("NFKC", word).translate(CONFUSABLES)
            if plain != word and re.fullmatch(r"[\x00-\x7f]+", plain):
                note("lookalike characters", word, plain)
                return plain
        return word

    if not text.isascii():  # an all-ASCII text has no lookalike letters to fold
        text = re.sub(r"[^\s`'\"<>()\[\]]+", fold, text)

    current = text
    for _ in range(max_rounds):
        found: list[str] = []
        for match in ESCAPES.finditer(current):
            try:
                after = match.group(0).encode("ascii").decode("unicode_escape")
            except UnicodeDecodeError:
                continue
            if _printable(after):
                note("string escapes", match.group(0), after)
                found.append(after)
        for match in CHR_CHAIN.finditer(current):
            after = "".join(chr(int(n)) for n in re.findall(r"\d+", match.group(0)) if 9 <= int(n) < 127)
            if _printable(after, min_length=3):  # short command names like "wget" are the point
                note("character codes", match.group(0), after)
                found.append(after)
        for match in FROM_CHAR_CODE.finditer(current):
            after = "".join(chr(int(n)) for n in re.findall(r"\d+", match.group(1)) if 9 <= int(n) < 127)
            if _printable(after, min_length=3):  # short command names like "wget" are the point
                note("character codes", match.group(0), after)
                found.append(after)
        for match in SPLIT_LITERALS.finditer(current):
            pieces = re.findall(QUOTED, match.group(0))
            after = "".join(piece[1:-1] for piece in pieces)
            if len(pieces) >= 2 and len(after) >= 4:
                note("split string literals", match.group(0), after)
                found.append(after)
        for match in BASE64_RUN.finditer(current):
            after = _try_base64(match.group(0))
            if after:
                note("base64", match.group(0), after)
                found.append(after)
        for match in HEX_RUN.finditer(current):
            try:
                after = bytes.fromhex(match.group(0)).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            if _printable(after):
                note("hex", match.group(0), after)
                found.append(after)
        new = [piece for piece in found if piece not in revealed]
        if not new:
            break
        revealed.extend(new)
        current = "\n".join(new)  # the next round looks inside what was just revealed (stacked encodings)
    return text if not revealed else text + "\n" + "\n".join(revealed)
