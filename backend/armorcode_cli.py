#!/usr/bin/env python3
"""
ArmorCode — Zero-Width Steganography IP Watermarking CLI + Gemma 3 1B Auditor
100% Interoperable with the ArmorCode Browser Dashboard.

Protocol Mapping:
  Bit '0'    -> Zero-Width Space (\u200B)
  Bit '1'    -> Zero-Width Non-Joiner (\u200C)
  Frame Sync -> Zero-Width Joiner (\u200D)
  AI Auditor -> Local Ollama 'gemma3:1b' (http://localhost:11434/api/generate)
"""

import sys
import re
import json
import urllib.request
import argparse
from typing import Optional, Tuple

if sys.platform == "win32":
    import io
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


# Protocol configuration
ZW_ZERO = '\u200b'  # Binary 0
ZW_ONE  = '\u200c'  # Binary 1
ZW_SYNC = '\u200d'  # Frame Sync Delimiter
DEFAULT_AUTHOR_ID = "Hemanth-2026"
DEFAULT_OWNER_EMAIL = "hemanth@creator.io"


# Watermark encoding
def compute_checksum(data_bytes: bytes) -> int:
    """Computes an 8-bit rolling XOR checksum identical to the JS engine."""
    crc = 0x5A
    for b in data_bytes:
        crc = ((crc << 1) | (crc >> 7)) & 0xFF
        crc ^= b
    return crc & 0xFF


def parse_author_and_email(raw_payload: str) -> Tuple[str, Optional[str]]:
    """Extracts signature name and owner email from raw payload string."""
    if not raw_payload:
        return ("UNKNOWN", None)

    match_angle = re.match(r"^(.*?)\s*<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>$", raw_payload)
    if match_angle:
        return (match_angle.group(1).strip(), match_angle.group(2).strip().lower())

    match_bracket = re.match(r"^(.*?)\s*\[owner:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\]$", raw_payload, re.I)
    if match_bracket:
        return (match_bracket.group(1).strip(), match_bracket.group(2).strip().lower())

    match_pipe = re.match(r"^(.*?)\s*\|\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$", raw_payload)
    if match_pipe:
        return (match_pipe.group(1).strip(), match_pipe.group(2).strip().lower())

    return (raw_payload.strip(), None)


def encode_signature_to_zw(author_id: str, owner_email: Optional[str] = None, include_checksum: bool = True) -> str:
    """Converts an Author ID string + optional Owner Email into a framed zero-width binary packet."""
    author_str = author_id.strip()
    if owner_email and "<" not in author_str and "@" not in author_str:
        author_str = f"{author_str} <{owner_email.strip().lower()}>"

    raw_bytes = author_str.encode('utf-8')
    if include_checksum:
        crc = compute_checksum(raw_bytes)
        payload_bytes = raw_bytes + bytes([crc])
    else:
        payload_bytes = raw_bytes

    bits = ''.join(f'{byte:08b}' for byte in payload_bytes)
    zw_body = ''.join(ZW_ZERO if bit == '0' else ZW_ONE for bit in bits)
    return f"{ZW_SYNC}{zw_body}{ZW_SYNC}"


def strip_zero_width(text: str) -> str:
    """Removes any existing zero-width characters."""
    return re.sub(r'[\u200b\u200c\u200d]', '', text)


def watermark_text(text: str, author_id: str = DEFAULT_AUTHOR_ID, owner_email: Optional[str] = None, distributed: bool = True) -> str:
    """Injects the zero-width watermark payload into source text or code."""
    clean_text = strip_zero_width(text)
    packet = encode_signature_to_zw(author_id, owner_email=owner_email, include_checksum=True)

    if not distributed or len(clean_text) < 30:
        return clean_text[:1] + packet + clean_text[1:]

    tokens = re.split(r'(\s+)', clean_text)
    output = []
    word_count = 0
    copies = 0

    for tok in tokens:
        if tok.strip():
            word_count += 1
            if (word_count == 1 or word_count % 12 == 0) and copies < 15:
                output.append(tok + packet)
                copies += 1
                continue
        output.append(tok)

    return ''.join(output)


# Watermark auditing
def audit_text(suspected_text: str) -> dict:
    """Extracts and verifies zero-width watermarks from suspected scraped text."""
    zw_stream = ''.join(ch for ch in suspected_text if ch in (ZW_ZERO, ZW_ONE, ZW_SYNC))
    if not zw_stream:
        return {"detected": False, "author_id": None, "owner_email": None, "frames_recovered": 0}

    segments = [seg for seg in zw_stream.split(ZW_SYNC) if len(seg) >= 8]
    recovered_authors = []

    for seg in segments:
        bits = ''.join('0' if ch == ZW_ZERO else '1' for ch in seg if ch in (ZW_ZERO, ZW_ONE))
        usable_len = (len(bits) // 8) * 8
        if usable_len < 8:
            continue

        byte_arr = bytearray(int(bits[i:i+8], 2) for i in range(0, usable_len, 8))
        checksum_ok = False
        if len(byte_arr) >= 2:
            expected_crc = compute_checksum(bytes(byte_arr[:-1]))
            if expected_crc == byte_arr[-1]:
                checksum_ok = True
                byte_arr = byte_arr[:-1]

        try:
            author_str = byte_arr.decode('utf-8', errors='ignore')
            if author_str:
                recovered_authors.append((author_str, checksum_ok))
        except Exception:
            continue

    if not recovered_authors:
        return {"detected": True, "author_id": "CORRUPTED_FRAME", "owner_email": None, "frames_recovered": 0}

    best_payload, crc_valid = recovered_authors[0]
    for cand, valid in recovered_authors:
        if valid:
            best_payload, crc_valid = cand, True
            break

    author_name, owner_email = parse_author_and_email(best_payload)

    return {
        "detected": True,
        "author_id": author_name,
        "owner_email": owner_email,
        "full_payload": best_payload,
        "checksum_verified": crc_valid,
        "frames_recovered": len(recovered_authors),
        "total_zw_chars": len(zw_stream)
    }


# Local Ollama report generation
def generate_gemma3_dmca_report(audit_result: dict, suspected_text: str, model: str = "gemma3:1b") -> str:
    """Calls local Ollama gemma3:1b to generate a legal DMCA & Forensic IP Report."""
    clean_snippet = strip_zero_width(suspected_text)[:500]
    owner_name = audit_result.get("author_id") or "UNKNOWN"
    owner_email = audit_result.get("owner_email") or "Unspecified"
    
    prompt = (
        f"You are a Forensic IP AI Auditor running on {model}. "
        f"A cryptographic zero-width watermark belonging to '{owner_name}' "
        f"(Verified Owner Email: {owner_email}, "
        f"Checksum Verified: {audit_result.get('checksum_verified')}, "
        f"Frames Recovered: {audit_result.get('frames_recovered')}) was detected in:\n"
        f"'''{clean_snippet}'''\n"
        f"Write a concise 3-bullet forensic infringement summary and a formal DMCA takedown notice."
    )
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    try:
        req = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            return json.loads(res.read().decode("utf-8")).get("response", "")
    except Exception as e:
        return (
            f"[Gemma 3 1B Offline Fallback Report]\n"
            f"Verified Owner Signature: {owner_name}\n"
            f"Verified Owner Email    : {owner_email}\n"
            f"Frames Recovered        : {audit_result.get('frames_recovered')} | Checksum: {audit_result.get('checksum_verified')}\n"
            f"Formal DMCA Demand      : Immediately purge stolen snippet '{clean_snippet[:80]}...' from AI training corpora."
        )


# Command-line interface
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ArmorCode Zero-Width IP Watermarking + Gemma 3 1B CLI")
    subparsers = parser.add_subparsers(dest="command")

    enc = subparsers.add_parser("encode", help="Apply invisible watermark to text")
    enc.add_argument("text", help="Input string to protect")
    enc.add_argument("--author", default=DEFAULT_AUTHOR_ID, help="Creator ID signature")
    enc.add_argument("--email", default=DEFAULT_OWNER_EMAIL, help="Owner email to bind to code")

    aud = subparsers.add_parser("audit", help="Detect watermark in suspected text")
    aud.add_argument("text", help="Suspected text to audit")
    aud.add_argument("--gemma-audit", action="store_true", help="Generate DMCA report with local Ollama gemma3:1b")

    args = parser.parse_args()
    if args.command == "encode":
        armored = watermark_text(args.text, args.author, owner_email=args.email)
        print("=== ARMORED OUTPUT (Copy below) ===")
        print(armored)
        print("===================================")
        print(f"[+] Verification Self-Test: {audit_text(armored)}")
    elif args.command == "audit":
        res = audit_text(args.text)
        print(res)
        if args.gemma_audit:
            print("\n=== GEMMA 3 1B FORENSIC DMCA REPORT ===")
            print(generate_gemma3_dmca_report(res, args.text))
    else:
        sample = "def proprietary_ai_kernel(x): return x * 42"
        protected = watermark_text(sample, DEFAULT_AUTHOR_ID, owner_email=DEFAULT_OWNER_EMAIL)
        audit_res = audit_text(protected)
        print(f"Original visible len : {len(sample)} chars")
        print(f"Protected total len  : {len(protected)} chars (Looks identical: '{protected}')")
        print(f"Forensic Audit Result: {audit_res}")
        print("\n--- Running Gemma 3 1B Forensic Auditor ---")
        print(generate_gemma3_dmca_report(audit_res, protected))
