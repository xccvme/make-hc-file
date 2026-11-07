"""Primitif kripto & encoding untuk format .hc HTTP Custom.

Diturunkan dari pipeline yang teramati pada berkas .hc asli:

    berkas (UTF-8)
      -> decode utf-8, encode latin-1      => byte "latin"
      -> XOR berulang dengan OUTER_XOR     => teks heksadesimal
      -> ChaCha20 (nonce 8 byte) + Poly1305 (tag 16 byte) => JSON pembungkus

Perhatikan: MAC memakai layout *original* Poly1305 (bukan RFC 8439).
Pesan yang diautentikasi = LE64(0) || ciphertext || LE64(len(ciphertext)),
tanpa padding, dan AAD kosong. Kunci sekali pakai Poly1305 = 32 byte pertama
keystream ChaCha20; payload dienkripsi mulai offset keystream 64 byte.
"""

from __future__ import annotations

import base64
import binascii
import re
import struct

from Crypto.Cipher import ChaCha20
from cryptography.hazmat.primitives.poly1305 import Poly1305

# --------------------------------------------------------------------------
# Konstanta profil format (nilai format aplikasi, bukan kredensial akun)
# --------------------------------------------------------------------------
FIELD_COUNT = 32
NONCE = b"\xdb" * 8

OUTER_XOR = bytes.fromhex("e382e4b8adc386f09f9293")
OUTER_KEY = bytes.fromhex(
    "81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"
)
MAIN_KEY = bytes.fromhex(
    "3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"
)
FIELD_KEY = bytes.fromhex(
    "3d632a251c9820f2baf83e15498d27548fc67921cb437f8ce48505989378adea"
)
JKL_XOR = bytes.fromhex("d5d4d3d2d1d0cfcecdccbdbcbbbab9b8b7b6b5b4")

# Nama field di pembungkus JSON
KEY_MAIN = "xy"   # blob konfigurasi utama (32 kolom)
KEY_UV = "uv"     # pemisah; ciphertext heksanya dipakai sebagai delimiter
KEY_BUILD = "vw"  # build aplikasi saat berkas dibuat


class HcError(Exception):
    """Kesalahan umum format .hc."""


class AuthenticationError(HcError):
    """Tag Poly1305 tidak cocok."""


# --------------------------------------------------------------------------
# ChaCha20 + Poly1305 (layout original, nonce 64-bit)
# --------------------------------------------------------------------------
def _keystream(key: bytes, nonce: bytes, nbytes: int, offset: int = 0) -> bytes:
    cipher = ChaCha20.new(key=key, nonce=nonce)
    if offset:
        cipher.seek(offset)
    return cipher.encrypt(bytes(nbytes))


def seal(key: bytes, data: bytes) -> bytes:
    """Kembalikan ciphertext||tag16 (layout MAC original, AAD kosong)."""
    one_time_key = _keystream(key, NONCE, 32, 0)
    cipher = ChaCha20.new(key=key, nonce=NONCE)
    cipher.seek(64)
    ciphertext = cipher.encrypt(data)
    authenticated = bytes(8) + ciphertext + struct.pack("<Q", len(ciphertext))
    tag = Poly1305.generate_tag(one_time_key, authenticated)
    return ciphertext + tag


def open_sealed(key: bytes, blob: bytes) -> bytes:
    if len(blob) < 16:
        raise HcError("record terlalu pendek")
    ciphertext, tag = blob[:-16], blob[-16:]
    one_time_key = _keystream(key, NONCE, 32, 0)
    authenticated = bytes(8) + ciphertext + struct.pack("<Q", len(ciphertext))
    try:
        Poly1305.verify_tag(one_time_key, authenticated, tag)
    except Exception as exc:  # cryptography.InvalidSignature
        raise AuthenticationError("tag Poly1305 tidak valid") from exc
    cipher = ChaCha20.new(key=key, nonce=NONCE)
    cipher.seek(64)
    return cipher.encrypt(ciphertext)


def seal_hex(key: bytes, data: bytes) -> str:
    return seal(key, data).hex()


def open_hex(key: bytes, value: str, label: str = "record") -> bytes:
    if not isinstance(value, str) or len(value) < 32 or len(value) % 2:
        raise HcError(f"{label}: record heksadesimal tidak lengkap")
    if re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        raise HcError(f"{label}: record bukan heksadesimal")
    return open_sealed(key, bytes.fromhex(value))


def is_record_token(token: str) -> bool:
    """Aturan parser aplikasi: token dianggap record bila >=32 char heks genap."""
    return (
        isinstance(token, str)
        and len(token) >= 32
        and len(token) % 2 == 0
        and re.fullmatch(r"[0-9a-fA-F]+", token) is not None
    )


# --------------------------------------------------------------------------
# Lapisan teks terluar
# --------------------------------------------------------------------------
def unwrap_outer(raw: bytes):
    """berkas -> (teks heksadesimal lapisan luar, byte ekor yang tak terpakai).

    Sebagian berkas diakhiri baris baru / spasi yang bukan bagian data; byte
    tersebut dikembalikan agar bisa ditulis ulang persis sama.
    """
    try:
        latin = raw.decode("utf-8").encode("latin1")
    except UnicodeError as exc:
        raise HcError("berkas tidak lolos lapisan UTF-8/latin-1") from exc

    def attempt(blob: bytes):
        out = bytes(v ^ OUTER_XOR[i % len(OUTER_XOR)] for i, v in enumerate(blob))
        try:
            text = out.decode("ascii")
        except UnicodeError:
            return None
        return text if re.fullmatch(r"[0-9a-fA-F]*", text) is not None else None

    for cut in range(0, 9):
        body = latin[: len(latin) - cut] if cut else latin
        text = attempt(body)
        if text is None:
            continue
        stripped = latin[len(latin) - cut:] if cut else b""
        trailing = b"".join(chr(b).encode("utf-8") for b in stripped)
        return text, trailing
    raise HcError("lapisan luar bukan teks heksadesimal")


def wrap_outer(hex_text: str, trailing: bytes = b"") -> bytes:
    """teks heksadesimal lapisan luar -> byte berkas."""
    ascii_bytes = hex_text.encode("ascii")
    latin = bytes(
        v ^ OUTER_XOR[i % len(OUTER_XOR)] for i, v in enumerate(ascii_bytes)
    )
    return latin.decode("latin1").encode("utf-8") + trailing


# --------------------------------------------------------------------------
# Representasi JKL (base64 -> XOR -> base64)
# --------------------------------------------------------------------------
def jkl_encode(text: str) -> str:
    first = base64.b64encode(text.encode("utf-8"))
    middle = bytes(v ^ JKL_XOR[i % len(JKL_XOR)] for i, v in enumerate(first))
    return base64.b64encode(middle).decode("ascii")


def _b64(value) -> bytes:
    if isinstance(value, bytes):
        value = value.decode("ascii")
    value = re.sub(r"\s", "", value)
    if not value or re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value) is None:
        raise ValueError("bukan base64")
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)


def _looks_like_text(value: str) -> bool:
    return bool(value) and sum(
        c.isprintable() or c in "\r\n\t" for c in value
    ) >= 0.95 * len(value)


def jkl_decode(value: str) -> tuple[str, bool]:
    """Hanya ganti nilai bila kedua lapis base64 menghasilkan UTF-8 terbaca."""
    try:
        first = _b64(value)
        middle = bytes(
            v ^ JKL_XOR[i % len(JKL_XOR)] for i, v in enumerate(first)
        )
        result = _b64(middle).decode("utf-8")
        if _looks_like_text(result):
            return result, True
    except (ValueError, UnicodeError, binascii.Error):
        pass
    return value, False


# --------------------------------------------------------------------------
# Representasi kredensial (braille nibble + pasangan angka)
# --------------------------------------------------------------------------
BRAILLE = "⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚⠅⠇⠍⠝⠕⠏"


def braille_encode(data: bytes) -> str:
    return "".join(BRAILLE[b >> 4] + BRAILLE[b & 0x0F] for b in data)


def braille_decode(value: str) -> bytes | None:
    try:
        return bytes(
            BRAILLE.index(value[i]) * 16 + BRAILLE.index(value[i + 1])
            for i in range(0, len(value), 2)
        )
    except (ValueError, IndexError):
        return None


def _number_pair_decode(part: str, size: int) -> str | None:
    pairs = re.findall(r"(-?\d+)\.(-?\d+)", part)
    if not pairs or not all(0 <= int(b) - size <= 63 for _, b in pairs):
        return None
    try:
        result = bytes(
            ((int(a) - size) // (1 << (int(b) - size))) % 256 for a, b in pairs
        ).decode("utf-8")
    except (UnicodeError, ValueError, OverflowError):
        return None
    return result if _looks_like_text(result) else None


def cred_decode(value: str, ssh: bool) -> tuple[str, bool]:
    """Kembalikan (nilai, apakah berubah)."""
    original = value
    if ssh and value and value[0] in BRAILLE:
        raw = braille_decode(value)
        if raw is not None:
            try:
                value = raw.decode("utf-8")
            except UnicodeError:
                return original, False
    pattern = r"^(.+):([\d-]+)@(.+):(.+)$" if ssh else r"^([^:]+):(.+)$"
    match = re.fullmatch(pattern, value)
    if match:
        parts = list(match.groups())
        size = None
        for i in (-2, -1):
            found = re.findall(r"(-?\d+)\.(-?\d+)", parts[i])
            if not found:
                continue
            size = size if size is not None else len(found)
            decoded = _number_pair_decode(parts[i], len(found))
            if decoded is not None:
                parts[i] = decoded
        value = (
            f"{parts[0]}:{parts[1]}@{parts[2]}:{parts[3]}"
            if ssh
            else ":".join(parts)
        )
    return value, value != original


def cred_encode(value: str, ssh: bool) -> str:
    """Kebalikan: kredensial polos -> representasi pasangan angka.

    Tiap byte `b` pada bagian yang dikodekan ditulis sebagai "a.b" dengan
    `a = b + size` dan `size` = jumlah byte bagian tersebut; pasangan dipisah
    koma. Terverifikasi cocok dengan berkas keluaran aplikasi (kolom 7).
    """
    pattern = r"^(.+):([\d-]+)@(.+):(.+)$" if ssh else r"^([^:]+):(.+)$"
    match = re.fullmatch(pattern, value)
    if not match:
        return value
    parts = list(match.groups())
    for i in (-2, -1):
        raw = parts[i].encode("utf-8")
        size = len(raw)
        parts[i] = ",".join(f"{b + size}.{size}" for b in raw)
    return (
        f"{parts[0]}:{parts[1]}@{parts[2]}:{parts[3]}" if ssh else ":".join(parts)
    )


def cred_encode_full(value: str, ssh: bool) -> str:
    """Rantai penuh yang dipakai aplikasi: pasangan angka -> braille."""
    return braille_encode(cred_encode(value, ssh).encode("utf-8"))
