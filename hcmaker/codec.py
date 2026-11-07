"""Decoder/encoder berkas .hc HTTP Custom (format pembungkus a/b, 32 kolom)."""

from __future__ import annotations

import json
import os
import re
from collections import OrderedDict
from dataclasses import dataclass, field as dc_field

from . import core
from .core import (
    FIELD_KEY,
    FIELD_COUNT,
    KEY_BUILD,
    KEY_MAIN,
    KEY_UV,
    MAIN_KEY,
    OUTER_KEY,
    HcError,
)

# --------------------------------------------------------------------------
# Peta kolom (indeks -> label). Dipakai untuk tampilan & pembuatan berkas.
# --------------------------------------------------------------------------
LABELS = {
    0: "payload_http",
    1: "remote_proxy",
    2: "flag_02",
    3: "flag_03",
    4: "masa_berlaku",
    5: "catatan_aktif",
    6: "catatan_html",
    7: "akun_ssh",
    8: "flag_08",
    9: "flag_09",
    10: "config_openvpn",
    11: "kredensial_openvpn",
    12: "tls_sni",
    13: "flag_13",
    14: "mode_14",
    15: "mode_15",
    16: "mode_16",
    17: "mode_17",
    18: "nama_config",
    19: "flag_19",
    20: "mode_koneksi",
    21: "flag_21",
    22: "data_22",
    23: "flag_23",
    24: "psiphon",
    25: "v2ray_aktif",
    26: "v2ray_config",
    27: "versi_config",
    28: "slowdns_aktif",
    29: "slowdns_server",
    30: "slowdns_public_key",
    31: "dns_resolver",
}

# Kolom yang pada berkas contoh disimpan sebagai record terautentikasi
# (terenkripsi dengan FIELD_KEY) alih-alih teks polos.
ENCRYPTED_COLUMNS = frozenset({0, 7, 10, 11, 12, 22, 24, 26, 29, 30, 31})
# Kolom yang nilainya dibungkus lagi dengan representasi JKL.
JKL_COLUMNS = frozenset({0, 1, 7, 11, 12})
CRED_COLUMNS = {7: "ssh", 11: "lain"}


@dataclass
class Field:
    index: int
    mode: str = "plain"          # plain | record | record2
    plain: str = ""              # teks terautentikasi (sebelum JKL/kredensial)
    sub_plains: list[str] = dc_field(default_factory=list)  # untuk record2
    value: str = ""              # nilai setelah semua lapisan dibuka
    jkl: bool = False
    cred: str | None = None

    @property
    def label(self) -> str:
        return LABELS.get(self.index, f"kolom_{self.index:02d}")

    def token(self) -> str:
        if self.mode == "plain":
            return self.plain
        if self.mode == "record":
            return core.seal_hex(FIELD_KEY, self.plain.encode("utf-8"))
        if self.mode == "record2":
            parts = self.sub_plains or [self.plain]
            return "".join(
                core.seal_hex(FIELD_KEY, p.encode("utf-8")) for p in parts
            )
        raise HcError(f"mode kolom tidak dikenal: {self.mode}")


@dataclass
class HcConfig:
    fields: list[Field]
    uv_plain: str = ""
    b_plain: str = ""
    a_plain: dict = dc_field(default_factory=OrderedDict)  # mis. {"uv":..,"vw":..}
    a_order: list[str] = dc_field(default_factory=list)
    top_order: list[str] = dc_field(default_factory=list)
    top_extra: dict = dc_field(default_factory=OrderedDict)
    trailing: bytes = b""
    pretty: bool = False
    builder_order: list[str] = dc_field(default_factory=list)
    source: str = "<dibuat>"
    build: str = ""

    def get(self, index: int) -> str:
        return self.fields[index].value

    def set(self, index: int, value: str) -> None:
        """Set nilai publik; lapisan JKL/kredensial dilepas (disimpan polos)."""
        f = self.fields[index]
        f.value = value
        f.jkl = False
        f.cred = None
        if f.mode == "record2":
            f.sub_plains = [value]
            f.plain = value
        else:
            f.plain = value


def set_value(cfg: "HcConfig", index: int, value: str) -> None:
    """Ubah nilai satu kolom sambil mengikuti kebiasaan penyimpanan aplikasi.

    Hanya kolom 7 (akun SSH) dan 11 (kredensial OpenVPN) yang secara konsisten
    dibungkus lapisan JKL/braille pada berkas nyata; kolom lain menyimpan
    teks apa adanya di dalam record.
    """
    f = cfg.fields[index]
    f.value = value
    if index == 7 and value:
        f.plain = core.jkl_encode(core.cred_encode_full(value, True))
    elif index == 11 and value:
        f.plain = core.jkl_encode(value)
    else:
        f.plain = value
    if f.mode == "record2":
        f.sub_plains = [value]
        f.plain = value
    elif f.mode == "plain" and core.is_record_token(f.plain):
        f.mode = "record"


def _dump_json(obj, pretty: bool) -> str:
    if pretty:
        return json.dumps(obj, indent=2, ensure_ascii=False)
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def detect_pretty(text: str) -> bool:
    return "\n" in text and '"' in text


# --------------------------------------------------------------------------
# Decode
# --------------------------------------------------------------------------
def decode_bytes(raw: bytes, *, source: str = "<bytes>") -> HcConfig:
    if not raw:
        raise HcError("berkas kosong")
    outer_hex, trailing = core.unwrap_outer(raw)
    envelope_text = core.open_hex(OUTER_KEY, outer_hex, "pembungkus").decode("utf-8")
    try:
        envelope = json.loads(envelope_text, object_pairs_hook=OrderedDict)
    except ValueError as exc:
        raise HcError("pembungkus bukan JSON valid") from exc
    if not isinstance(envelope.get("a"), dict) or "b" not in envelope:
        raise HcError("bukan pembungkus format a/b")
    a = envelope["a"]
    if KEY_MAIN not in a or KEY_UV not in a:
        raise HcError("kunci xy/uv tidak ada di dalam 'a'")

    a_plain: dict = OrderedDict()
    for key, value in a.items():
        if key == KEY_MAIN:
            continue
        a_plain[key] = core.open_hex(FIELD_KEY, value, f"a.{key}").decode("utf-8")
    b_plain = core.open_hex(FIELD_KEY, envelope["b"], "b").decode("utf-8")
    top_extra = OrderedDict(
        (k, v) for k, v in envelope.items() if k not in ("a", "b")
    )

    uv_ct = a[KEY_UV]
    joined = core.open_hex(MAIN_KEY, a[KEY_MAIN], "konfigurasi").decode("utf-8")
    tokens = joined.split(uv_ct)
    if len(tokens) != FIELD_COUNT:
        raise HcError(
            f"jumlah kolom {len(tokens)}, diharapkan {FIELD_COUNT}"
        )

    fields: list[Field] = []
    for index, token in enumerate(tokens):
        f = Field(index=index)
        if index == 24 and len(token) == 120 and core.is_record_token(token):
            f.mode = "record2"
            f.sub_plains = [
                core.open_hex(FIELD_KEY, token[n : n + 60], f"kolom24[{n}]").decode(
                    "utf-8"
                )
                for n in (0, 60)
            ]
            f.plain = "".join(f.sub_plains)
        elif core.is_record_token(token):
            f.mode = "record"
            f.plain = core.open_hex(FIELD_KEY, token, f"kolom{index}").decode("utf-8")
        else:
            f.mode = "plain"
            f.plain = token

        value, f.jkl = core.jkl_decode(f.plain)
        cred_kind = CRED_COLUMNS.get(index)
        if cred_kind:
            new_value, changed = core.cred_decode(value, cred_kind == "ssh")
            if changed:
                f.cred = cred_kind
                value = new_value
        f.value = value
        fields.append(f)

    return HcConfig(
        fields=fields,
        uv_plain=a_plain.get(KEY_UV, ""),
        b_plain=b_plain,
        a_plain=a_plain,
        a_order=list(a.keys()),
        top_order=list(envelope.keys()),
        top_extra=top_extra,
        trailing=trailing,
        pretty=detect_pretty(envelope_text),
        source=source,
        build=a_plain.get(KEY_BUILD, ""),
    )


def decode_file(path) -> HcConfig:
    with open(path, "rb") as stream:
        return decode_bytes(stream.read(), source=os.path.basename(str(path)))


# --------------------------------------------------------------------------
# Encode
# --------------------------------------------------------------------------
def encode_config(cfg: HcConfig) -> bytes:
    uv_plain = cfg.uv_plain or os.urandom(16).hex()
    cfg.uv_plain = uv_plain
    uv_ct = core.seal_hex(FIELD_KEY, uv_plain.encode("utf-8"))

    tokens = [f.token() for f in cfg.fields]
    if len(tokens) != FIELD_COUNT:
        raise HcError(f"jumlah kolom {len(tokens)}, diharapkan {FIELD_COUNT}")
    joined = uv_ct.join(tokens)

    order = cfg.builder_order or cfg.a_order or [KEY_MAIN, KEY_UV, KEY_BUILD]
    a: OrderedDict = OrderedDict()
    for key in order:
        if key == KEY_MAIN:
            a[key] = core.seal_hex(MAIN_KEY, joined.encode("utf-8"))
        elif key == KEY_UV:
            a[key] = uv_ct
        elif key in cfg.a_plain:
            a[key] = core.seal_hex(FIELD_KEY, str(cfg.a_plain[key]).encode("utf-8"))
        else:
            raise HcError(f"kunci a.{key} tidak punya nilai")

    envelope: OrderedDict = OrderedDict()
    for key in cfg.top_order or ["a", "b"]:
        if key == "a":
            envelope["a"] = a
        elif key == "b":
            envelope["b"] = core.seal_hex(FIELD_KEY, cfg.b_plain.encode("utf-8"))
        elif key in cfg.top_extra:
            envelope[key] = cfg.top_extra[key]
    text = _dump_json(envelope, cfg.pretty)
    return core.wrap_outer(
        core.seal_hex(OUTER_KEY, text.encode("utf-8")), getattr(cfg, "trailing", b"")
    )


def write_file(cfg: HcConfig, path) -> None:
    with open(path, "wb") as stream:
        stream.write(encode_config(cfg))
