"""Format lama HTTP Custom: pembungkus {"cfg": {...}, "verCfg": N}.

Pada format ini 32 kolom yang sama disimpan sebagai satu teks yang dipisah
literal ``[splitConfig]`` lalu disegel dengan kunci konten. Kolom tertentu
disimpan sebagai record terautentikasi terpisah (kunci field), sisanya teks
polos. Terverifikasi kompatibel untuk verCfg 51 / 54 / 57 (verApp 331-645).
"""

from __future__ import annotations

import json
import os
from collections import OrderedDict
from dataclasses import dataclass, field as dc_field

from . import core
from .core import FIELD_COUNT, HcError, OUTER_KEY
from . import codec as codec_mod
from .codec import CRED_COLUMNS, Field

SPLIT = "[splitConfig]"

# Kunci konten & field per era. Semua diambil dari tabel kunci libsysNative.so
# ditambah kunci field format modern.
KEY_TABLE = [
    bytes.fromhex("2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d"),
    bytes.fromhex("3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372"),
    bytes.fromhex("cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3"),
    bytes.fromhex("4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193"),
    bytes.fromhex("f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63"),
    bytes.fromhex("81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c"),
    bytes.fromhex("45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944"),
    core.FIELD_KEY,
]
CONTENT_KEY_DEFAULT = 0      # key#0 (2be43429…) — dipakai verCfg 54
FIELD_KEY_DEFAULT = 2        # key#2 (cea9305c…)
SIDE_KEY_DEFAULT = 3         # key#3 (4beeace0…) — kolom 29-31
SIDE_COLUMNS = frozenset({29, 30, 31})


@dataclass
class LegacyConfig:
    fields: list[Field]
    cfg_plain: dict = dc_field(default_factory=OrderedDict)
    ver_cfg: object = 57
    key_index: list[int] = dc_field(default_factory=list)
    content_key: int = 0
    pretty: bool = False
    trailing: bytes = b""
    cfg_order: list = dc_field(default_factory=list)
    top_order: list = dc_field(default_factory=list)
    source: str = "<dibuat>"

    @property
    def build(self):
        return str(self.cfg_plain.get("verApp", ""))

    def get(self, index: int) -> str:
        return self.fields[index].value

    def set(self, index: int, value: str) -> None:
        f = self.fields[index]
        f.value = value
        f.jkl = False
        f.cred = None
        f.plain = value
        f.sub_plains = []


def _try_open(blob: bytes, key: bytes) -> bytes | None:
    try:
        return core.open_sealed(key, blob)
    except Exception:
        return None


def looks_like_legacy(raw: bytes) -> bool:
    try:
        text = core.open_hex(OUTER_KEY, core.unwrap_outer(raw)[0], "pembungkus")
        obj = json.loads(text.decode("utf-8"))
    except Exception:
        return False
    return isinstance(obj, dict) and "cfg" in obj and "verCfg" in obj


def decode_bytes(raw: bytes, *, source: str = "<bytes>") -> LegacyConfig:
    outer_hex, trailing = core.unwrap_outer(raw)
    envelope_text = core.open_hex(OUTER_KEY, outer_hex, "pembungkus")
    try:
        envelope = json.loads(envelope_text.decode("utf-8"), object_pairs_hook=OrderedDict)
    except ValueError as exc:
        raise HcError("pembungkus format lama bukan JSON valid") from exc
    cfg_plain = envelope.get("cfg")
    if not isinstance(cfg_plain, dict) or "content" not in cfg_plain:
        raise HcError("bukan pembungkus cfg/content")

    content_blob = bytes.fromhex(cfg_plain["content"])
    joined = None
    content_key = None
    for ki, key in enumerate(KEY_TABLE):
        plain = _try_open(content_blob, key)
        if plain is None:
            continue
        try:
            text = plain.decode("utf-8")
        except UnicodeError:
            continue
        if SPLIT in text:
            joined, content_key = text, ki
            break
    if joined is None:
        raise HcError("kunci konten format lama tidak ditemukan di tabel")

    tokens = joined.split(SPLIT)
    if len(tokens) != FIELD_COUNT:
        raise HcError(f"jumlah kolom {len(tokens)}, diharapkan {FIELD_COUNT}")

    fields: list[Field] = []
    key_index: list[int] = []
    for index, token in enumerate(tokens):
        f = Field(index=index)
        chosen = -1
        if core.is_record_token(token):
            blob = bytes.fromhex(token)
            for ki, key in enumerate(KEY_TABLE):
                plain = _try_open(blob, key)
                if plain is None:
                    continue
                try:
                    f.plain = plain.decode("utf-8")
                except UnicodeError:
                    continue
                chosen = ki
                break
        if chosen < 0:
            f.mode = "plain"
            f.plain = token
        else:
            f.mode = "record"
        key_index.append(chosen)
        value, f.jkl = core.jkl_decode(f.plain)
        cred_kind = CRED_COLUMNS.get(index)
        if cred_kind:
            value, changed = core.cred_decode(value, cred_kind == "ssh")
            if changed:
                f.cred = cred_kind
        f.value = value
        fields.append(f)

    cfg_body = OrderedDict((k, v) for k, v in cfg_plain.items() if k != "content")
    return LegacyConfig(
        cfg_order=list(cfg_plain.keys()),
        top_order=list(envelope.keys()),
        fields=fields,
        cfg_plain=cfg_body,
        ver_cfg=envelope.get("verCfg", 57),
        key_index=key_index,
        content_key=content_key,
        trailing=trailing,
        pretty=codec_mod.detect_pretty(envelope_text.decode("utf-8")),
        source=source,
    )


def decode_file(path) -> LegacyConfig:
    with open(path, "rb") as stream:
        return decode_bytes(stream.read(), source=os.path.basename(str(path)))


def encode_config(cfg: LegacyConfig) -> bytes:
    tokens = []
    for f in cfg.fields:
        if f.mode == "record":
            ki = cfg.key_index[f.index] if f.index < len(cfg.key_index) else -1
            if ki < 0:
                ki = SIDE_KEY_DEFAULT if f.index in SIDE_COLUMNS else FIELD_KEY_DEFAULT
            tokens.append(core.seal_hex(KEY_TABLE[ki], f.plain.encode("utf-8")))
        else:
            tokens.append(f.plain)
    joined = SPLIT.join(tokens)

    content_hex = core.seal_hex(KEY_TABLE[cfg.content_key], joined.encode("utf-8"))
    body = OrderedDict()
    for k in cfg.cfg_order or (["content"] + list(cfg.cfg_plain.keys())):
        body[k] = content_hex if k == "content" else cfg.cfg_plain[k]
    parts = {"cfg": body, "verCfg": cfg.ver_cfg}
    envelope = OrderedDict((k, parts[k]) for k in (cfg.top_order or ["cfg", "verCfg"]))
    text = codec_mod._dump_json(envelope, cfg.pretty)
    return core.wrap_outer(
        core.seal_hex(OUTER_KEY, text.encode("utf-8")), getattr(cfg, "trailing", b"")
    )


def write_file(cfg: LegacyConfig, path) -> None:
    with open(path, "wb") as stream:
        stream.write(encode_config(cfg))
