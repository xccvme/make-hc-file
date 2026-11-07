"""Pembangun berkas .hc format modern (pembungkus a/b, build 645+).

Semua nilai ditulis dengan cara yang sama seperti aplikasi:

* kolom 0,7,10,11,12,22,24,26,29,30,31  -> record terautentikasi (FIELD_KEY)
* kolom 0,1,7,11,12,26                   -> dibungkus lagi dengan lapisan JKL
* kolom 7                                -> kredensial pasangan angka + braille
* kolom 24                               -> dua record dipisah "[splitPsiphon]"
"""

from __future__ import annotations

import os
from collections import OrderedDict

from . import core

_NOTE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default_note.html")


def default_note() -> str:
    """Catatan bawaan (hcmaker/default_note.html), dipakai bila catatan tidak diatur."""
    try:
        with open(_NOTE_PATH, encoding="utf-8") as stream:
            return stream.read()
    except OSError:
        return ""

from .codec import (
    ENCRYPTED_COLUMNS,
    JKL_COLUMNS,
    KEY_BUILD,
    KEY_MAIN,
    KEY_UV,
    HcConfig,
    Field,
)
from .core import FIELD_COUNT, HcError

BUILD_DEFAULT = "645"
VER_CFG_DEFAULT = "57"

# Kolom yang selalu disimpan sebagai record terautentikasi.
RECORD_COLUMNS = frozenset(ENCRYPTED_COLUMNS)
# Kolom 29-31 memakai record walau nilainya kosong.
ALWAYS_EMPTY_RECORDS = frozenset({29, 30, 31})

# Kunci 'a' dan nilai bawaan aplikasi (dari berkas keluaran build 645).
A_TEMPLATE = OrderedDict([
    ("yz", "false"),
    ("xy", None),        # diisi blob konfigurasi
    ("wx", "false"),
    ("vw", BUILD_DEFAULT),
    ("uv", None),        # pemisah acak 16 byte
    ("aa", "false"),
    ("cb", "false"),
    ("sr", "false"),
    ("ts", "false"),
    ("ut", "false"),
    ("wv", "64"),
    ("xw", "true"),
    ("yx", "1"),
    ("zy", "1"),
])

MODE_KONFIG = "no_lock"          # nama lain: lihat LOCK_MODES
LOCK_MODES = {
    "no_lock": (False, False, False),
    "lock_all": (True, False, False),
    "lock_payload_unlock_server": (False, True, False),
    "unlock_user_and_password": (False, False, True),
}

# Nilai bawaan tiap kolom pada berkas keluaran aplikasi.
DEFAULTS = {
    0: "",
    1: "",
    2: "false",     # block_root (blokir perangkat root)
    3: "false",     # lock_all
    4: "lifeTime",  # masa berlaku
    5: "false",     # ada catatan?
    6: "",          # catatan (HTML)
    7: "",          # akun SSH  host:port@user:pass
    8: "false",     # hanya data seluler
    9: "false",     # buka remote proxy
    10: "",         # config OpenVPN
    11: ":",        # kredensial OpenVPN user:pass
    12: "",         # TLS SNI
    13: "true",     # konek lewat SSH (mode payload/SSL)
    14: "",         # port udpgw
    15: "false",    # lock_payload
    16: "false",    # pakai HWID?
    17: "",         # daftar HWID
    18: "",         # nama config
    19: "false",    # buka user & password
    20: "0",        # mode koneksi
    21: "false",    # aktifkan password
    22: "",         # password
    23: "false",
    24: "[splitPsiphon][splitPsiphon]",
    25: "false",    # V2Ray aktif
    26: "",         # JSON V2Ray
    27: BUILD_DEFAULT,
    28: "false",    # SlowDNS aktif
    29: "",         # SlowDNS server
    30: "",         # SlowDNS public key
    31: "",         # DNS resolver
}


def empty_config(*, build: str = BUILD_DEFAULT, ver_cfg: str = VER_CFG_DEFAULT) -> HcConfig:
    fields = []
    for i in range(FIELD_COUNT):
        f = Field(index=i, mode="plain", plain=DEFAULTS.get(i, ""))
        f.value = f.plain
        fields.append(f)
    a_plain = OrderedDict()
    for key, value in A_TEMPLATE.items():
        if key in (KEY_MAIN, KEY_UV):
            continue
        a_plain[key] = build if key == KEY_BUILD else value
    return HcConfig(
        fields=fields,
        a_plain=a_plain,
        a_order=list(A_TEMPLATE.keys()),
        top_order=["a", "b"],
        pretty=True,
        b_plain=VER_CFG_DEFAULT,
        build=build,
        source="<dibuat>",
    )


def set_field(cfg: HcConfig, index: int, value: str) -> None:
    f = cfg.fields[index]
    f.value = value
    f.plain = value
    f.sub_plains = [value]
    f.jkl = False
    f.cred = None


def _finish(cfg: HcConfig) -> HcConfig:
    """Terapkan aturan penyimpanan aplikasi pada seluruh kolom."""
    for f in cfg.fields:
        i = f.index
        if i == 24:
            parts = f.sub_plains or [f.plain or ""]
            f.mode = "record2" if len(parts) > 1 else "record"
            f.sub_plains = parts
            f.plain = "".join(parts)
            f.value = f.plain
            continue

        if i in RECORD_COLUMNS:
            f.mode = "record"
            f.plain = f.value
        else:
            f.mode = "plain"
            f.plain = f.value

        if i in JKL_COLUMNS and f.plain:
            if i == 7:
                f.plain = core.jkl_encode(core.cred_encode_full(f.plain, True))
            else:
                f.plain = core.jkl_encode(f.plain)

        # kolom teks polos yang isinya menyerupai record harus disegel,
        # supaya parser aplikasi tidak salah mendekode.
        if f.mode == "plain" and core.is_record_token(f.plain):
            f.mode = "record"

    cfg.build = cfg.a_plain.get(KEY_BUILD, cfg.build) or cfg.build
    set_field(cfg, 27, str(cfg.build) if cfg.build else DEFAULTS[27])
    if cfg.build:
        cfg.a_plain[KEY_BUILD] = str(cfg.build)
    return cfg


def apply_lock(cfg: HcConfig, mode: str) -> None:
    if mode not in LOCK_MODES:
        raise HcError(
            "mode lock harus salah satu dari: " + ", ".join(LOCK_MODES)
        )
    lock_all, lock_payload, unlock_up = LOCK_MODES[mode]
    set_field(cfg, 3, "true" if lock_all else "false")
    set_field(cfg, 15, "true" if lock_payload else "false")
    set_field(cfg, 19, "true" if unlock_up else "false")


def build(
    *,
    nama: str = "Config Tia",
    payload: str = "",
    remote_proxy: str = "",
    ssh: str = "",
    sni: str = "",
    mode_koneksi: str = "0",
    masa_berlaku: str = "lifeTime",
    catatan: str | None = None,
    lock: str = "no_lock",
    unlock_remote_proxy: bool = False,
    block_root: bool = False,
    hanya_data_seluler: bool = False,
    hwid: str = "",
    password: str = "",
    openvpn_config: str = "",
    openvpn_kredensial: str = ":",
    v2ray_json: str = "",
    psiphon: object = ("[splitPsiphon]", "[splitPsiphon]"),
    slowdns_server: str = "",
    slowdns_public_key: str = "",
    dns_resolver: str = "",
    update_url: str = "",
    build_target: str = BUILD_DEFAULT,
    ver_cfg: str = VER_CFG_DEFAULT,
    extra: dict | None = None,
) -> HcConfig:
    """Rakit HcConfig baru sesuai struktur keluaran aplikasi."""
    if catatan is None:  # tidak diatur -> pakai catatan bawaan; "" = tanpa catatan
        catatan = default_note()
    cfg = empty_config(build=build_target, ver_cfg=ver_cfg)
    cfg.b_plain = ver_cfg

    values = {
        0: payload,
        1: remote_proxy,
        2: "true" if block_root else "false",
        4: masa_berlaku,
        5: "true" if catatan else "false",
        6: catatan,
        7: ssh,
        8: "true" if hanya_data_seluler else "false",
        9: "true" if unlock_remote_proxy else "false",
        10: openvpn_config,
        11: openvpn_kredensial,
        12: sni,
        13: "true",
        14: "",
        16: "true" if hwid else "false",
        17: hwid,
        18: nama,
        20: mode_koneksi,
        21: "true" if password else "false",
        22: password,
        24: "",  # ditangani terpisah (psiphon punya dua record)
        25: "true" if v2ray_json else "false",
        26: v2ray_json,
        28: "true" if slowdns_server else "false",
        29: slowdns_server,
        30: slowdns_public_key,
        31: dns_resolver,
    }
    for index, value in values.items():
        set_field(cfg, index, value)

    parts = list(psiphon) if isinstance(psiphon, (list, tuple)) else [str(psiphon)]
    f24 = cfg.fields[24]
    f24.sub_plains = parts
    f24.plain = "".join(parts)
    f24.value = f24.plain

    apply_lock(cfg, lock)

    if update_url:
        cfg.top_order = ["a", "b", "c"]
        cfg.top_extra = OrderedDict([("c", core.seal_hex(core.FIELD_KEY, update_url.encode("utf-8")))])
    if extra:
        for key, value in extra.items():
            if isinstance(key, int):
                set_field(cfg, key, value)
            else:
                cfg.a_plain[key] = value
                if key not in cfg.a_order:
                    cfg.a_order.append(key)

    cfg.uv_plain = os.urandom(16).hex()
    return _finish(cfg)


def clone_options(cfg: HcConfig, template: HcConfig) -> HcConfig:
    """Warisi seluruh opsi 'a' + kolom di luar isi koneksi dari template."""
    cfg.a_plain = OrderedDict(template.a_plain)
    cfg.a_order = list(template.a_order)
    cfg.top_order = list(template.top_order)
    cfg.top_extra = OrderedDict(template.top_extra)
    cfg.pretty = template.pretty
    cfg.b_plain = template.b_plain
    for index in (2, 3, 4, 8, 9, 13, 15, 16, 17, 19, 21, 23, 25, 28, 29, 30, 31):
        set_field(cfg, index, template.fields[index].value)
    set_field(cfg, 24, template.fields[24].value)
    return _finish(cfg)


# --------------------------------------------------------------------------
# Varian lama (verCfg 54) — untuk aplikasi versi lama yang belum mengenal
# pembungkus a/b. Struktur mengikuti berkas keluaran verApp 464.
# --------------------------------------------------------------------------
LEGACY_RECORD_COLUMNS = frozenset({0, 7, 10, 11, 12, 26})
LEGACY_CFG_KEYS = ["content", "isLoginHwid", "verApp", "a", "c"]


def build_legacy(**kwargs):
    """Rakit konfigurasi format lama (verCfg 54)."""
    from . import legacy

    kwargs.setdefault("ver_cfg", 54)
    kwargs.setdefault("build_target", "464")   # sama seperti berkas verCfg 54 asli
    cfg = build(**kwargs)
    legacy_cfg = legacy.LegacyConfig(
        fields=cfg.fields,
        cfg_plain=OrderedDict([
            ("isLoginHwid", False),
            ("verApp", int(cfg.build) if str(cfg.build).isdigit() else 464),
            ("a", False),
            ("c", False),
        ]),
        ver_cfg=54,
        pretty=True,
        cfg_order=list(LEGACY_CFG_KEYS),
        top_order=["cfg", "verCfg"],
    )
    legacy_cfg.key_index = []
    for f in legacy_cfg.fields:
        if f.index in legacy.SIDE_COLUMNS:
            f.mode = "record"
            legacy_cfg.key_index.append(legacy.SIDE_KEY_DEFAULT)
        elif f.index in LEGACY_RECORD_COLUMNS:
            f.mode = "record"
            legacy_cfg.key_index.append(legacy.FIELD_KEY_DEFAULT)
        elif f.index == 24:
            f.mode = "plain"
            legacy_cfg.key_index.append(-1)
        else:
            f.mode = "plain"
            legacy_cfg.key_index.append(-1)
    # kolom 22 pada format lama disimpan sebagai record kosong
    f22 = legacy_cfg.fields[22]
    if not f22.value:
        f22.mode = "record"
        legacy_cfg.key_index[22] = legacy.FIELD_KEY_DEFAULT
        f22.plain = ""
    else:
        f22.mode = "plain"
        legacy_cfg.key_index[22] = -1
    legacy_cfg.content_key = legacy.CONTENT_KEY_DEFAULT
    return legacy_cfg
