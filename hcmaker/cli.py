"""CLI hcmaker — baca, ubah, dan buat berkas .hc HTTP Custom."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import OrderedDict

from . import builder, codec, legacy
from .core import HcError

LOCK_HELP = " | ".join(builder.LOCK_MODES)


def _load(path):
    with open(path, "rb") as stream:
        return stream.read()


def _detect(raw: bytes):
    """Kembalikan modul & config yang cocok untuk berkas ini."""
    errors = []
    for name, mod in (("modern", codec), ("legacy", legacy)):
        try:
            return name, mod, mod.decode_bytes(raw)
        except HcError as exc:
            errors.append(f"{name}: {exc}")
    raise HcError("format tidak dikenali -> " + "; ".join(errors))


def _profile_dict(name: str, cfg) -> OrderedDict:
    out = OrderedDict()
    out["format"] = name
    if name == "modern":
        out["build"] = cfg.build
        out["ver_cfg"] = cfg.b_plain
    else:
        out["build"] = cfg.build
        out["ver_cfg"] = cfg.ver_cfg
    out["lock"] = {
        "lock_all": cfg.get(3) == "true",
        "lock_payload_unlock_server": cfg.get(15) == "true",
        "unlock_user_and_password": cfg.get(19) == "true",
        "unlock_remote_proxy": cfg.get(9) == "true",
    }
    out["kolom"] = [
        OrderedDict([
            ("index", f.index),
            ("label", codec.LABELS.get(f.index, f"kolom_{f.index:02d}")),
            ("nilai", f.value),
            ("penyimpanan", f.mode),
            ("jkl", f.jkl),
        ])
        for f in cfg.fields
    ]
    return out


def cmd_info(args):
    name, mod, cfg = _detect(_load(args.berkas))
    print(f"berkas      : {args.berkas} ({os.path.getsize(args.berkas)} byte)")
    print(f"format      : {name}")
    print(f"build       : {cfg.build}")
    print(f"nama config : {cfg.get(18)!r}")
    print(f"masa berlaku: {cfg.get(4)!r}")
    print(f"payload     : {cfg.get(0)[:90]!r}")
    print(f"ssh         : {cfg.get(7)[:90]!r}")
    print(f"sni         : {cfg.get(12)[:90]!r}")
    flags = {
        "lock_all (kolom 3)": cfg.get(3),
        "lock_payload (kolom 15)": cfg.get(15),
        "unlock_user_pass (kolom 19)": cfg.get(19),
        "unlock_proxy (kolom 9)": cfg.get(9),
        "block_root (kolom 2)": cfg.get(2),
        "hwid aktif (kolom 16)": cfg.get(16),
        "password aktif (kolom 21)": cfg.get(21),
    }
    print("flag:")
    for key, value in flags.items():
        print(f"  {key:32s} = {value}")
    return 0


def cmd_dump(args):
    name, mod, cfg = _detect(_load(args.berkas))
    data = _profile_dict(name, cfg)
    text = json.dumps(data, indent=2, ensure_ascii=False)
    if args.keluaran:
        with open(args.keluaran, "w", encoding="utf-8") as stream:
            stream.write(text + "\n")
        print(f"profil ditulis: {args.keluaran}")
    else:
        print(text)
    return 0


def cmd_build(args):
    with open(args.spec, encoding="utf-8") as stream:
        spec = json.load(stream)
    if args.format == "legacy":
        cfg = builder.build_legacy(**spec)
        legacy.write_file(cfg, args.keluaran)
    else:
        cfg = builder.build(**spec)
        codec.write_file(cfg, args.keluaran)
    size = os.path.getsize(args.keluaran)
    print(f"selesai: {args.keluaran} ({size} byte, format {args.format})")
    print(f"lock   : {spec.get('lock', 'no_lock')} (kolom 3={cfg.get(3)}, 15={cfg.get(15)}, 19={cfg.get(19)})")
    return 0


def cmd_reencode(args):
    name, mod, cfg = _detect(_load(args.berkas))
    mod.write_file(cfg, args.keluaran)
    print(f"ditulis ulang: {args.keluaran} (format {name})")
    return 0


def cmd_lock(args):
    name, mod, cfg = _detect(_load(args.berkas))
    if name != "modern":
        raise HcError("perubahan mode lock hanya didukung untuk format modern (a/b)")
    builder.apply_lock(cfg, args.mode)
    mod.write_file(cfg, args.keluaran or args.berkas)
    print(f"mode lock -> {args.mode}")
    print(f"tersimpan: {args.keluaran or args.berkas}")
    return 0


def cmd_set(args):
    name, mod, cfg = _detect(_load(args.berkas))
    for item in args.pasangan:
        if "=" not in item:
            raise HcError(f"format harus indeks=nilai, dapat: {item!r}")
        index, value = item.split("=", 1)
        if name == "modern":
            codec.set_value(cfg, int(index), value)
        else:
            cfg.set(int(index), value)
    mod.write_file(cfg, args.keluaran or args.berkas)
    print(f"tersimpan: {args.keluaran or args.berkas}")
    return 0


def cmd_test(args):
    from .selftest import run_all

    return 0 if run_all(verbose=args.verbose) else 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="hcmaker", description="Baca & buat berkas konfigurasi HTTP Custom (.hc)"
    )
    sub = parser.add_subparsers(dest="perintah", required=True)

    p = sub.add_parser("info", help="ringkasan isi berkas .hc")
    p.add_argument("berkas")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("dump", help="keluarkan seluruh kolom sebagai JSON")
    p.add_argument("berkas")
    p.add_argument("-o", "--keluaran")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("build", help="buat .hc baru dari spesifikasi JSON")
    p.add_argument("spec")
    p.add_argument("-o", "--keluaran", required=True)
    p.add_argument(
        "--format", choices=["modern", "legacy"], default="modern",
        help="modern = pembungkus a/b (build 645, seperti APK contoh); "
             "legacy = verCfg 54 (untuk aplikasi versi lama)",
    )
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("reencode", help="baca lalu tulis ulang berkas .hc")
    p.add_argument("berkas")
    p.add_argument("-o", "--keluaran", required=True)
    p.set_defaults(func=cmd_reencode)

    p = sub.add_parser("lock", help=f"ubah mode lock ({LOCK_HELP})")
    p.add_argument("berkas")
    p.add_argument("mode", choices=list(builder.LOCK_MODES))
    p.add_argument("-o", "--keluaran")
    p.set_defaults(func=cmd_lock)

    p = sub.add_parser("set", help="ubah kolom: set BERKAS 3=true 18=Nama")
    p.add_argument("berkas")
    p.add_argument("pasangan", nargs="+")
    p.add_argument("-o", "--keluaran")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("selftest", help="jalankan uji round-trip internal")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_test)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except HcError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: berkas tidak ditemukan ({exc.filename})", file=sys.stderr)
        return 2
