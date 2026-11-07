"""Uji mandiri: round-trip byte-identik + cek struktur berkas buatan."""

from __future__ import annotations

import glob
import os
import tempfile

from . import builder, codec, core, legacy

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
REFS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ref-hcdecode", "examples"
)


def _collect():
    paths = []
    for base in (SAMPLES_DIR, REFS_DIR):
        paths += sorted(glob.glob(os.path.join(base, "**", "*.hc"), recursive=True))
    return paths


def test_roundtrip(verbose: bool = False):
    ok = fail = 0
    paths = _collect()
    if not paths:
        print("round-trip: dilewati (folder samples/ tidak disertakan)")
        return True
    for path in paths:
        raw = open(path, "rb").read()
        for name, mod in (("modern", codec), ("legacy", legacy)):
            try:
                cfg = mod.decode_bytes(raw, source=os.path.basename(path))
                same = mod.encode_config(cfg) == raw
            except Exception as exc:  # noqa: BLE001
                if verbose:
                    print(f"  skip {os.path.basename(path)} [{name}] {type(exc).__name__}")
                continue
            if same:
                ok += 1
                if verbose:
                    print(f"  IDENTIK {os.path.basename(path)} [{name}]")
            else:
                fail += 1
                print(f"  BEDA    {os.path.basename(path)} [{name}]")
    print(f"round-trip: {ok} identik, {fail} beda")
    return fail == 0 and ok > 0


def test_credentials():
    """Rantai kredensial kolom 7 harus mereproduksi berkas asli."""
    path = os.path.join(REFS_DIR, "demo_ssh.hc")
    if not os.path.exists(path):
        print("kredensial: dilewati (sampel tidak ada)")
        return True
    cfg = codec.decode_file(path)
    f = cfg.fields[7]
    rebuilt = core.jkl_encode(core.cred_encode_full(f.value, True))
    good = rebuilt == f.plain
    print(f"kredensial kolom 7: {'OK' if good else 'GAGAL'}")
    return good


def test_build_all_locks():
    good = True
    for mode in builder.LOCK_MODES:
        cfg = builder.build(
            nama=f"Uji {mode}",
            payload="GET / HTTP/1.1[crlf]Host: [host][crlf][crlf]",
            ssh="sg.example.com:443@demo:rahasia",
            sni="sg.example.com",
            lock=mode,
        )
        blob = codec.encode_config(cfg)
        back = codec.decode_bytes(blob)
        lock_all, lock_payload, unlock_up = builder.LOCK_MODES[mode]
        expect = {
            3: "true" if lock_all else "false",
            15: "true" if lock_payload else "false",
            19: "true" if unlock_up else "false",
        }
        ok = all(back.get(i) == v for i, v in expect.items())
        ok = ok and back.get(0) == cfg.get(0) and back.get(7) == cfg.get(7)
        ok = ok and codec.encode_config(back) == blob
        print(f"build mode {mode:28s}: {'OK' if ok else 'GAGAL'}")
        good = good and ok
    return good


def test_build_matches_real_profile():
    """Struktur berkas buatan harus sama dengan profil terbanyak berkas nyata."""
    counts: dict[tuple, int] = {}
    modes: dict[tuple, int] = {}
    for path in _collect():
        try:
            cand = codec.decode_file(path)
        except Exception:  # noqa: BLE001
            continue
        counts[tuple(cand.a_order)] = counts.get(tuple(cand.a_order), 0) + 1
        key = tuple(f.mode for f in cand.fields)
        modes[key] = modes.get(key, 0) + 1
    if not counts:
        print("profil: dilewati (folder samples/ tidak disertakan)")
        return True
    common_keys = max(counts, key=counts.get)
    common_modes = max(modes, key=modes.get)
    mine = builder.build(nama="Profil", payload="x", ssh="a:22@b:c", sni="a")
    same_keys = tuple(mine.a_order) == common_keys
    modes_ok = tuple(f.mode for f in mine.fields) == common_modes
    print(
        f"profil a-keys terbanyak ({counts[common_keys]} berkas) sama: {same_keys} | "
        f"mode kolom sama: {modes_ok}"
    )
    if not same_keys:
        print(f"  umum : {list(common_keys)}")
        print(f"  milik: {list(mine.a_order)}")
    if not modes_ok:
        print(f"  mode umum : {list(common_modes)}")
        print(f"  mode milik: {[f.mode for f in mine.fields]}")
    return same_keys and modes_ok


def test_write_read(tmpdir=None):
    cfg = builder.build(
        nama="Tulis Baca",
        payload="CONNECT [host_port] [protocol][crlf][crlf]",
        ssh="1.2.3.4:443@user:pass",
        sni="1.2.3.4",
        lock="unlock_user_and_password",
        catatan="<p>catatan</p>",
        mode_koneksi="0",
    )
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "uji.hc")
        codec.write_file(cfg, path)
        back = codec.decode_file(path)
        ok = (
            back.get(18) == "Tulis Baca"
            and back.get(7) == "1.2.3.4:443@user:pass"
            and back.get(6) == "<p>catatan</p>"
            and back.get(4) == "lifeTime"
            and back.get(19) == "true"
            and back.get(27) == builder.BUILD_DEFAULT
        )
        print(f"tulis/baca berkas: {'OK' if ok else 'GAGAL'}")
        return ok


def test_default_note():
    """Catatan tidak diatur -> catatan bawaan; "" -> kosong; diisi -> dipakai."""
    note = builder.default_note()
    ok = bool(note)
    for fmt in ("modern", "legacy"):
        for kw, want, flag in (
            ({}, note, "true"),
            ({"catatan": ""}, "", "false"),
            ({"catatan": "<p>x</p>"}, "<p>x</p>", "true"),
        ):
            if fmt == "modern":
                back = codec.decode_bytes(codec.encode_config(builder.build(nama="N", **kw)))
            else:
                from . import legacy
                back = legacy.decode_bytes(legacy.encode_config(builder.build_legacy(nama="N", **kw)))
            ok = ok and back.get(6) == want and back.get(5) == flag
    print(f"catatan bawaan ({len(note)} karakter): {'OK' if ok else 'GAGAL'}")
    return ok


def run_all(verbose: bool = False) -> bool:
    results = [
        test_roundtrip(verbose),
        test_credentials(),
        test_build_all_locks(),
        test_build_matches_real_profile(),
        test_write_read(),
        test_default_note(),
    ]
    print("=" * 46)
    print("HASIL:", "SEMUA LULUS" if all(results) else "ADA YANG GAGAL")
    return all(results)
