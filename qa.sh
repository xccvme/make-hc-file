#!/bin/bash
# QA menyeluruh untuk hcmaker: CLI pada semua sampel + kasus tepi.
# Butuh folder samples/ (berkas .hc nyata) di direktori yang sama.
set -u
PY=${PY:-.venv/bin/python}
pass=0; fail=0
ok(){ echo "  OK    $1"; pass=$((pass+1)); }
no(){ echo "  GAGAL $1"; fail=$((fail+1)); }

mapfile -d '' FILES < <(find samples ref-hcdecode/examples -name '*.hc' -print0 2>/dev/null)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "Tidak ada sampel .hc — bagian uji berkas nyata dilewati."
fi

echo "== 1. info pada semua sampel (${#FILES[@]} berkas) =="
for f in "${FILES[@]}"; do
  if $PY -m hcmaker info "$f" >/dev/null 2>&1; then ok "info $(basename "$f")"; else no "info $(basename "$f")"; fi
done

echo "== 2. dump JSON pada semua sampel =="
for f in "${FILES[@]}"; do
  if $PY -m hcmaker dump "$f" -o /tmp/d.json >/dev/null 2>&1 && $PY -c "import json;json.load(open('/tmp/d.json'))"; then
    ok "dump $(basename "$f")"
  else
    no "dump $(basename "$f")"
  fi
done

if [ "${#FILES[@]}" -gt 0 ]; then
echo "== 3. round-trip byte-identik =="
$PY - <<'PY'
import glob
from hcmaker import codec, legacy
ok = 0
for p in sorted(glob.glob("samples/**/*.hc", recursive=True)) + sorted(glob.glob("ref-hcdecode/examples/*.hc")):
    raw = open(p, "rb").read()
    for m in (codec, legacy):
        try:
            if m.encode_config(m.decode_bytes(raw)) == raw:
                ok += 1
        except Exception:
            pass
print(f"  round-trip identik: {ok} pasangan")
raise SystemExit(0 if ok >= 20 else 1)
PY
if [ $? -eq 0 ]; then ok "round-trip"; else no "round-trip"; fi

echo "== 4. ubah mode lock pada berkas modern nyata =="
$PY - <<'PY'
import glob
from hcmaker import codec, builder
n = bad = 0
for p in sorted(glob.glob("samples/**/*.hc", recursive=True)) + sorted(glob.glob("ref-hcdecode/examples/*.hc")):
    try:
        cfg = codec.decode_file(p)
    except Exception:
        continue
    for mode in builder.LOCK_MODES:
        c2 = codec.decode_file(p)
        builder.apply_lock(c2, mode)
        blob = codec.encode_config(c2)
        back = codec.decode_bytes(blob)
        la, lp, lu = builder.LOCK_MODES[mode]
        exp = {3: "true" if la else "false", 15: "true" if lp else "false", 19: "true" if lu else "false"}
        if all(back.get(i) == v for i, v in exp.items()) and back.get(0) == cfg.get(0) and back.get(7) == cfg.get(7):
            n += 1
        else:
            bad += 1
            print("   gagal", p, mode)
print(f"  kombinasi lock diuji: {n} benar, {bad} salah")
raise SystemExit(0 if bad == 0 and n > 0 else 1)
PY
if [ $? -eq 0 ]; then ok "mode lock"; else no "mode lock"; fi
else
  echo "== 3-4. round-trip & mode lock: dilewati (tanpa samples/) =="
fi

echo "== 5. kasus tepi (nilai harus kembali utuh) =="
$PY - <<'PY'
from hcmaker import builder, codec
cases = [
    ("catatan unicode", dict(nama="Ünïcødé ✓ 中文", catatan="<p>ñ ✓ 中文 😀</p>", payload="GET / [crlf][crlf]"),
     {18: "Ünïcødé ✓ 中文", 6: "<p>ñ ✓ 中文 😀</p>", 0: "GET / [crlf][crlf]"}),
    ("payload sangat panjang", dict(nama="Panjang", payload="X" * 60000), {18: "Panjang", 0: "X" * 60000}),
    ("semua kosong", dict(nama=""), {18: "", 0: ""}),
    ("nama mirip heks", dict(nama="a" * 40), {18: "a" * 40}),
    ("tanpa ssh (v2ray)", dict(nama="V2Ray", v2ray_json='{"outbounds":[{"protocol":"vmess"}]}'),
     {18: "V2Ray", 25: "true", 26: '{"outbounds":[{"protocol":"vmess"}]}'}),
    ("sni + proxy", dict(nama="Proxy", sni="a.com", remote_proxy="1.2.3.4:8080"), {12: "a.com", 1: "1.2.3.4:8080"}),
    ("password + hwid", dict(nama="Proteksi", password="rahasia", hwid="HWID-1"),
     {21: "true", 22: "rahasia", 16: "true", 17: "HWID-1"}),
    ("ssh kredensial", dict(nama="SSH", ssh="h.example:443@user:p@ss:w0rd"), {7: "h.example:443@user:p@ss:w0rd"}),
]
bad = 0
for label, kw, expect in cases:
    try:
        cfg = builder.build(**kw)
        blob = codec.encode_config(cfg)
        back = codec.decode_bytes(blob)
        misses = {i: (back.get(i), want) for i, want in expect.items() if back.get(i) != want}
        assert codec.encode_config(back) == blob
        if misses:
            print(f"  GAGAL {label}: {misses}")
            bad += 1
        else:
            print(f"  OK    {label} ({len(blob)} byte)")
    except Exception as exc:
        print(f"  GAGAL {label}: {type(exc).__name__}: {exc}")
        bad += 1
raise SystemExit(0 if bad == 0 else 1)
PY
if [ $? -eq 0 ]; then ok "kasus tepi"; else no "kasus tepi"; fi

echo "== 6. selftest internal =="
$PY -m hcmaker selftest | tail -3
if [ ${PIPESTATUS[0]} -eq 0 ]; then ok "selftest"; else no "selftest"; fi

echo
echo "RINGKASAN: $pass OK, $fail GAGAL"
[ "$fail" -eq 0 ]
