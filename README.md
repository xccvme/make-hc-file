# make-hc-file (HCMaker)

Toolkit CLI untuk **membaca, membuat, dan mengedit** berkas config `.hc` HTTP Custom
(format modern build 645 dan format legacy), termasuk mengatur **lock / unlock**.

## Instalasi

```bash
git clone https://github.com/xccvme/make-hc-file.git
cd make-hc-file
python3 -m venv .venv                      # buat virtualenv
.venv/bin/pip install -r requirements.txt  # pycryptodome + cryptography
```

Semua perintah memakai pola:

```bash
.venv/bin/python -m hcmaker <perintah> [opsi]
```

## Perintah

### `info` — lihat ringkasan config

```bash
# tampilkan format, build, nama, payload, SSH, SNI, dan semua flag lock
.venv/bin/python -m hcmaker info config.hc
```

### `dump` — bongkar semua kolom ke JSON

```bash
# cetak 32 kolom + status lock ke layar
.venv/bin/python -m hcmaker dump config.hc

# simpan ke berkas JSON
.venv/bin/python -m hcmaker dump config.hc -o hasil.json
```

### `build` — buat config baru dari JSON

```bash
# format modern (aplikasi HTTP Custom terbaru, build 645)
.venv/bin/python -m hcmaker build contoh/spesifikasi.json -o baru.hc

# format legacy (aplikasi versi lama; versi baru tetap bisa membuka)
.venv/bin/python -m hcmaker build contoh/spesifikasi.json -o baru_legacy.hc --format legacy
```

Contoh `spesifikasi.json`:

```json
{
  "nama": "Config Demo",
  "payload": "GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: Keep-Alive[crlf][crlf]",
  "ssh": "sg.example.com:443@user:pass",
  "sni": "sg.example.com",
  "mode_koneksi": "0",
  "masa_berlaku": "lifeTime",
  "catatan": "<b>Catatan HTML</b>",
  "lock": "no_lock"
}
```

> **Catatan bawaan:** jika `catatan` tidak diisi, deskripsi otomatis memakai isi
> `hcmaker/default_note.html` (edit berkas itu untuk mengganti default).
> Isi `"catatan": ""` bila ingin config tanpa catatan.

Kunci lain yang didukung: `remote_proxy`, `unlock_remote_proxy`, `block_root`,
`hanya_data_seluler`, `hwid`, `password`, `v2ray_json`, `openvpn_config`,
`openvpn_kredensial`, `slowdns_server`, `slowdns_public_key`, `dns_resolver`,
`update_url`, `build_target`, `extra` (`{indeks: nilai}` untuk override kolom).

### `lock` — ubah mode lock (khusus format modern)

```bash
# buka semua (payload, server, user/pass bisa dilihat & diubah)
.venv/bin/python -m hcmaker lock config.hc no_lock -o config_unlock.hc

# kunci semua
.venv/bin/python -m hcmaker lock config.hc lock_all -o config_lock.hc

# payload terkunci, server & akun diisi penerima
.venv/bin/python -m hcmaker lock config.hc lock_payload_unlock_server -o config_lp.hc

# server & payload terkunci, user/pass diisi penerima
.venv/bin/python -m hcmaker lock config.hc unlock_user_and_password -o config_up.hc
```

Tanpa `-o`, berkas asli ditimpa.

### `set` — ubah kolom langsung (`indeks=nilai`)

```bash
# ganti nama config
.venv/bin/python -m hcmaker set config.hc 18="NAMA BARU" -o baru.hc

# ganti catatan/deskripsi (5=true menyalakan tampilan catatan)
.venv/bin/python -m hcmaker set config.hc 5=true 6="<b>Deskripsi baru</b>" -o baru.hc

# ganti catatan dari isi berkas HTML/teks
.venv/bin/python -m hcmaker set config.hc 5=true 6="$(cat catatan.html)" -o baru.hc

# unlock all + izinkan ubah remote proxy
.venv/bin/python -m hcmaker set config.hc 3=false 15=false 19=false 9=true -o unlock.hc

# ganti akun SSH dan SNI
.venv/bin/python -m hcmaker set config.hc 7="host:443@user:pass" 12="bug.example.com" -o baru.hc
```

### `reencode` — baca lalu tulis ulang

```bash
# hasilnya harus identik byte-per-byte dengan aslinya (uji keaslian format)
.venv/bin/python -m hcmaker reencode config.hc -o ulang.hc
cmp config.hc ulang.hc && echo identik
```

### `selftest` / `qa.sh` — pengujian

```bash
.venv/bin/python -m hcmaker selftest      # uji internal
.venv/bin/python -m hcmaker selftest -v   # versi rinci
./qa.sh                                   # QA lengkap (round-trip butuh folder samples/)
```

## Peta kolom penting

| # | Isi | # | Isi |
| --- | --- | --- | --- |
| 0 | payload | 15 | lock payload |
| 1 | remote proxy | 16/17 | HWID aktif / daftar HWID |
| 2 | blokir root | 18 | nama config |
| 3 | lock all | 19 | unlock user & password |
| 4 | masa berlaku | 20 | mode koneksi |
| 5/6 | catatan aktif / HTML catatan | 21/22 | password aktif / password |
| 7 | akun SSH `host:port@user:pass` | 25/26 | V2Ray aktif / JSON V2Ray |
| 9 | unlock remote proxy | 28–30 | SlowDNS |
| 12 | SNI | 31 | DNS resolver |

Rincian teknis format ada di `docs/FORMAT.md`.
