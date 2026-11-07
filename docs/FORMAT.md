# Rincian teknis format `.hc` HTTP Custom

Didapat dari membongkar APK `xyz.easypro.httpcustom` versi 4.11.25 (build 645)
dan diverifikasi terhadap 19 berkas `.hc` nyata.

## 1. Lapisan luar (semua format)

```
berkas byte  -> decode UTF-8 -> encode latin-1          => byte "latin"
latin[i] ^= OUTER_XOR[i mod 11]                          => teks heksadesimal
teks heksadesimal -> ChaCha20-Poly1305 (OUTER_KEY)       => JSON pembungkus
```

* `OUTER_XOR` = `e382e4b8adc386f09f9293` (11 byte)
* nonce tetap `db db db db db db db db` (8 byte)
* MAC memakai layout **original** Poly1305, bukan RFC 8439:
  pesan = `LE64(0) || ciphertext || LE64(len(ciphertext))`, AAD kosong.
* kunci sekali pakai Poly1305 = 32 byte pertama keystream ChaCha20 (offset 0);
  payload dienkripsi mulai offset keystream 64.

Repository pihak ketiga sering salah di sini: `Crypto.Cipher.ChaCha20_Poly1305`
memakai layout MAC RFC sehingga tag selalu ditolak.

## 2. Format modern (a/b, build 645 — keluaran APK yang dibongkar)

```json
{ "a": { "yz": "...", "xy": "<blob>", "wx": "...", "vw": "645",
         "uv": "<pemisah>", "aa": "..." },
  "b": "<verCfg>" }
```

* `a.xy` = satu record berisi **32 kolom** yang digabung memakai
  **ciphertext heksadesimal dari `a.uv`** sebagai pemisah — bukan nilai
  `uv` yang sudah didekripsi.
* `a.vw` = build aplikasi; `b` = versi format (`57`).
* Kunci `a` lain (`yz`, `wx`, `aa`, `cb`, `sr`, `ts`, `ut`, `wv`, `xw`,
  `yx`, `zy`) adalah opsi aplikasi; nilainya disalin dari profil terbanyak.
* Kunci opsional `c` = URL auto-update (record dengan FIELD_KEY).

Aturan penyimpanan per kolom:

* record terautentikasi (FIELD_KEY): `0, 7, 10, 11, 12, 22, 24, 26, 29, 30, 31`
* lapisan **JKL** tambahan: `0, 1, 7, 11, 12, 26`
* kolom `24` = **dua** record dipisah, contoh `["[splitPsiphon]", "[splitPsiphon]"]`
* kolom `7` = pasangan angka lalu braille lalu JKL (lihat bagian 4)

## 3. Format legacy (cfg/content, verCfg 51/54/57)

```json
{ "cfg": { "content": "<blob>", "isLoginHwid": false, "verApp": 464,
           "a": false, "c": false },
  "verCfg": 54 }
```

* `content` = record berisi 32 kolom yang digabung literal `[splitConfig]`.
* Kunci konten berbeda per era: verCfg 54 -> key#0, 57 -> key#1, 51 -> key#5.
* Kunci field: key#2 untuk `0,7,10,11,12,26`, key#3 untuk `29,30,31`.
* Kolom `22` ditulis sebagai record walaupun kosong; kalau diisi teks pendek
  non-heksadesimal ditulis polos.
* JSON memakai gaya Gson *pretty print* (indentasi 2 spasi) dan urutan kunci
  harus dipertahankan agar byte-identik.

## 4. Lapisan JKL dan kredensial

```
JKL     : base64 -> XOR berulang (17 byte) -> base64
braille : tiap byte -> 2 karakter braille (nibble tinggi, nibble rendah)
angka   : tiap byte b -> "a.b" dengan a = b + size, size = jumlah byte bagian
```

Kolom `7` = `JKL(braille(angka(akun SSH)))`.
Contoh: `vpn.example.com:443@demo_user:DemoOnly123!`
-> `vpn.example.com:443@109.9,110.9,…:80.12,113.12,…` -> braille -> JKL.

Kolom `11` (kredensial OpenVPN) memakai bentuk yang sama tanpa braille bila
polanya cocok.

## 5. Peta 32 kolom

| # | Arti | # | Arti |
| --- | --- | --- | --- |
| 0 | payload HTTP | 16 | pakai HWID? |
| 1 | remote proxy | 17 | daftar HWID |
| 2 | blokir perangkat root | 18 | nama config |
| 3 | **lock all** | 19 | **buka user & password** |
| 4 | masa berlaku | 20 | mode koneksi (`0`, `1`, `3`) |
| 5 | ada catatan? | 21 | aktifkan password |
| 6 | catatan (HTML) | 22 | password |
| 7 | akun SSH | 23 | belum dipetakan |
| 8 | hanya data seluler | 24 | Psiphon (2 record) |
| 9 | buka remote proxy | 25 | V2Ray aktif |
| 10 | config OpenVPN | 26 | JSON V2Ray |
| 11 | kredensial OpenVPN | 27 | versi config (build) |
| 12 | TLS SNI | 28 | SlowDNS aktif |
| 13 | konek lewat SSH | 29 | SlowDNS server |
| 14 | port udpgw | 30 | SlowDNS public key |
| 15 | **lock payload** | 31 | DNS resolver |

Kolom 0–22 sejajar dengan daftar 23 field milik decoder generasi lama
(`payloadURL`, `payloadProxyURL`, `shouldNotWorkWithRoot`,
`lockPayloadAndServers`, `expiryDate`, `hasNotes`, `noteField2`, `sshAddress`,
`onlyMobileData`, `unlockRemoteProxy`, …). Kesesuaian ini diverifikasi dengan
`lock tes.hc` (password `tes` di kolom 22) dan pasangan berkas NO LOCK/UNLOCK
(kolom 15).

## 6. Tabel kunci

Ketujuh kunci ditemukan sebagai teks heksadesimal di
`lib/arm64-v8a/libsysNative.so`:

```
#0 2be4342943c6f91ff58987f41a1aafd179eeb4e053f5cea55b11d6a7db58bd7d
#1 3380aa278b744ba5b529a7f32fa803e48749280dae378345d9b526cf1dbce372   (kunci utama a.xy)
#2 cea9305c95168b162a335b137c61983b8df54e6375da01136547890f14c5fac3   (kunci field legacy)
#3 4beeace0e42bae8f29470cf40cf2dfacd5f4e1f751912bf52e803c8c85792193   (kolom 29-31 legacy)
#4 f8e5f6ebea90558eb32229da24fd0fb7d813091dafe89bb2954fda33b4c60f63
#5 81342f558a6273bac4548d473f54c4ffc7c41747dee81369acab9c787d41ab9c   (kunci luar)
#6 45635e6fc70486e2fd10d3c2b4780f02d0b4c5f4aa929fc54f86bb8fa4417944
```

Kunci field format modern (`3d632a251c…`) tidak tersimpan sebagai teks di
binari mana pun; nilainya dipakai apa adanya karena terbukti membuka MAC
berkas nyata.

## 7. Verifikasi yang sudah dilakukan

1. 21 berkas `.hc` nyata (11 modern + 10 legacy) dibaca lalu ditulis ulang,
   hasilnya byte-identik dengan berkas aslinya. Berkas yang diakhiri baris baru
   nyasar (`ILPED2028.hc`) pun identik karena byte ekor disimpan apa adanya.
2. Berkas buatan dibaca ulang oleh decoder pembanding independen
   (`ref-hcdecode/`) dan seluruh tag Poly1305 dinyatakan valid.
3. Rantai kredensial kolom 7 direkonstruksi dan hasilnya sama dengan nilai
   tersimpan pada berkas nyata.
4. Struktur `a` dan pola record/polos berkas buatan sama dengan profil
   terbanyak (8 berkas) berkas nyata.
