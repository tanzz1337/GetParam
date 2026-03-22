<p align="center">
  <img src="logo.svg" width="420" alt="GetParam Logo">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-42be65?style=flat-square&labelColor=0a0a0a" alt="version">
  <img src="https://img.shields.io/badge/python-3.8+-33b1ff?style=flat-square&labelColor=0a0a0a" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-f1c21b?style=flat-square&labelColor=0a0a0a" alt="license">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-a8a8a8?style=flat-square&labelColor=0a0a0a" alt="platform">
</p>

<p align="center">
  <b>Hidden Parameter Discovery Tool untuk Web App dan REST API</b><br>
  Lebih akurat dari Arjun dengan Multi-Signal Detection, WAF Awareness, dan Rate Limit Bypass bawaan.
</p>

---

## Daftar Isi

1. [Tentang GetParam](#tentang-getparam)
2. [Perbedaan dengan Arjun](#perbedaan-dengan-arjun)
3. [Persyaratan](#persyaratan)
4. [Instalasi](#instalasi)
5. [Cara Penggunaan](#cara-penggunaan)
6. [Opsi dan Parameter](#opsi-dan-parameter)
7. [Sistem Deteksi](#sistem-deteksi)
8. [WAF Detection](#waf-detection)
9. [Rate Limit Bypass](#rate-limit-bypass)
10. [Wordlist](#wordlist)
11. [Struktur Direktori](#struktur-direktori)
12. [Legal Disclaimer](#legal-disclaimer)

---

## Tentang GetParam

GetParam adalah tools open source untuk menemukan **hidden parameter** pada aplikasi web dan REST API. Tools ini bekerja dengan mengirimkan parameter dari wordlist ke target URL, lalu membandingkan response menggunakan **5 sinyal deteksi** secara bersamaan untuk memastikan hasil yang akurat dan minim false positive.

Cocok untuk:
- Bug bounty hunting
- Web penetration testing (authorized)
- Security assessment aplikasi web
- REST API security audit

---

## Perbedaan dengan Arjun

GetParam dirancang untuk menutup celah yang ada di Arjun:

| Fitur | Arjun | GetParam |
|---|---|---|
| Sinyal deteksi | Response size saja | Size + Status code + Reflection + Error-based + Time-based |
| WAF detection | Tidak ada | 10 WAF populer terdeteksi otomatis |
| Rate limit bypass | Manual | Otomatis + adaptif per WAF yang terdeteksi |
| Chunk strategy | Fixed size | Dua fase: chunk scan → individual confirm |
| UA rotation | Tidak ada | Otomatis, 10+ User-Agent pool |
| False positive | Ada (Arjun: 1 FP di test) | Minim (variance-aware baseline) |
| Bypass parameter | Terlewat di test | Terdeteksi lewat sinyal error-based |

### Hasil Uji di Test Lab

Pengujian dilakukan pada environment khusus dengan 20 hidden parameter tersebar di 3 endpoint:

```
Endpoint               Arjun     GetParam
/profile.php           7/7 +1FP  7/7
/api/products.php      7/7       7/7
/login.php             5/6       6/6
─────────────────────────────────────────
Total                  19/20     20/20
False positive         1         0
```

---

## Persyaratan

| Komponen | Keterangan |
|---|---|
| Python | 3.8 atau lebih baru |
| OS | Linux, Windows, macOS |
| Library | `requests`, `urllib3` |

---

## Instalasi

```bash
# Clone repositori
git clone https://github.com/tanzz1337/getparam
cd getparam

# Install dependensi
pip install -r requirements.txt

# Verifikasi
python getparam.py --help
```

---

## Cara Penggunaan

### Scan dasar

```bash
python getparam.py -u https://example.com/profile
```

### Contoh output

```
 ██████╗ ███████╗████████╗██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗
 ...

  [*] Loading wordlist: wordlists/common.txt
  [*] Wordlist loaded  : 511 parameter
  
  [*] Target   : https://example.com/profile
  [*] Method   : GET
  [*] Threads  : 10
  [*] Chunk    : 50 param/request
  [*] Bypass   : ON

  [*] Detecting WAF...
  [*] WAF              : None detected

  [*] Sending baseline request...
  [*] Baseline status  : 200
  [*] Baseline size    : 312 bytes
  [*] Baseline time    : 0.142s

  [*] Starting parameter discovery (511 params)...
  ───────────────────────────────────────────────────────

  [+] user_id              → /profile?user_id=   [size_change]
  [+] debug                → /profile?debug=      [size_change]
  [+] admin                → /profile?admin=      [size_change]
  [+] token                → /profile?token=      [status_change]
  [+] callback             → /profile?callback=   [reflection]
  [+] format               → /profile?format=     [size_change]
  [+] lang                 → /profile?lang=       [error_based]

  ───────────────────────────────────────────────────────
  [*] Done — 7 found | 511 tested | 8.4s
```

### Method POST

```bash
python getparam.py -u https://example.com/login -m POST
```

### JSON body

```bash
python getparam.py -u https://example.com/api/user -m JSON
```

### Dengan autentikasi

```bash
# Bearer token
python getparam.py -u https://example.com/api \
  -H "Authorization: Bearer eyJhbGci..."

# Cookie
python getparam.py -u https://example.com/dashboard \
  -c "session=abc123; csrf=xyz"
```

### Wordlist custom

```bash
# Wordlist API
python getparam.py -u https://example.com/api -w wordlists/api.txt

# Fokus kerentanan OWASP
python getparam.py -u https://example.com/search -w wordlists/owasp.txt

# Wordlist sendiri
python getparam.py -u https://example.com -w /path/to/custom.txt
```

### Melalui proxy Burp Suite

```bash
python getparam.py -u https://example.com/api \
  --proxy http://127.0.0.1:8080
```

### Simpan hasil ke file

```bash
python getparam.py -u https://example.com/api -o hasil.txt
```

### Scan cepat dengan lebih banyak thread

```bash
python getparam.py -u https://example.com/api -t 25
```

### Verbose untuk melihat setiap request

```bash
python getparam.py -u https://example.com/api -v
```

---

## Opsi dan Parameter

| Parameter | Default | Keterangan |
|---|---|---|
| `-u`, `--url` | Wajib | Target URL |
| `-m`, `--method` | `GET` | HTTP method: `GET`, `POST`, `JSON`, `HEADER` |
| `-w`, `--wordlist` | `wordlists/common.txt` | Path wordlist |
| `-t`, `--threads` | `10` | Jumlah thread paralel |
| `--chunk` | `50` | Parameter per request chunk |
| `-H`, `--header` | — | Custom header, bisa diulang: `-H "Key: Val"` |
| `-c`, `--cookie` | — | Cookie string: `"name=val; name2=val2"` |
| `--proxy` | — | Proxy URL: `http://127.0.0.1:8080` |
| `--delay` | `0` | Delay antar request (detik) |
| `--timeout` | `10` | Timeout per request (detik) |
| `--no-bypass` | Tidak aktif | Matikan rate limit bypass |
| `--no-waf` | Tidak aktif | Skip WAF detection |
| `-o`, `--output` | — | Simpan hasil ke file |
| `-v`, `--verbose` | Tidak aktif | Tampilkan detail setiap request |

---

## Sistem Deteksi

GetParam menggunakan 5 sinyal deteksi secara bersamaan (Multi-Signal Detection). Setiap parameter diuji dengan semua sinyal — jika salah satu sinyal terpenuhi, parameter dianggap valid.

### Sinyal 1 — Status Code Change

Parameter valid jika server mengembalikan status code yang berbeda dari baseline. Contoh: baseline `200 OK`, dengan parameter `token` server mengembalikan `401 Unauthorized`.

**Confidence: High**

### Sinyal 2 — Reflection Detection

Setiap parameter diinjeksi dengan nilai unik `getparam_probe_<nama>`. Jika nilai ini muncul di body response, parameter diproses oleh server.

**Confidence: High**

### Sinyal 3 — Response Size Change

Response size dibandingkan dengan rata-rata baseline (3 request). Perbedaan signifikan di atas threshold menandakan parameter mengubah output server. Threshold adaptif berdasarkan variance baseline untuk menghindari noise.

**Confidence: High / Medium**

### Sinyal 4 — Error-Based Detection

Deteksi kemunculan keyword error baru di response (`invalid`, `required`, `missing`, `validation`, dll) yang tidak ada di baseline. Menandakan parameter dikenali aplikasi tapi nilainya tidak valid.

**Confidence: Medium**

### Sinyal 5 — Response Time

Parameter yang memicu proses berat (query DB, external call) akan memperlambat response secara signifikan. Hanya dilaporkan jika 2x lebih lambat dari baseline dan minimal 1 detik lebih lambat.

**Confidence: Low**

---

## WAF Detection

GetParam mendeteksi WAF sebelum mulai fuzzing dan menyesuaikan strategi bypass secara otomatis.

WAF yang dikenali:

| WAF | Metode Deteksi |
|---|---|
| Cloudflare | Header `CF-Ray`, body signature, server header |
| ModSecurity | Header `X-Mod-Security`, body signature |
| Akamai | Header `AkamaiGHost`, body signature |
| AWS WAF | Header `X-Amzn-RequestId` |
| Sucuri | Header `X-Sucuri-ID`, server header |
| Imperva / Incapsula | Header `X-Iinfo`, body signature |
| F5 BIG-IP ASM | Server header, body signature |
| Fortinet FortiWeb | Server header, body signature |
| Barracuda WAF | Server header, body signature |
| Wordfence | Body signature |

Jika WAF terdeteksi, GetParam otomatis menyesuaikan delay, chunk size, dan frekuensi rotasi User-Agent.

---

## Rate Limit Bypass

Rate limit bypass aktif secara default dan bekerja dengan beberapa strategi:

**Rotasi User-Agent** — Pool 10+ User-Agent dirotasi setiap beberapa request, termasuk browser modern, bot, dan tool umum.

**Header variation** — Header `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` divariasikan untuk menghindari fingerprinting.

**Adaptive delay** — Delay bervariasi secara acak dalam range yang ditentukan per WAF. Jika server mengembalikan `429 Too Many Requests`, backoff dinaikkan secara exponential (max 10x) dan diturunkan kembali setelah request sukses.

**Strategi per WAF:**

| WAF | Delay Range | Chunk Multiplier |
|---|---|---|
| Cloudflare | 0.3 – 0.8s | 50% |
| Akamai | 0.5 – 1.2s | 40% |
| ModSecurity | 0.1 – 0.4s | 70% |
| Wordfence | 0.2 – 0.6s | 60% |
| Default | 0.05 – 0.2s | 100% |

Untuk mematikan bypass:

```bash
python getparam.py -u https://example.com --no-bypass
```

---

## Wordlist

| File | Parameter | Kegunaan |
|---|---|---|
| `common.txt` | 511 | Parameter umum web app |
| `owasp.txt` | 117 | Fokus titik rentan OWASP Top 10 |
| `api.txt` | 73 | REST API modern, GraphQL, tracing |
| `json.txt` | 91 | JSON body parameter |

Semua wordlist bisa dikombinasikan:

```bash
cat wordlists/common.txt wordlists/api.txt | sort -u > wordlists/combined.txt
python getparam.py -u https://example.com/api -w wordlists/combined.txt
```

---

## Struktur Direktori

```
getparam/
│
├── getparam.py              Entry point utama dan CLI
├── requirements.txt         Dependensi Python
├── logo.svg                 Logo tools
│
├── wordlists/
│   ├── common.txt           511 parameter umum
│   ├── api.txt              73 parameter REST API
│   ├── owasp.txt            117 parameter OWASP
│   └── json.txt             91 parameter JSON body
│
└── modules/
    ├── requester.py         HTTP client + UA rotation
    ├── waf.py               WAF detection (10 WAF)
    ├── ratelimit.py         Adaptive rate limit bypass
    ├── analyzer.py          Multi-signal response analyzer
    ├── detector.py          Discovery engine (chunk + individual)
    └── reporter.py          Output formatter
```

---

## Legal Disclaimer

> GetParam dibuat **hanya untuk kebutuhan security testing yang sah** — bug bounty, penetration testing dengan izin tertulis, dan security research pada sistem milik sendiri.
>
> Penggunaan tools ini pada sistem tanpa izin eksplisit dari pemilik adalah **tindakan ilegal** dan melanggar hukum yang berlaku di berbagai yurisdiksi.
>
> Pengembang tidak bertanggung jawab atas penyalahgunaan tools ini.

---

<p align="center">
  Made by <a href="https://github.com/tanzz1337">tanzz1337</a> &mdash; Web Penetration Tester
</p>

