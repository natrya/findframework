# findframework

**Author:** Ryan Fabella

`findframework.sh` adalah script reconnaissance untuk memetakan **subdomain** dan
melakukan **fingerprinting framework/teknologi web** dari sebuah domain target.
Alur kerjanya pasif dulu (enumerasi subdomain dari sumber OSINT), lalu aktif
(memeriksa host yang hidup dan mengidentifikasi teknologinya). 

> ⚠️ **Peringatan legal.** Tahap fingerprinting aktif (whatweb, nuclei, wafw00f)
> mengirim request langsung ke server target. Jalankan **hanya** terhadap domain
> yang Anda punya izin/otorisasi tertulis untuk diuji. Untuk domain pemerintah,
> gunakan rate limit rendah dan mode sekuensial (lihat bagian *Tips target `.id`*).

---

## Daftar Isi

- [Cara Kerja](#cara-kerja)
- [Prasyarat (Dependensi)](#prasyarat-dependensi)
- [Instalasi](#instalasi)
- [Cara Penggunaan](#cara-penggunaan)
- [Opsi Command-line](#opsi-command-line)
- [Contoh Penggunaan](#contoh-penggunaan)
- [File Output](#file-output)
- [Tips Target `.id`](#tips-target-goid)
- [Konfigurasi API Key](#konfigurasi-api-key)
- [Troubleshooting](#troubleshooting)

---

## Cara Kerja

Script berjalan dalam **4 tahap** otomatis:

| Tahap | Nama | Tools | Sifat |
|-------|------|-------|-------|
| 1 | Enumerasi subdomain pasif | `subfinder`, `amass`, `crt.sh` | Pasif (OSINT, tidak menyentuh target) |
| 2 | Cek host hidup + deteksi teknologi ringan | `httpx` | Aktif (ringan) |
| 3 | Fingerprinting mendalam | `whatweb`, `nuclei`, `wafw00f` | Aktif (dilewati bila mode `-p`) |
| 4 | Gabung hasil + buat laporan | `merge_findings.py` | Lokal |

Hasil akhirnya adalah laporan `report.md` (tabel ringkas) dan `results.json`
(data mentah terstruktur).

---

## Prasyarat (Dependensi)

Script akan berhenti bila ada tool wajib yang belum terpasang. Tool yang diperlukan:

```
subfinder  amass  httpx  whatweb  nuclei  wafw00f  jq  curl  python3
```

Cek cepat apakah semua sudah ada:

```bash
for b in subfinder amass httpx whatweb nuclei wafw00f jq curl python3; do
  command -v "$b" >/dev/null && echo "OK   $b" || echo "HILANG $b"
done
```

### Instalasi tool (Kali/Debian)

```bash
# Tools ProjectDiscovery (butuh Go)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Dari repo Kali/apt
sudo apt update && sudo apt install -y amass whatweb wafw00f jq curl python3

# Perbarui template nuclei (sekali di awal)
nuclei -update-templates
```

> Pastikan `$HOME/go/bin` ada di `PATH` agar binary hasil `go install` terpanggil.

---

## Instalasi

```bash
git clone <repo-ini>   # atau salin folder findframework/
cd findframework
chmod +x findframework.sh
```

File penting dalam folder:

```
findframework.sh    # script utama
merge_findings.py   # penggabung hasil + generator laporan (dipanggil otomatis)
README.md           # dokumen ini
KONFIGURASI.md      # cara mendapatkan & menyimpan API key subfinder
.gitignore          # mengecualikan folder output/ & file rahasia dari git
output/             # hasil scan tiap run (dibuat otomatis, tidak di-commit)
```

---

## Cara Penggunaan

Bentuk paling dasar — hanya wajib memberi domain target dengan `-d`:

```bash
./findframework.sh -d contoh.id
```

Script akan membuat folder output otomatis di
`./output/contoh.id_<tanggal>_<jam>/` dan menaruh **semua** hasil di sana.
Folder `output/` sudah masuk `.gitignore`, jadi hasil scan tidak akan
ter-commit ke git secara tidak sengaja.

---

## Opsi Command-line

| Opsi | Wajib? | Default | Keterangan |
|------|--------|---------|------------|
| `-d <domain>` | **Ya** | — | Domain target, mis. `contoh.id` |
| `-o <outdir>` | Tidak | `./output/<domain>_<timestamp>` | Folder output kustom |
| `-r <rps>` | Tidak | `100` | Rate limit (request per detik) untuk httpx & nuclei |
| `-p` | Tidak | mati | Mode **pasif saja**: lewati whatweb/nuclei/wafw00f |
| `-h` | Tidak | — | Tampilkan bantuan lalu keluar |

---

## Contoh Penggunaan

**1. Scan standar (pasif + aktif), rate default:**

```bash
./findframework.sh -d contoh.id
```

**2. Folder output khusus untuk arsip engagement:**

```bash
./findframework.sh -d contoh.id -o ./contoh/recon-2026
```

**3. Mode pasif saja (paling aman — tidak melakukan fingerprint aktif):**

```bash
./findframework.sh -d contoh.id -p
```

**4. Target pemerintah — rate limit rendah supaya tidak membebani server:**

```bash
./findframework.sh -d contoh.id -r 20 -o ./contoh/recon-2026
```

---

## File Output

Semua file tersimpan di dalam folder output (`-o` atau default). Isinya:

| File | Isi |
|------|-----|
| `subdomains_raw.txt` | Semua subdomain mentah (belum dibersihkan) dari seluruh sumber |
| `subdomains.txt` | Subdomain final (huruf kecil, unik, sudah difilter sesuai domain) |
| `subfinder_stats.txt` | Statistik per-sumber subfinder (sumber mana yang aktif / dilewati karena tak ada API key) |
| `httpx_output.json` | Hasil httpx: URL hidup, status code, judul, server, teknologi |
| `live_hosts.txt` | Daftar URL host yang hidup |
| `whatweb_output.json` | Hasil fingerprint whatweb |
| `nuclei_tech.jsonl` | Deteksi teknologi oleh nuclei (satu JSON per baris) |
| `wafw00f_output.txt` | Deteksi WAF per host |
| **`results.json`** | **Data gabungan terstruktur** (untuk diproses lanjut) |
| **`report.md`** | **Laporan akhir** berupa tabel ringkas per subdomain |

Isi `report.md` mencakup: jumlah subdomain, jumlah host hidup, jumlah host yang
teridentifikasi teknologinya, tabel `Subdomain | Status | Server | Technologies | WAF`,
dan daftar teknologi unik yang ditemukan.

---

## Tips Target `.id`

Untuk domain pemerintah, kehati-hatian lebih penting daripada kecepatan:

1. **Mulai dari mode pasif** (`-p`) untuk memetakan permukaan tanpa menyentuh server.
2. **Turunkan rate limit** saat fingerprint aktif, mis. `-r 20` atau lebih rendah,
   agar tidak memicu alarm/WAF atau membebani layanan publik.
3. **Jalankan sekuensial**, jangan paralel dengan scanner berat lain terhadap target yang sama.
4. **Pastikan otorisasi** (nomor surat tugas / ruang lingkup engagement) sebelum tahap aktif.
5. **Tambahkan API key subfinder** untuk memperkaya hasil subdomain (lihat di bawah) —
   ini murni memperbanyak sumber OSINT pasif, tidak menambah beban ke target.

---

## Konfigurasi API Key

Tahap 1 (subfinder) menemukan jauh lebih banyak subdomain bila Anda memasang
API key dari sumber-sumber pasif tambahan (VirusTotal, SecurityTrails, Censys,
Shodan, GitHub, dll). Tanpa key, hanya sumber gratisan yang berjalan.

👉 **Panduan lengkap cara mendapatkan dan menyimpan API key ada di
[`KONFIGURASI.md`](./KONFIGURASI.md).**

Cek cepat sumber mana yang aktif vs. dilewati:

```bash
subfinder -d contoh.id -all -stats -v
```

---

## Troubleshooting

| Gejala | Kemungkinan penyebab & solusi |
|--------|------------------------------|
| `Error: missing required tools: ...` | Ada tool yang belum terpasang — pasang sesuai bagian *Instalasi tool*. |
| `Error: no subdomains found ...` | Domain memang tak punya subdomain publik, atau semua sumber gagal. Coba lagi, atau tambah API key. |
| Subdomain sedikit sekali | Belum ada API key subfinder — lihat `KONFIGURASI.md`. |
| `crtsh` error di statistik | crt.sh memang sering timeout/502; sumber lain (thc, wayback) biasanya menutupi. |
| Tahap 2 dapat 0 host hidup | Semua subdomain mati/terfilter, atau rate limit terlalu ketat/koneksi bermasalah. |
| Banyak `403`/blokir saat aktif | Terkena WAF. Turunkan `-r`, atau cukup pakai mode `-p`. |

---

*Gunakan alat ini secara bertanggung jawab dan hanya pada target yang diizinkan.*
