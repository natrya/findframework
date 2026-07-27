# Konfigurasi API Key subfinder

**Author:** Ryan Fabella

Tahap 1 pada `findframework.sh` menggunakan **subfinder** untuk enumerasi
subdomain secara pasif. Subfinder menarik data dari puluhan sumber OSINT.
Sebagian sumber gratis dan langsung jalan; sebagian besar sumber terbaik
**baru aktif setelah Anda memasang API key**-nya.

Dokumen ini menjelaskan:

1. Di mana file konfigurasi berada
2. Format penyimpanan key (penting — ada 2 bentuk)
3. Cara mendapatkan key untuk tiap sumber (prioritas)
4. Cara memverifikasi key sudah terpakai
5. Keamanan penyimpanan key

---

## 1. Lokasi File Konfigurasi

Subfinder membaca key dari:

```
~/.config/subfinder/provider-config.yaml
```

Kalau file belum ada, buat dulu dengan menjalankan subfinder sekali:

```bash
subfinder -d contoh.go.id
```

Perintah itu akan menghasilkan `provider-config.yaml` berisi daftar semua
sumber dengan nilai kosong `[]`. Repositori ini juga sudah menyediakan
**template lengkap dengan label format** — cukup salin ke lokasi di atas bila
belum punya.

---

## 2. Format Penyimpanan Key

File berformat YAML. Setiap sumber adalah sebuah **list**. Ada dua bentuk
penulisan key — perhatikan baik-baik karena ini penyebab kesalahan paling umum:

### a. Bentuk `(bare)` — hanya satu key

Sebagian besar sumber cukup satu string:

```yaml
virustotal:
    - 0x1234abcd5678efgh
securitytrails:
    - key-securitytrails-anda
shodan:
    - key-shodan-anda
```

### b. Bentuk `(id:secret)` — dua bagian dipisah titik dua

Beberapa sumber butuh dua bagian, digabung dengan tanda `:` (titik dua):

```yaml
censys:
    - CENSYS_API_ID:CENSYS_API_SECRET
fofa:
    - email@anda.com:key-fofa-anda
passivetotal:
    - email@anda.com:key-pt-anda
intelx:
    - 2.intelx.io:key-intelx-anda
```

### c. Beberapa key sekaligus (rotasi otomatis)

Anda boleh memasang **lebih dari satu key** per sumber. Subfinder akan
memutar (rotate) key tersebut untuk menghindari limit per-key. Sangat
disarankan untuk GitHub:

```yaml
github:
    - ghp_tokenPertama
    - ghp_tokenKedua
    - ghp_tokenKetiga
```

> **Aturan format:** gunakan indentasi spasi (bukan tab), diawali `- ` (strip
> spasi). Sumber yang dibiarkan `[]` artinya nonaktif dan tidak akan dipanggil.

---

## 3. Cara Mendapatkan API Key (berdasarkan prioritas)

### 🥇 Tier 1 — gratis & paling berdampak (pasang ini dulu)

| Sumber | Biaya | Format | Cara dapat |
|--------|-------|--------|-----------|
| **virustotal** | Gratis (~500/hari) | bare | Daftar di virustotal.com → menu profil → **API key** |
| **securitytrails** | Gratis (50/bulan) | bare | securitytrails.com → Account → API |
| **chaos** | Gratis (akun PD) | bare | cloud.projectdiscovery.io → API Key |
| **shodan** | Gratis (tier dasar) | bare | account.shodan.io → **API Key** |
| **censys** | Gratis (250/bulan) | id:secret | search.censys.io → Account → API (salin **API ID** dan **Secret**) |
| **github** | Gratis (cukup PAT) | bare | github.com → Settings → Developer settings → **Personal access token** (tanpa scope khusus) |
| **certspotter** | Gratis (tier dasar) | bare | sslmate.com/certspotter → API |
| **fullhunt** | Gratis (tier dasar) | bare | fullhunt.io → daftar → API key |
| **leakix** | Gratis | bare | leakix.net → Settings → API |

### 🥈 Tier 2 — cakupan APAC/Indonesia bagus (umumnya berbasis kredit)

| Sumber | Format | Cara dapat |
|--------|--------|-----------|
| **fofa** | email:key | fofa.info → Personal Center → API |
| **quake** | bare | quake.360.net → profil → API key |
| **netlas** | bare | app.netlas.io → API |
| **zoomeyeapi** | bare | zoomeye.org → Profile → API key |
| **threatbook** | bare | threatbook.io → API |
| **hunter** | bare | hunter.how → API |

### 🥉 Tier 3 — berbayar / berbasis kredit (pasang bila punya)

`binaryedge`, `intelx` (host:key), `passivetotal` (user:key), `bevigil`,
`c99`, `chinaz`, `dnsdb`, `dnsrepo`, `bufferover`, `whoisxmlapi`, `robtex`.

> **Catatan untuk target Indonesia:** mesin `fofa`, `quake`, dan `netlas`
> sering memberi cakupan infrastruktur pemerintah/APAC yang tidak muncul di
> Shodan/Censys. Layak diprioritaskan setelah Tier 1.

### Sumber tanpa key (sudah otomatis jalan)

`crtsh`, `hackertarget`, `alienvault (otx)`, `rapiddns`, `waybackarchive`,
`commoncrawl`, `sitedossier`, `anubis`, `digitorus`, dan lainnya — tidak perlu
dikonfigurasi.

---

## 4. Contoh Isi File Lengkap

Contoh `~/.config/subfinder/provider-config.yaml` setelah beberapa key diisi
(sumber lain dibiarkan `[]`):

```yaml
# Tier 1
virustotal:
    - 0x1234abcd5678efgh
securitytrails:
    - st-key-anda
chaos:
    - chaos-key-anda
shodan:
    - shodan-key-anda
censys:
    - 12ab34cd-5678-90ef:rahasiaCensysAnda
github:
    - ghp_tokenPertama
    - ghp_tokenKedua
certspotter:
    - certspotter-key-anda
fullhunt:
    - fullhunt-key-anda
leakix:
    - leakix-key-anda

# Tier 2 (opsional)
fofa:
    - email@anda.com:fofa-key-anda
quake:
    - quake-key-anda
netlas:
    - netlas-key-anda

# Sumber lain dibiarkan nonaktif
binaryedge: []
intelx: []
passivetotal: []
```

---

## 5. Verifikasi Key Sudah Terpakai

Setelah mengisi key, uji dengan flag `-stats` (menampilkan hasil per sumber)
dan `-ls` (mendaftar sumber & menandai mana yang butuh auth):

```bash
# Lihat semua sumber dan mana yang butuh API key
subfinder -ls

# Jalankan dan lihat berapa hasil dari tiap sumber
subfinder -d contoh.go.id -all -stats -v
```

Pada output `-stats`:

- Sumber yang **berhasil pakai key** akan muncul di tabel dengan angka `Results`.
- Sumber yang **key-nya salah/tidak ada** akan muncul di daftar
  *"included but skipped"* di bagian bawah, atau punya angka `Errors`.

`findframework.sh` juga otomatis menyimpan statistik ini ke
`subfinder_stats.txt` di dalam folder output setiap kali dijalankan, sehingga
Anda bisa mengecek kontribusi tiap sumber per-engagement.

---

## 6. Keamanan Penyimpanan Key

API key bersifat rahasia. Beberapa hal penting:

1. **Batasi izin file** agar hanya bisa dibaca Anda:

   ```bash
   chmod 600 ~/.config/subfinder/provider-config.yaml
   ```

2. **Jangan commit file key ke git.** Bila folder ini di-track git, tambahkan
   ke `.gitignore`:

   ```
   provider-config.yaml
   *.bak.*
   ```

3. **Gunakan Personal Access Token GitHub tanpa scope berlebih** — untuk
   subfinder tidak perlu izin apa pun (atau cukup `public_repo`).

4. **Cabut/rotasi key** bila bocor atau setelah engagement selesai, terutama
   token GitHub.

5. **Backup aman.** Bila membuat backup config (`provider-config.yaml.bak.*`),
   perlakukan sama rahasianya dan jangan sebar.

---

*Semua API key di atas hanya untuk enumerasi pasif OSINT. Tidak ada satupun
yang mengirim request langsung ke server target — memperbanyak key hanya
memperkaya data subdomain, aman untuk target pemerintah.*
