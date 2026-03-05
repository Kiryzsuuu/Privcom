# Terminal Chat (CMD) + Password

Program chat dua arah yang dijalankan lewat terminal Windows (CMD/PowerShell). Cocok untuk komunikasi di **LAN tanpa internet**.

> Catatan penting: “tanpa internet tapi jarak jauh” **tetap butuh jalur jaringan** apa pun (mis. VPN, port-forwarding, jaringan seluler/satelit dari provider). Kalau tidak ada *network path* sama sekali, komputer tidak bisa saling kirim pesan jarak jauh.

## Syarat

- Windows 10/11
- Python 3.10+ (disarankan). Di Windows biasanya tersedia perintah `py -3`.

Cek:

```bat
py -3 --version
```

## Cara pakai (sekali klik)

1. Jalankan `chat.bat` (double-click).
2. Pilih:
   - `1` untuk **SERVER** (komputer yang jadi host)
   - `2` untuk **CLIENT** (komputer yang ikut chat)

## SERVER (host)

Saat server pertama kali dijalankan, kamu akan diminta membuat password. Password disimpan sebagai **hash** (bukan plaintext) di file `chat_config.json` di folder yang sama.

Opsi utama:

- Port default: `5050`
- Bind default: `0.0.0.0` (menerima koneksi dari LAN)

Jalankan manual (opsional):

```bat
py -3 chat.py --mode server
```

Reset password (opsional):

```bat
py -3 chat.py --mode server --reset-password
```

## CLIENT

Client akan diminta:

- `Server IP/hostname` (contoh: `192.168.1.10`)
- `Nama kamu`
- `Password`

Jalankan manual (opsional):

```bat
py -3 chat.py --mode client --server 192.168.1.10
```

## Perintah di chat

- `/help` menampilkan bantuan
- `/quit` keluar
- `/cls` membersihkan layar

## Tampilan CMD yang lebih “pro”

Client akan menampilkan nama pengirim berwarna dan timestamp (jika terminal mendukung ANSI). Ini hanya untuk kenyamanan, tidak mengubah cara kerja jaringan.

Opsi client:

- Matikan warna: `--no-color`
- Matikan timestamp: `--no-ts`

Contoh:

```bat
py -3 chat.py --mode client --server 100.x.y.z --no-color
```

Jika warna tidak muncul di CMD lama, kamu bisa install dependency opsional:

```bat
py -3 -m pip install colorama
```

## Otomasi / non-interaktif (opsional)

Jika kamu ingin scripting (atau testing), kamu bisa:

- Set password setup server via env (lebih aman daripada argumen CLI):

```bat
set CHAT_SETUP_PASSWORD=PasswordKamu
set CHAT_SETUP_PASSWORD_CONFIRM=PasswordKamu
py -3 chat.py --mode server --reset-password
```

- Jalankan client tanpa prompt password:

```bat
set CHAT_PASSWORD=PasswordKamu
py -3 chat.py --mode client --server 127.0.0.1 --name Alice --once "halo"
```

## Tips koneksi tanpa internet (LAN)

- Pastikan kedua PC berada di Wi‑Fi yang sama atau terhubung kabel LAN.
- Cari IP server dengan:

```bat
ipconfig
```

- Jika Windows Firewall memblokir, izinkan Python menerima koneksi (atau buka port 5050 untuk jaringan Private).

## Remote jarak jauh (butuh jalur jaringan)

Kalau ingin dipakai jarak jauh, kamu perlu salah satu:

- VPN (mis. WireGuard/Tailscale/ZeroTier) lalu pakai IP VPN
- Port forwarding dari router ke PC server (hati-hati keamanan)
- Jaringan data seluler/satelit dari provider (tetap “internet/wan” secara praktik)

Program ini bekerja selama client bisa menjangkau `IP:PORT` server.

## Rekomendasi: pakai VPN saja (paling mudah)

### Opsi A (paling gampang): Tailscale

1. Install Tailscale di **PC Server** dan **PC Client**.
2. Login ke akun yang sama (atau satu tailnet yang sama) dan pastikan status **Connected**.
3. Ambil IP Tailscale di PC Server (biasanya format `100.x.y.z`).
   - Bisa lihat dari aplikasi Tailscale, atau jalankan `tailscale ip -4` jika CLI tersedia.
4. Jalankan server:

```bat
py -3 chat.py --mode server --port 5050
```

5. Di PC Client, jalankan client dan isi `Server IP/hostname` dengan IP Tailscale server:

```bat
py -3 chat.py --mode client --server 100.x.y.z --port 5050
```

Jika ada masalah koneksi:
- Pastikan Windows Firewall mengizinkan Python untuk jaringan **Private** (atau rule inbound port `5050`).
- Pastikan kedua perangkat benar-benar terhubung di Tailscale (ping antar device harus jalan).

### Opsi B: WireGuard (lebih teknis, tapi ringan)

1. Buat tunnel WireGuard (bisa via server VPS/rumah sebagai “hub”, atau site-to-site).
2. Pastikan PC Server dan Client saling bisa ping lewat IP WireGuard (mis. `10.7.0.1` ↔ `10.7.0.2`).
3. Jalankan server seperti biasa (bind `0.0.0.0` sudah OK).
4. Client konek ke IP WireGuard server:

```bat
py -3 chat.py --mode client --server 10.7.0.1 --port 5050
```
