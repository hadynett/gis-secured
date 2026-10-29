# gis-secured (gisnet-secure-ssh)

Satu skrip untuk mengamankan server Linux, lalu mengelolanya sehari-hari. Perintahnya tetap `gisnet-secure-ssh`.

- memasang **kunci publik SSH** Anda ke root (ditanyakan saat dijalankan);
- memasang & menyalakan **fail2ban** (jail `sshd` mode *aggressive* + *recidive*);
- **whitelist** IP/subnet yang tidak pernah diblokir;
- **mengetatkan SSH**: login hanya dengan kunci, password dimatikan, root hanya boleh dengan kunci;
- **update keamanan otomatis** (unattended-upgrades / dnf-automatic / yum-cron);
- **jail pemindai website** bila ada nginx/apache (blokir hanya port web, 6 jam), otomatis dilewati bila website di belakang Cloudflare/proxy;
- **jail FTP & email** (vsftpd, proftpd, pure-ftpd, postfix, dovecot) bila layanannya ada;
- **pemeriksaan server**: kesehatan (CPU/RAM/disk), port berbahaya yang terbuka, proses mencurigakan (penambang kripto, program dari /tmp), riwayat login SSH;
- **blokir bersama**: IP penyerang SSH yang diblokir di server GISNET lain ikut diblokir (lewat aplikasi pemantau);
- **update sendiri**: `gisnet-secure-ssh update` memperbarui skrip & memasang ulang dengan pengaturan yang sama;
- perintah harian: `status`, `banned`, `ban`/`unban`, `whitelist`, `key`, `port`, `restore`, `report`, `checks`, `update`, `menu`.

Mendukung **Debian, Ubuntu, AlmaLinux / Rocky / RHEL / CentOS / Fedora, openSUSE, Arch, Alpine**.

## Cara pakai

Login ke server sebagai root (atau pakai `sudo`), lalu:

```bash
curl -fsSL https://raw.githubusercontent.com/hadynett/gis-secured/main/gisnet-secure-ssh.sh -o gisnet-secure-ssh.sh
sudo bash gisnet-secure-ssh.sh --dry-run   # lihat dulu apa yang akan dilakukan (tidak mengubah apa pun)
sudo bash gisnet-secure-ssh.sh             # pasang
```

Skrip akan bertanya:

1. **Kunci publik SSH**: tempel isi file `.pub` Anda (diawali `ssh-ed25519` / `ssh-rsa` / `ecdsa-sha2-...`). Bisa lebih dari satu kunci, satu per baris; Enter pada baris kosong untuk selesai.
2. **Whitelist**: IP/subnet yang tidak boleh diblokir, misalnya IP kantor (pisahkan dengan spasi). Enter untuk melewati.

Setelah terpasang, skrip tersalin ke `/usr/local/sbin/gisnet-secure-ssh`. Semua perintah di bawah bisa dijalankan langsung, misalnya `gisnet-secure-ssh status`.

> ⚠️ **Jangan tutup sesi SSH yang sedang dipakai** sebelum Anda berhasil login baru dengan kunci di terminal lain.

### Opsi pemasangan

```bash
sudo bash gisnet-secure-ssh.sh \
  --key "ssh-ed25519 AAAA... nama-pc" \
  --whitelist "203.0.113.5 10.0.0.0/8"
```

| Opsi | Arti |
|---|---|
| `--key "<kunci>"` | kunci publik SSH (boleh diulang untuk beberapa kunci) |
| `--whitelist "<ip ...>"` | IP/subnet yang tidak pernah diblokir, dipisah spasi |
| `--user <nama>` | pasang kunci juga untuk user lain selain root (boleh diulang) |
| `--keep-password` | login password SSH **tetap** aktif |
| `--ssh-port <N>` | tambahkan port SSH baru (port lama tetap dibuka) |
| `--no-auto-update` | jangan pasang update keamanan otomatis |
| `--no-web-jail` | jangan pasang jail pemindai website |
| `--report-url <url> --report-token <token>` | kirim status ke aplikasi pemantau tiap 5 menit |
| `--allow-reboot` / `--no-allow-reboot` | izinkan / tolak reboot dari aplikasi (tanpa opsi ini: ditanyakan) |
| `--no-service-jails` | jangan pasang jail FTP/email yang terdeteksi |
| `--no-shared-blocklist` | jangan terima blokir bersama dari aplikasi |
| `--dry-run` | tampilkan rencana & isi file konfigurasi, tanpa mengubah apa pun |
| `-h`, `--help` | bantuan |

Menjalankan pemasangan ulang aman: whitelist lama dipertahankan, kunci yang sudah ada tidak digandakan, dan opsi pemasangan sebelumnya (mis. `--keep-password`, `--no-web-jail`) diingat.

## Perintah harian

| Perintah | Arti |
|---|---|
| `gisnet-secure-ssh menu` | menu interaktif semua fitur |
| `gisnet-secure-ssh status` | ringkasan: fail2ban, jumlah blokir per jail, whitelist, pengaturan SSH, update otomatis, kesehatan, port berbahaya, proses mencurigakan, login SSH terakhir, 10 blokir terakhir |
| `gisnet-secure-ssh banned` | daftar IP yang sedang diblokir |
| `gisnet-secure-ssh ban <ip>` | blokir IP secara manual (port SSH). IP yang ada di whitelist ditolak |
| `gisnet-secure-ssh unban <ip>` | buka blokir satu IP; `unban all` = buka semua |
| `gisnet-secure-ssh whitelist` | kelola whitelist (lihat bagian di bawah) |
| `gisnet-secure-ssh key` | kelola kunci SSH (lihat bagian di bawah) |
| `gisnet-secure-ssh port <N>` | ganti port SSH dengan aman (lihat bagian di bawah) |
| `gisnet-secure-ssh restore` | kembalikan pengaturan dari cadangan terakhir |
| `gisnet-secure-ssh report` | kirim status ke aplikasi pemantau |
| `gisnet-secure-ssh checks` | hasil pemeriksaan server (JSON) |
| `gisnet-secure-ssh update` | perbarui skrip ke versi terbaru & pasang ulang dengan pengaturan sama (`--check` = cek saja) |

### Memperbarui skrip (mulai v2.5)

```bash
gisnet-secure-ssh update --check   # lihat versi terpasang & terbaru
gisnet-secure-ssh update           # unduh, ganti, pasang ulang (kunci, whitelist, port, laporan & izin tetap)
```

- File yang diunduh dicek dulu (harus skrip yang valid). Versi lama disimpan di `/etc/gisnet-secure-ssh/gisnet-secure-ssh.prev`.
- Repo private: `GH_TOKEN=<token read-only> gisnet-secure-ssh update`.
- Versi sebelum 2.5 belum punya perintah ini: unduh ulang skrip sekali, pasang ulang (Enter di semua pertanyaan), setelah itu cukup `update`.
- Bisa juga dari aplikasi (tombol **Perbarui skrip**), bila server mengizinkan: `gisnet-secure-ssh report allow-update on`.

### Pemeriksaan server (mulai v2.5)

Ikut di `status` dan di laporan ke aplikasi:

- **Kesehatan**: load CPU, RAM, swap, disk.
- **Port berbahaya terbuka**: layanan yang mendengarkan di alamat publik, mis. MySQL/MariaDB 3306, Redis 6379, GenieACS NBI 7557, MongoDB, Docker API, Webmin. Bila memang perlu terbuka (mis. hanya untuk server tertentu lewat firewall), tandai aman di aplikasi.
- **Proses mencurigakan**: nama penambang kripto yang dikenal (xmrig, kdevtmpfsi, kinsing, ...), program yang berjalan dari `/tmp`, `/var/tmp`, `/dev/shm`, dan proses yang memakai CPU ≥90% selama 30 menit lebih.
- **Login SSH** 7 hari terakhir: kapan, user, dari IP mana, metode, dan nama kunci bila cocok.

### Blokir bersama (mulai v2.5)

IP yang menyerang SSH di salah satu server GISNET ikut diblokir di server lain (jail `gisnet-shared`, port SSH saja, 24 jam). Daftarnya datang dari aplikasi pemantau di balasan laporan; IP whitelist semua server dan IP privat tidak pernah ikut.

```bash
gisnet-secure-ssh report shared-blocklist off   # matikan
gisnet-secure-ssh report shared-blocklist on    # nyalakan lagi
```

### Whitelist

```bash
gisnet-secure-ssh whitelist                          # menu: lihat, tambah, hapus
gisnet-secure-ssh whitelist list
gisnet-secure-ssh whitelist add 203.0.113.5 10.0.0.0/8
gisnet-secure-ssh whitelist remove 203.0.113.5       # atau nomor urutnya: remove 3
```

Perubahan langsung berlaku (fail2ban dimuat ulang) dan IP yang baru ditambahkan langsung dibuka blokirnya. `127.0.0.1/8` dan `::1` bawaan, tidak bisa dihapus.

### Kunci SSH

```bash
gisnet-secure-ssh key list                           # daftar kunci root + sidik jari
gisnet-secure-ssh key add "ssh-ed25519 AAAA... laptop-baru"
gisnet-secure-ssh key remove 2                       # nomor atau nama kunci
gisnet-secure-ssh key list --user deploy             # user lain
```

Kunci **terakhir tidak bisa dihapus** selama login password mati, supaya server tidak terkunci.

### Ganti port SSH (dua langkah)

```bash
gisnet-secure-ssh port 2269                # 1. tambah port 2269, port lama TETAP dibuka
ssh -p 2269 root@<ip-server>               # 2. coba login di terminal lain
gisnet-secure-ssh port 2269 --remove-old   # 3. bila berhasil, tutup port lama
```

Skrip otomatis membuka port di **firewalld / ufw**, mendaftarkannya di **SELinux** (`semanage port`), menangani `ssh.socket` di Ubuntu baru, dan memperbarui port jail fail2ban.

### Kembalikan dari cadangan

```bash
gisnet-secure-ssh restore                                         # cadangan terakhir
gisnet-secure-ssh restore /root/gisnet-secure-ssh-backup-20261029-130000
```

Setiap kali skrip mengubah file, salinannya disimpan di `/root/gisnet-secure-ssh-backup-<waktu>/` beserta `MANIFEST`. Restore mengembalikan file lama **dan menghapus file yang baru dibuat skrip**, lalu memuat ulang SSH & fail2ban.

### Laporan ke aplikasi pemantau

Server bisa melapor statusnya (fail2ban, jumlah blokir, pengaturan SSH, update otomatis, blokir terakhir) ke aplikasi tiap 5 menit:

```bash
gisnet-secure-ssh report setup <url-laporan> <token>   # pasang (cron tiap 5 menit)
gisnet-secure-ssh report                               # kirim sekarang
gisnet-secure-ssh report json                          # lihat isi laporan
gisnet-secure-ssh report off                           # matikan
```

URL dan token didapat dari aplikasi pemantau. Token disimpan di `/etc/gisnet-secure-ssh/report.conf` (hanya bisa dibaca root). Isi laporan berupa JSON yang dikirim dengan `Authorization: Bearer <token>`. Laporan tidak memuat kunci atau password.

#### Langkah lengkap: server baru sampai tampil di aplikasi

```bash
# 1. Pasang skrip (lihat dulu rencananya dengan --dry-run)
curl -fsSL https://raw.githubusercontent.com/hadynett/gis-secured/main/gisnet-secure-ssh.sh -o gisnet-secure-ssh.sh
sudo bash gisnet-secure-ssh.sh --dry-run
sudo bash gisnet-secure-ssh.sh

# 2. Di aplikasi: menu Keamanan Server > Tambah Server, isi nama, lalu salin perintah yang muncul:
gisnet-secure-ssh report setup <url-laporan> <token>
```

Di langkah 2 skrip bertanya **"Izinkan reboot dari aplikasi? [y/N]"** dan **"Izinkan update skrip dari aplikasi? [y/N]"**. Jawab `y` supaya tombol **Reboot** di kartu server langsung aktif, atau Enter untuk menolak. Kartu server muncul di aplikasi begitu langkah 2 selesai.

Tanpa pertanyaan: tambahkan `--allow-reboot` (izinkan) atau `--no-allow-reboot` (tolak), mis. `gisnet-secure-ssh report setup <url> <token> --allow-reboot`. Izin bisa diubah kapan saja dengan `report allow-reboot on|off`.

#### Memperbarui server yang sudah terpasang

Pasang ulang dengan skrip terbaru. Kunci dan whitelist yang sudah ada tetap dipakai: cukup tekan **Enter** di kedua pertanyaan. Pengaturan laporan juga tetap.

```bash
rm -f gisnet-secure-ssh.sh
curl -fsSL https://raw.githubusercontent.com/hadynett/gis-secured/main/gisnet-secure-ssh.sh -o gisnet-secure-ssh.sh
bash gisnet-secure-ssh.sh --version        # pastikan versi terbaru (GitHub kadang telat ±5 menit)
sudo bash gisnet-secure-ssh.sh
gisnet-secure-ssh report allow-reboot on   # bila ingin reboot dari aplikasi (v2.3+), bila belum diizinkan
```

#### Reboot dari aplikasi (opsional, mulai v2.3)

Aplikasi pemantau bisa meminta server **reboot sekarang**, **reboot jam 00.00**, atau **membatalkan jadwal reboot**. Permintaan ikut di balasan laporan berikutnya (maksimal 5 menit), jadi aplikasi tidak pernah masuk ke server.

```bash
gisnet-secure-ssh report allow-reboot on    # izinkan (atau jawab y saat report setup)
gisnet-secure-ssh report allow-reboot off   # cabut izin
gisnet-secure-ssh report allow-reboot       # lihat status
```

- Default **tidak diizinkan**. Tanpa izin, permintaan dari aplikasi diabaikan.
- Hanya tiga perintah tetap itu yang dijalankan (`shutdown -r +1`, `shutdown -r 00:00`, `shutdown -c`). Isi lain di balasan aplikasi tidak pernah dijalankan.
- Laporan juga memuat apakah server **perlu reboot** (ada kernel baru dari update otomatis) dan jadwal reboot yang sedang berjalan.

## Yang dipasang

**fail2ban** (`/etc/fail2ban/jail.d/gisnet.local`):

- `sshd`: mode *aggressive*, blokir **24 jam** setelah 5x gagal dalam 10 menit;
- `recidive`: IP yang diblokir 3x dalam sehari diblokir **1 minggu**;
- `gisnet-scan` (bila ada nginx/apache): pemindai file rahasia (`.env`, `wp-login.php`, `phpmyadmin`, `.git/`, ...) 5x diblokir **6 jam**, **hanya port 80/443**;
- semua blokir **hanya ke port yang diserang**, aman untuk IP NAT bersama;
- aksi blokir menyesuaikan firewall yang ada: firewalld, nftables, atau iptables.

**SSH** (`/etc/ssh/sshd_config.d/00-gisnet.conf`, atau bagian atas `sshd_config` bila tidak memakai `Include`):

```
Port 22
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
```

Hanya opsi yang dikenali versi OpenSSH di server tersebut yang ditulis.

**Update keamanan otomatis**: `unattended-upgrades` (Debian/Ubuntu), `dnf-automatic` hanya paket keamanan (Alma/Rocky/RHEL 8+/Fedora), `yum-cron` (CentOS 7). Distro lain dilewati. Penjelasan lengkap ada di bagian berikut.

## Update keamanan otomatis

Server memasang **perbaikan keamanan sendiri setiap hari**, tanpa perlu login dan menjalankan `apt upgrade` manual.

**Kenapa perlu:** celah keamanan baru ditemukan hampir tiap minggu (OpenSSH, OpenSSL, kernel, dll.). Debian/Ubuntu cepat merilis perbaikannya, tetapi server tetap rawan sampai perbaikan itu dipasang. Server yang jarang disentuh biasanya tertinggal berbulan-bulan, dan celah lama seperti ini yang paling sering dipakai penyerang.

**Cara kerjanya (Debian/Ubuntu):**

- Sekali sehari server memeriksa paket baru dari **repo resmi distro** (perbaikan keamanan & perbaikan bug stabil), lalu langsung memasangnya.
- **Tidak** menaikkan versi distro (mis. Debian 13 → 14). Itu tetap manual.
- **Tidak** menyentuh repo pihak lain (mis. repo vendor aplikasi). Paket dari repo itu tetap diperbarui manual.
- **Tidak** me-restart server. Bila ada update kernel, kernel baru aktif setelah reboot manual di waktu yang aman.
- Layanan yang paketnya diperbarui kadang ikut restart sebentar (hitungan detik).

Pada Alma/Rocky/RHEL, `dnf-automatic` diatur hanya memasang **paket keamanan** (`upgrade_type = security`).

**Perintah yang berguna (Debian/Ubuntu):**

```bash
ls /var/log/unattended-upgrades/                                    # catatan apa saja yang sudah dipasang
tail /var/log/unattended-upgrades/unattended-upgrades.log           # riwayat terakhir
unattended-upgrade --dry-run -d                                     # lihat apa yang akan dipasang, tanpa memasang
ls /var/run/reboot-required 2>/dev/null && echo "perlu reboot"      # ada update yang butuh reboot?
```

Alma/Rocky/RHEL: `systemctl list-timers 'dnf-automatic*'` dan `journalctl -u dnf-automatic.service`.

**Mematikan:**

- Saat pemasangan: tambahkan `--no-auto-update`.
- Setelah terpasang (Debian/Ubuntu): ubah kedua `"1"` menjadi `"0"` di `/etc/apt/apt.conf.d/20auto-upgrades`.
- Alma/Rocky/RHEL: `systemctl disable --now dnf-automatic.timer`.

Saran: biarkan aktif. Yang dipasang hanya perbaikan resmi distro, jadi risikonya kecil, sedangkan manfaatnya besar untuk server yang terbuka ke internet.

**Catatan:** bila `apt` menampilkan peringatan seperti `Signing key ... SHA1 is not considered secure` untuk repo pihak lain, itu masalah repo tersebut (kuncinya masih SHA1, ditolak Debian 13 sejak 2026-02-01), bukan skrip ini. Paket dari repo itu tidak ikut ter-update sampai vendornya memperbarui kunci. Update resmi Debian tetap berjalan normal.

## Pengaman

- Password SSH baru dimatikan **setelah** kunci terpasang & terverifikasi. Bila gagal, password tetap aktif.
- Semua file yang diubah dicadangkan (`/root/gisnet-secure-ssh-backup-<waktu>/` + `MANIFEST`), bisa dikembalikan dengan `restore`.
- Konfigurasi diuji dulu (`sshd -t`, `fail2ban-client -t`). Bila tidak valid, otomatis dikembalikan.
- Port SSH baru tidak pernah langsung menggantikan port lama; port lama ditutup hanya dengan `--remove-old`.
- IP whitelist yang sedang terblokir langsung dibuka; IP whitelist tidak bisa diblokir manual.
