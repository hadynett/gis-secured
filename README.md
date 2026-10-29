# gisnet-secure-ssh

Satu skrip untuk mengamankan SSH server Linux, lalu mengelolanya sehari-hari:

- memasang **kunci publik SSH** Anda ke root (ditanyakan saat dijalankan);
- memasang & menyalakan **fail2ban** (jail `sshd` mode *aggressive* + *recidive*);
- **whitelist** IP/subnet yang tidak pernah diblokir;
- **mengetatkan SSH**: login hanya dengan kunci, password dimatikan, root hanya boleh dengan kunci;
- **update keamanan otomatis** (unattended-upgrades / dnf-automatic / yum-cron);
- **jail pemindai website** bila ada nginx/apache (blokir hanya port web, 6 jam);
- perintah harian: `status`, `banned`, `ban`/`unban`, `whitelist`, `key`, `port`, `restore`, `report`, `menu`.

Mendukung **Debian, Ubuntu, AlmaLinux / Rocky / RHEL / CentOS / Fedora, openSUSE, Arch, Alpine**.

## Cara pakai

Login ke server sebagai root (atau pakai `sudo`), lalu:

```bash
curl -fsSL https://raw.githubusercontent.com/hadynett/fail2ban/main/gisnet-secure-ssh.sh -o gisnet-secure-ssh.sh
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
| `--dry-run` | tampilkan rencana & isi file konfigurasi, tanpa mengubah apa pun |
| `-h`, `--help` | bantuan |

Menjalankan pemasangan ulang aman: whitelist lama dipertahankan, kunci yang sudah ada tidak digandakan.

## Perintah harian

| Perintah | Arti |
|---|---|
| `gisnet-secure-ssh menu` | menu interaktif semua fitur |
| `gisnet-secure-ssh status` | ringkasan: fail2ban, jumlah blokir per jail, whitelist, pengaturan SSH, update otomatis, 10 blokir terakhir |
| `gisnet-secure-ssh banned` | daftar IP yang sedang diblokir |
| `gisnet-secure-ssh ban <ip>` | blokir IP secara manual (port SSH). IP yang ada di whitelist ditolak |
| `gisnet-secure-ssh unban <ip>` | buka blokir satu IP; `unban all` = buka semua |
| `gisnet-secure-ssh whitelist` | kelola whitelist (lihat bagian di bawah) |
| `gisnet-secure-ssh key` | kelola kunci SSH (lihat bagian di bawah) |
| `gisnet-secure-ssh port <N>` | ganti port SSH dengan aman (lihat bagian di bawah) |
| `gisnet-secure-ssh restore` | kembalikan pengaturan dari cadangan terakhir |
| `gisnet-secure-ssh report` | kirim status ke aplikasi pemantau |

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

**Update keamanan otomatis**: `unattended-upgrades` (Debian/Ubuntu), `dnf-automatic` hanya paket keamanan (Alma/Rocky/RHEL 8+/Fedora), `yum-cron` (CentOS 7). Distro lain dilewati.

## Pengaman

- Password SSH baru dimatikan **setelah** kunci terpasang & terverifikasi. Bila gagal, password tetap aktif.
- Semua file yang diubah dicadangkan (`/root/gisnet-secure-ssh-backup-<waktu>/` + `MANIFEST`), bisa dikembalikan dengan `restore`.
- Konfigurasi diuji dulu (`sshd -t`, `fail2ban-client -t`). Bila tidak valid, otomatis dikembalikan.
- Port SSH baru tidak pernah langsung menggantikan port lama; port lama ditutup hanya dengan `--remove-old`.
- IP whitelist yang sedang terblokir langsung dibuka; IP whitelist tidak bisa diblokir manual.
