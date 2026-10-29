# gisnet-secure-ssh

Satu skrip untuk mengamankan SSH server Linux:

- memasang **kunci publik SSH** Anda ke root (ditanyakan saat dijalankan);
- memasang & menyalakan **fail2ban** (jail `sshd` mode *aggressive* + *recidive*);
- **whitelist** IP/subnet yang tidak pernah diblokir (ditanyakan saat dijalankan);
- **mengetatkan SSH**: login hanya dengan kunci, password dimatikan, root hanya boleh dengan kunci.

Mendukung **Debian, Ubuntu, AlmaLinux / Rocky / RHEL / CentOS / Fedora, openSUSE, Arch, Alpine**.

## Cara pakai

Login ke server sebagai root (atau pakai `sudo`), lalu:

```bash
curl -fsSL https://raw.githubusercontent.com/hadynett/fail2ban/main/gisnet-secure-ssh.sh -o gisnet-secure-ssh.sh
sudo bash gisnet-secure-ssh.sh
```

Skrip akan bertanya:

1. **Kunci publik SSH**: tempel isi file `.pub` Anda (diawali `ssh-ed25519` / `ssh-rsa` / `ecdsa-sha2-...`). Bisa lebih dari satu kunci, satu per baris; Enter pada baris kosong untuk selesai.
2. **Whitelist**: IP/subnet yang tidak boleh diblokir, misalnya IP kantor (pisahkan dengan spasi). Enter untuk melewati.

> ⚠️ **Jangan tutup sesi SSH yang sedang dipakai** sebelum Anda berhasil login baru dengan kunci di terminal lain.

### Tanpa pertanyaan (otomatis)

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
| `--keep-password` | pasang kunci & fail2ban, tetapi login password SSH **tetap** aktif |
| `-h`, `--help` | bantuan |

## Kelola whitelist (lihat / tambah / hapus)

Setelah terpasang, whitelist bisa dikelola kapan saja dengan skrip yang sama:

```bash
sudo bash gisnet-secure-ssh.sh whitelist
```

Menu interaktif muncul:

```
Whitelist fail2ban (/etc/fail2ban/jail.d/gisnet.local):
   1. 127.0.0.1/8  (bawaan, tidak bisa dihapus)
   2. ::1  (bawaan, tidak bisa dihapus)
   3. 203.0.113.5

  1) Tambah IP    2) Hapus IP    3) Keluar
Pilih [1-3]:
```

Atau langsung dengan perintah:

| Perintah | Arti |
|---|---|
| `whitelist list` | lihat daftar whitelist |
| `whitelist add 203.0.113.5 10.0.0.0/8` | tambah satu atau beberapa IP/subnet |
| `whitelist remove 203.0.113.5` | hapus IP (boleh juga nomor urutnya, mis. `remove 3`) |

Contoh: `sudo bash gisnet-secure-ssh.sh whitelist add 203.0.113.5`

Perubahan langsung berlaku: fail2ban dimuat ulang, dan IP yang baru ditambahkan langsung dibuka blokirnya. Salinan file sebelum diubah disimpan sebagai `gisnet.local.bak-<waktu>`.

## Yang dipasang

**fail2ban** (`/etc/fail2ban/jail.d/gisnet.local`):

- `sshd`: mode *aggressive*, blokir **24 jam** setelah 5x gagal dalam 10 menit;
- `recidive`: IP yang diblokir 3x dalam sehari diblokir **1 minggu**;
- semua blokir **hanya ke port SSH** (port dideteksi otomatis), aman untuk IP NAT bersama;
- aksi blokir menyesuaikan firewall yang ada: firewalld, nftables, atau iptables.

**SSH** (`/etc/ssh/sshd_config.d/00-gisnet.conf`, atau bagian atas `sshd_config` bila tidak memakai `Include`):

```
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
```

Hanya opsi yang dikenali versi OpenSSH di server tersebut yang ditulis.

## Pengaman

- Password SSH baru dimatikan **setelah** kunci terpasang & terverifikasi. Bila gagal, password tetap aktif.
- Semua file yang diubah dicadangkan ke `/root/gisnet-secure-ssh-backup-<waktu>/`.
- Konfigurasi diuji dulu (`sshd -t`, `fail2ban-client -t`). Bila tidak valid, otomatis dikembalikan.
- IP whitelist yang sedang terblokir langsung dibuka.

## Mengembalikan (bila perlu)

```bash
ls /root/gisnet-secure-ssh-backup-*/
cp /root/gisnet-secure-ssh-backup-<waktu>/_etc_ssh_sshd_config /etc/ssh/sshd_config
rm -f /etc/ssh/sshd_config.d/00-gisnet.conf
systemctl reload sshd   # atau: systemctl reload ssh
```

Buka blokir IP: `fail2ban-client unban <ip>` · Lihat status: `fail2ban-client status sshd`
