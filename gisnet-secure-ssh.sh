#!/usr/bin/env bash
# =============================================================================
#  gisnet-secure-ssh.sh v2 -- pengamanan SSH server Linux dalam satu skrip
#
#  Mendukung: Debian, Ubuntu, AlmaLinux/Rocky/RHEL/CentOS, Fedora, openSUSE,
#  Arch, Alpine (deteksi otomatis lewat /etc/os-release).
#
#  PEMASANGAN (sebagai root):
#     bash gisnet-secure-ssh.sh                   # interaktif: tanya kunci & whitelist
#     bash gisnet-secure-ssh.sh --dry-run         # lihat rencana tanpa mengubah apa pun
#     bash gisnet-secure-ssh.sh --key "ssh-ed25519 AAAA... nama" --whitelist "203.0.113.5"
#   Opsi pemasangan:
#     --key "<kunci>"        kunci publik SSH (boleh diulang)
#     --whitelist "<ip ..>"  IP/subnet yang tidak pernah diblokir (dipisah spasi)
#     --user <nama>          pasang kunci juga untuk user lain (boleh diulang)
#     --keep-password        login password SSH tetap aktif
#     --ssh-port <N>         tambahkan port SSH baru (port lama tetap dibuka)
#     --no-auto-update       jangan pasang update keamanan otomatis
#     --no-web-jail          jangan pasang jail pemindai web (nginx/apache)
#     --report-url <url> --report-token <token>   kirim status ke aplikasi pemantau
#     --allow-reboot / --no-allow-reboot   izinkan / tolak reboot dari aplikasi (tanpa: ditanya)
#     --allow-all            izinkan SEMUA perintah dari aplikasi: reboot, update, port, whitelist, DNS, kunci SSH
#     --no-service-jails     jangan pasang jail FTP/email yang terdeteksi
#     --no-shared-blocklist  jangan terima blokir bersama dari aplikasi
#     --dry-run              tampilkan rencana saja
#
#  PERINTAH (setelah terpasang, tersedia juga sebagai: gisnet-secure-ssh <perintah>):
#     menu                                  menu interaktif semua fitur
#     status                                ringkasan keamanan server
#     banned                                daftar IP yang sedang diblokir
#     ban <ip>  /  unban <ip|all>           blokir / buka blokir manual
#     whitelist [list|add|remove] [ip ..]   kelola IP yang tidak pernah diblokir
#     key [list|add|remove] [kunci|nomor] [--user <nama>]   kelola kunci SSH
#     port <N> [--remove-old]               tambah port SSH; --remove-old menutup port lama
#     restore [folder-cadangan]             kembalikan pengaturan dari cadangan
#     report [now|setup <url> <token> [--allow-reboot]|off]   laporan status ke aplikasi
#     report allow-reboot on|off             izinkan reboot (sekarang / 00.00 / batal) dari aplikasi
#     report allow-update on|off             izinkan update skrip dari aplikasi
#     report allow-port on|off               izinkan ganti port SSH dari aplikasi (dua langkah)
#     report allow-whitelist on|off          izinkan ubah whitelist dari aplikasi (otomatis bila allow-port on)
#     report allow-dns on|off                izinkan ganti DNS dari aplikasi (otomatis bila allow-port on)
#     report allow-key on|off                izinkan tambah/hapus kunci SSH root dari aplikasi (izin terpisah)
#     report allow-all on|off                semua izin di atas sekaligus (juga: report setup ... --allow-all)
#     report shared-blocklist on|off         blokir bersama: IP penyerang dari server GISNET lain
#     dns [show|set <ip> .. (maks 3, 4 bila systemd-resolved)]  lihat / ganti DNS server (diuji, batal otomatis bila gagal)
#     baseline [show|accept]                 jejak penyusup: cron/layanan/user/kunci/SUID/port baru sejak kondisi normal
#     restrict [list|add <port>|remove <port>]   batasi port berbahaya (mis. 3306) ke server ini sendiri
#     rootkit-scan                           pindai rootkit sekarang (otomatis seminggu sekali, rkhunter/chkrootkit)
#     update [--check] [--force]             perbarui skrip ke versi terbaru, pengaturan tetap
#     checks                                 pemeriksaan: kesehatan, port terbuka, proses, login SSH (JSON)
#
#  PENGAMAN: password SSH baru dimatikan setelah kunci terverifikasi; semua file
#  dicadangkan (/root/gisnet-secure-ssh-backup-<waktu>/); konfigurasi diuji
#  sebelum dipakai; semua blokir HANYA port yang diserang (aman untuk IP NAT
#  bersama). JANGAN tutup sesi SSH yang sedang dipakai sebelum mencoba login
#  baru di terminal lain.
# =============================================================================
set -euo pipefail
# Cron hanya punya PATH=/usr/bin:/bin -- tanpa ini ufw, shutdown, semanage, nft (di /usr/sbin)
# dianggap tidak ada saat perintah datang dari aplikasi (ditemukan 2026-10-29 di server NMS).
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"

SCRIPT_VERSION='2.21'
SELF_INSTALL=/usr/local/sbin/gisnet-secure-ssh
STATE_DIR=/etc/gisnet-secure-ssh
REPORT_CONF="$STATE_DIR/report.conf"
ALLOW_REBOOT="$STATE_DIR/allow-reboot"
INSTALL_CONF="$STATE_DIR/install.conf"     # opsi pemasangan, dipakai ulang oleh "update"
WEB_PROXY_STATE="$STATE_DIR/web-proxy"     # cloudflare | proxy -- jail web dilewati
SHARED_OFF="$STATE_DIR/shared-blocklist-off"
ALLOW_UPDATE="$STATE_DIR/allow-update"
ALLOW_PORT="$STATE_DIR/allow-port"
# 2.9: whitelist & DNS dari aplikasi -- diizinkan oleh file sendiri, atau ikut izin port (lebih berisiko).
ALLOW_WHITELIST="$STATE_DIR/allow-whitelist"
ALLOW_DNS="$STATE_DIR/allow-dns"
ALLOW_KEY="$STATE_DIR/allow-key"            # kunci SSH root dari aplikasi -- SELALU izin terpisah (akses root penuh)
REPORT_IP_CACHE="$STATE_DIR/report-ip"      # IP aplikasi terakhir -- laporan tetap terkirim saat DNS mati
DNS_RESULT="$STATE_DIR/dns-result"          # hasil ganti DNS terakhir (dilaporkan ke aplikasi)
UPDATE_URL_DEFAULT='https://raw.githubusercontent.com/hadynett/gis-secured/main/gisnet-secure-ssh.sh'
JAIL=/etc/fail2ban/jail.d/gisnet.local
F2B_LOG=/var/log/fail2ban.log
SSHD_CONFIG=/etc/ssh/sshd_config
DROPIN_DIR=/etc/ssh/sshd_config.d
DROPIN=$DROPIN_DIR/00-gisnet.conf
WL_BUILTIN='127.0.0.1/8 ::1'

# ------------------------------------------------------------------ bantuan ---
c_ok()   { printf '\033[32m[OK]\033[0m %s\n' "$*"; }
c_info() { printf '\033[36m[..]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[33m[!!]\033[0m %s\n' "$*"; }
c_err()  { printf '\033[31m[XX]\033[0m %s\n' "$*" >&2; }
c_plan() { printf '\033[35m[rencana]\033[0m %s\n' "$*"; }
die()    { c_err "$*"; exit 1; }
have()   { command -v "$1" >/dev/null 2>&1; }
usage()  { awk 'NR>2 && /^# =+$/ {exit} NR>2 {sub(/^# ?/, ""); print}' "${BASH_SOURCE[0]:-$0}" 2>/dev/null; exit 0; }
lower()  { printf '%s' "$1" | tr 'A-Z' 'a-z'; }

valid_key() {
    case "$1" in
        ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*\ *|sk-ssh-ed25519@openssh.com\ *|sk-ecdsa-sha2-*\ *)
            [ -n "$(printf '%s' "$1" | awk '{print $2}')" ] ;;
        *) return 1 ;;
    esac
}
valid_ip() { # IPv4/IPv6, boleh /CIDR
    printf '%s' "$1" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$|^[0-9A-Fa-f:]+:[0-9A-Fa-f:.]*(/[0-9]{1,3})?$'
}
key_blob() { printf '%s' "$1" | awk '{print $2}'; }

# Pertanyaan dibaca dari terminal (/dev/tty) supaya tetap bisa dijawab walau
# skrip dijalankan lewat "curl ... | bash".
TTY=''
if [ -z "${GISNET_NONINTERACTIVE-}" ] && [ -r /dev/tty ] && { : < /dev/tty; } 2>/dev/null; then TTY=/dev/tty; fi
ask() { local reply=''; printf '%s' "$1" > /dev/tty; IFS= read -r reply < /dev/tty || true; printf '%s' "$reply"; }
confirm() { [ -n "$TTY" ] || return 0; case "$(lower "$(ask "$1 [y/N]: ")")" in y|ya|yes) return 0 ;; *) return 1 ;; esac; }
need_root() { [ "$(id -u)" -eq 0 ] || die "Jalankan sebagai root (sudo)."; }

# ------------------------------------------------------------- deteksi OS ---
detect_os() {
    # Dibaca di subshell: os-release juga punya VERSION/ID yang tidak boleh menimpa variabel skrip.
    OS_ID="$( . /etc/os-release 2>/dev/null; echo "${ID:-unknown}")"
    OS_NAME="$( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-}")"; OS_NAME="${OS_NAME:-$OS_ID}"
    PKG=''
    if have apt-get; then PKG=apt
    elif have dnf; then PKG=dnf
    elif have yum; then PKG=yum
    elif have zypper; then PKG=zypper
    elif have pacman; then PKG=pacman
    elif have apk; then PKG=apk
    fi
    HAS_SYSTEMD=0; [ -d /run/systemd/system ] && HAS_SYSTEMD=1
    SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
}
pkg_install() {
    case "$PKG" in
        # Repo pihak ketiga yang rusak (kunci kedaluwarsa, rilis dihapus) membuat `apt-get update`
        # gagal walau repo distro sehat -> tetap lanjut memasang dari daftar paket yang ada.
        apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq || c_warn "apt-get update bermasalah (ada repo pihak ketiga rusak) -- tetap mencoba memasang $*."
                DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${APT_NO_RECOMMENDS:+--no-install-recommends} "$@" ;;
        dnf)    dnf install -y -q "$@" ;;
        yum)    yum install -y -q "$@" ;;
        zypper) zypper --non-interactive install -y "$@" ;;
        pacman) pacman -Sy --noconfirm --needed "$@" ;;
        apk)    apk add --no-cache "$@" ;;
        *)      return 1 ;;
    esac
}
svc() { # svc <aksi> <nama...> -- coba beberapa nama layanan (ssh/sshd)
    local action="$1" name; shift
    for name in "$@"; do
        if [ "$HAS_SYSTEMD" -eq 1 ]; then
            systemctl cat "$name.service" >/dev/null 2>&1 && systemctl "$action" "$name" && return 0
        elif have rc-service && [ -e "/etc/init.d/$name" ]; then
            rc-service "$name" "$action" && return 0
        elif have service; then
            service "$name" "$action" >/dev/null 2>&1 && return 0
        fi
    done
    return 1
}
ssh_ports() { "$SSHD_BIN" -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un | paste -sd, - || true; }
ssh_reload() {
    # Ubuntu 22.10+ memakai ssh.socket: port dibaca saat soket dibuat ulang.
    if [ "$HAS_SYSTEMD" -eq 1 ] && systemctl is-active --quiet ssh.socket 2>/dev/null; then
        systemctl daemon-reload; systemctl restart ssh.socket; svc restart ssh sshd || true
    else
        svc reload ssh sshd || svc restart ssh sshd || c_warn "Gagal reload SSH -- jalankan: systemctl reload sshd (atau ssh)."
    fi
}
f2b_reload() { fail2ban-client reload >/dev/null 2>&1 && return 0; svc restart fail2ban || c_warn "Gagal memuat ulang fail2ban -- jalankan: fail2ban-client reload"; }

# --------------------------------------------------------------- cadangan ---
# Tiap file yang diubah dicatat di MANIFEST (path asli | file cadangan | ada/baru)
# supaya "restore" bisa mengembalikan persis -- termasuk menghapus file baru.
BACKUP_DIR=''
start_backup() {
    BACKUP_DIR="/root/gisnet-secure-ssh-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"; : > "$BACKUP_DIR/MANIFEST"
}
backup() {
    [ -n "$BACKUP_DIR" ] || start_backup
    local path="$1" name
    grep -q "^$path|" "$BACKUP_DIR/MANIFEST" 2>/dev/null && return 0
    name="$(printf '%s' "$path" | tr '/' '_')"
    if [ -e "$path" ]; then cp -a "$path" "$BACKUP_DIR/$name"; echo "$path|$name|ada" >> "$BACKUP_DIR/MANIFEST"
    else echo "$path||baru" >> "$BACKUP_DIR/MANIFEST"; fi
}

# ========================================================== PEMBUAT KONFIG ===
gen_recidive_filter() {
    cat <<'EOF'
# recidive khusus jail sshd (gisnet-secure-ssh.sh).
[Definition]
failregex = NOTICE\s+\[sshd\]\s+Ban\s+<HOST>\s*$
ignoreregex =
EOF
}
gen_scan_filter() {
    cat <<'EOF'
# Pemindai file rahasia website (.env, wp-login, phpmyadmin, .git, ...) di access log (format combined).
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "(?:GET|POST|HEAD|PUT) [^"]*(?:\.env|wp-login\.php|wp-admin|wp-config|xmlrpc\.php|phpmyadmin|pma/|\.git/|/vendor/phpunit|cgi-bin|\.aws/|\.ssh/|server-status|actuator/)[^"]*" (?:400|403|404|405)
ignoreregex =
EOF
}
gen_shared_filter() {
    cat <<'EOF'
# Blokir bersama antar-server (gisnet-secure-ssh.sh): diisi dari aplikasi lewat "fail2ban-client set gisnet-shared banip",
# tidak pernah dari log -- regex ini sengaja tidak pernah cocok.
[Definition]
failregex = ^GISNET-SHARED-NEVER-MATCHES <HOST>$
ignoreregex =
EOF
}
gen_jail() { # gen_jail <whitelist> <banaction> <ports> <sshd-log> [weblog] [shared 0|1] [blok-jail-layanan]
    local wl="$1" ba="$2" ports="$3" sshdlog="$4" weblog="${5-}" shared="${6:-0}" extra="${7-}"
    cat <<EOF
# fail2ban -- dipasang gisnet-secure-ssh.sh v$SCRIPT_VERSION ($(date '+%Y-%m-%d %H:%M'))
# Semua blokir HANYA port yang diserang (bukan semua port) -- aman untuk IP NAT bersama.
[DEFAULT]
ignoreip  = $wl
bantime   = 24h
findtime  = 10m
maxretry  = 5
banaction = $ba

[sshd]
enabled  = true
mode     = aggressive
port     = $ports
$sshdlog

# Diblokir berulang (3x sehari) -> 1 minggu, tetap hanya port SSH.
[recidive]
enabled   = true
filter    = gisnet-recidive-ssh
logpath   = $F2B_LOG
banaction = $ba
port      = $ports
bantime   = 1w
findtime  = 1d
maxretry  = 3
EOF
    if [ -n "$weblog" ]; then
        cat <<EOF

# Pemindai file rahasia website -- port web saja, blokir pendek (IP bisa bersama).
[gisnet-scan]
enabled  = true
port     = http,https
filter   = gisnet-scan
logpath  = $weblog
maxretry = 5
bantime  = 6h
EOF
    fi
    if [ "$shared" = 1 ]; then
        cat <<EOF

# Blokir bersama: IP penyerang SSH yang diblokir di server GISNET lain (dari aplikasi), port SSH saja.
[gisnet-shared]
enabled   = true
filter    = gisnet-shared
logpath   = $F2B_LOG
banaction = $ba
port      = $ports
maxretry  = 1
bantime   = 24h
EOF
    fi
    [ -n "$extra" ] && printf '\n%s\n' "$extra"
    return 0
}
# Jail bawaan fail2ban untuk layanan lain yang ditemukan di server (FTP, email).
service_jail_candidates() { # cetak "nama|blok" per baris kosong
    local backend='backend = systemd' maillog=''
    [ "${HAS_SYSTEMD:-0}" -eq 1 ] || backend='backend = auto'
    [ -f /var/log/mail.log ] && maillog=1
    svc_present() { [ -d "/etc/$1" ] || have "$1"; }
    if svc_present postfix; then
        printf '%s\n\n' "postfix-sasl|# Tebak password SMTP (postfix)
[postfix-sasl]
enabled = true
$([ -n "$maillog" ] && echo 'backend = auto' || echo "$backend")"
    fi
    if svc_present dovecot; then
        printf '%s\n\n' "dovecot|# Tebak password IMAP/POP3 (dovecot)
[dovecot]
enabled = true
$([ -n "$maillog" ] && echo 'backend = auto' || echo "$backend")"
    fi
    local ftp
    for ftp in vsftpd proftpd pure-ftpd; do
        if svc_present "$ftp" || [ -f "/etc/$ftp.conf" ]; then
            printf '%s\n\n' "$ftp|# Tebak password FTP ($ftp)
[$ftp]
enabled = true
$backend"
        fi
    done
    return 0
}
# Deteksi website di belakang Cloudflare / reverse proxy: log hanya berisi IP proxy, jadi jail web
# akan memblokir pengunjung asli. Hasil: cloudflare | proxy | (kosong = aman).
detect_web_proxy() { # detect_web_proxy <access-log>
    [ -f "$1" ] || return 0
    tail -n 2000 "$1" 2>/dev/null | awk '
        function ip2n(ip,  p) { split(ip, p, "."); return ((p[1]*256 + p[2])*256 + p[3])*256 + p[4] }
        function inr(n, cidr,  a, b, m) { split(cidr, a, "/"); b = ip2n(a[1]); m = 2^(32 - a[2]); return n >= b && n < b + m }
        BEGIN { n = split("173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22", cf, " ") }
        {
            ip = $1; total++
            if (ip ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {
                v = ip2n(ip)
                if (ip ~ /^(10\.|127\.|192\.168\.)/ || (v >= ip2n("172.16.0.0") && v < ip2n("172.32.0.0"))) { priv++; next }
                for (i = 1; i <= n; i++) if (inr(v, cf[i])) { cfc++; next }
            } else if (tolower(ip) ~ /^(2400:cb00|2606:4700|2803:f800|2405:b500|2405:8100|2a06:98c[0-7]|2c0f:f248):/) { cfc++ }
            else if (ip == "::1") { priv++ }
        }
        END { if (total < 20) exit; if (cfc * 2 >= total) print "cloudflare"; else if (priv * 2 >= total) print "proxy" }'
}
# Opsi pemasangan disimpan supaya "update" memasang ulang dengan pilihan yang sama.
save_install_conf() {
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    {
        printf 'SAVED_KEEP_PASSWORD=%q\n' "$KEEP_PASSWORD"
        printf 'SAVED_AUTO_UPDATE=%q\n' "$AUTO_UPDATE"
        printf 'SAVED_WEB_JAIL=%q\n' "$WEB_JAIL"
        printf 'SAVED_SERVICE_JAILS=%q\n' "$SERVICE_JAILS"
        printf 'SAVED_EXTRA_USERS=%q\n' "${EXTRA_USERS[*]-}"
    } > "$INSTALL_CONF"; chmod 600 "$INSTALL_CONF"
}
gen_ssh_settings() { # gen_ssh_settings <yes|no> -- hanya opsi yang dikenali OpenSSH ini
    local pw="$1" supported kw val
    supported="$("$SSHD_BIN" -T 2>/dev/null | awk '{print tolower($1)}')"
    printf '%s\n' \
        "PubkeyAuthentication yes" "PasswordAuthentication $pw" "KbdInteractiveAuthentication no" \
        "ChallengeResponseAuthentication no" "PermitEmptyPasswords no" "PermitRootLogin prohibit-password" \
        "MaxAuthTries 4" "LoginGraceTime 30" |
    while read -r kw val; do
        printf '%s\n' "$supported" | grep -qx "$(lower "$kw")" && printf '%s %s\n' "$kw" "$val"
    done
}
detect_banaction() {
    if [ "$HAS_SYSTEMD" -eq 1 ] && systemctl is-active --quiet firewalld 2>/dev/null; then echo firewallcmd-rich-rules
    elif have nft; then echo nftables-multiport
    elif have iptables; then echo iptables-multiport
    else echo nftables-multiport; fi
}
detect_sshd_log() {
    if [ "$HAS_SYSTEMD" -eq 1 ]; then echo 'backend  = systemd'; return; fi
    local f=/var/log/auth.log
    [ -f /var/log/secure ] && f=/var/log/secure
    [ ! -f /var/log/auth.log ] && [ ! -f /var/log/secure ] && [ -f /var/log/messages ] && f=/var/log/messages
    printf 'backend  = auto\nlogpath  = %s\n' "$f"
}
detect_weblog() {
    local f
    for f in /var/log/nginx/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do
        [ -f "$f" ] && { echo "$f"; return; }
    done
}
wl_current() { [ -f "$JAIL" ] && awk '/^[[:space:]]*ignoreip[[:space:]]*=/{sub(/^[^=]*=/, ""); print; exit}' "$JAIL" | tr ' \t' '\n\n' | sed '/^$/d' || true; }

# ================================================================ INSTALL ===
cmd_install() {
    local KEYS=() WL_INPUT='' WL_GIVEN=0 EXTRA_USERS=() KEEP_PASSWORD=0 NEW_PORT='' AUTO_UPDATE=1 WEB_JAIL=1 SERVICE_JAILS=1 DRY=0 R_URL='' R_TOKEN='' R_REBOOT=ask R_ALL=0 SHARED=''
    # Pemasangan ulang / update: mulai dari pilihan yang tersimpan, opsi di baris perintah tetap menang.
    if [ -f "$INSTALL_CONF" ]; then
        local SAVED_KEEP_PASSWORD=0 SAVED_AUTO_UPDATE=1 SAVED_WEB_JAIL=1 SAVED_SERVICE_JAILS=1 SAVED_EXTRA_USERS=''
        # shellcheck disable=SC1090
        . "$INSTALL_CONF"
        KEEP_PASSWORD="$SAVED_KEEP_PASSWORD"; AUTO_UPDATE="$SAVED_AUTO_UPDATE"; WEB_JAIL="$SAVED_WEB_JAIL"; SERVICE_JAILS="$SAVED_SERVICE_JAILS"
        local su; for su in $SAVED_EXTRA_USERS; do EXTRA_USERS+=("$su"); done
    fi
    while [ $# -gt 0 ]; do
        case "$1" in
            --key) KEYS+=("${2:?--key butuh nilai}"); shift 2 ;;
            --whitelist) WL_INPUT="${2-}"; WL_GIVEN=1; shift 2 ;;
            --user) EXTRA_USERS+=("${2:?--user butuh nilai}"); shift 2 ;;
            --keep-password) KEEP_PASSWORD=1; shift ;;
            --no-keep-password) KEEP_PASSWORD=0; shift ;;
            --auto-update) AUTO_UPDATE=1; shift ;;
            --web-jail) WEB_JAIL=1; shift ;;
            --no-service-jails) SERVICE_JAILS=0; shift ;;
            --service-jails) SERVICE_JAILS=1; shift ;;
            --shared-blocklist) SHARED=1; shift ;;
            --no-shared-blocklist) SHARED=0; shift ;;
            --ssh-port) NEW_PORT="${2:?--ssh-port butuh nilai}"; shift 2 ;;
            --no-auto-update) AUTO_UPDATE=0; shift ;;
            --no-web-jail) WEB_JAIL=0; shift ;;
            --report-url) R_URL="${2:?}"; shift 2 ;;
            --report-token) R_TOKEN="${2:?}"; shift 2 ;;
            --allow-reboot) R_REBOOT=yes; shift ;;
            --no-allow-reboot) R_REBOOT=no; shift ;;
            --allow-all) R_ALL=1; R_REBOOT=yes; shift ;;
            --dry-run) DRY=1; shift ;;
            -h|--help) usage ;;
            *) die "Opsi tidak dikenal: $1 (lihat --help)" ;;
        esac
    done
    need_root; detect_os
    [ -n "$PKG" ] || die "Pengelola paket tidak dikenali (butuh apt/dnf/yum/zypper/pacman/apk)."
    [ -f "$SSHD_CONFIG" ] || die "$SSHD_CONFIG tidak ditemukan (OpenSSH server belum terpasang?)."
    if [ -n "$NEW_PORT" ]; then [[ "$NEW_PORT" =~ ^[0-9]+$ ]] && [ "$NEW_PORT" -ge 1 ] && [ "$NEW_PORT" -le 65535 ] || die "Port tidak valid: $NEW_PORT"; fi
    if [ -n "$R_URL$R_TOKEN" ]; then [ -n "$R_URL" ] && [ -n "$R_TOKEN" ] || die "--report-url dan --report-token harus diisi keduanya."; fi
    c_info "Sistem: $OS_NAME ($PKG, $([ "$HAS_SYSTEMD" -eq 1 ] && echo systemd || echo tanpa systemd))"

    # --- kunci publik (root yang sudah punya kunci, mis. dari v1: Enter = pakai kunci yang ada)
    local EXISTING_KEYS
    EXISTING_KEYS="$(grep -cE '(^|[[:space:]])(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+) ' "$(key_file_of root)" 2>/dev/null || true)"; EXISTING_KEYS="${EXISTING_KEYS:-0}"
    if [ "${#KEYS[@]}" -eq 0 ]; then
        if [ -z "$TTY" ]; then
            [ "$EXISTING_KEYS" -gt 0 ] || die "Tidak ada terminal untuk bertanya -- berikan kunci lewat --key \"ssh-ed25519 AAAA...\"."
            c_info "Memakai $EXISTING_KEYS kunci root yang sudah terpasang."
        else
            echo
            echo "Tempel KUNCI PUBLIK SSH Anda (isi file .pub, diawali ssh-ed25519 / ssh-rsa / ecdsa-sha2-...)."
            if [ "$EXISTING_KEYS" -gt 0 ]; then
                echo "Root sudah punya $EXISTING_KEYS kunci -- tekan Enter saja untuk tetap memakainya, atau tempel kunci tambahan."
            else
                echo "Satu kunci per baris; tekan Enter pada baris kosong bila selesai."
            fi
            local line
            while :; do
                line="$(ask "Kunci publik #$(( ${#KEYS[@]} + 1 )): " | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
                if [ -z "$line" ]; then
                    { [ "${#KEYS[@]}" -gt 0 ] || [ "$EXISTING_KEYS" -gt 0 ]; } && break
                    c_warn "Minimal satu kunci publik."; continue
                fi
                if valid_key "$line"; then KEYS+=("$line"); c_ok "Kunci diterima (${line##* })."
                else c_warn "Bukan kunci publik SSH yang valid (pastikan isi file .pub, bukan kunci privat)."; fi
            done
            [ "${#KEYS[@]}" -eq 0 ] && c_ok "Memakai $EXISTING_KEYS kunci root yang sudah terpasang."
        fi
    fi
    local k; for k in ${KEYS[@]+"${KEYS[@]}"}; do valid_key "$k" || die "Kunci publik tidak valid: ${k:0:40}..."; done

    # --- whitelist
    if [ "$WL_GIVEN" -eq 0 ] && [ -n "$TTY" ]; then
        echo; echo "IP / subnet yang TIDAK BOLEH diblokir fail2ban (mis. IP kantor). Pisahkan dengan spasi."
        local wl_old; wl_old="$(wl_current | grep -vxF -e 127.0.0.1/8 -e ::1 | paste -sd' ' - || true)"
        if [ -n "$wl_old" ]; then
            echo "Whitelist yang sudah ada TETAP dipakai: $wl_old"
            WL_INPUT="$(ask "IP tambahan (Enter = tidak ada tambahan): ")"
        else
            WL_INPUT="$(ask "Whitelist (Enter untuk lewati): ")"
        fi
    fi
    local WL_EXTRA='' ip
    for ip in $(printf '%s' "$WL_INPUT" | tr ',' ' '); do valid_ip "$ip" || die "IP whitelist tidak valid: $ip"; WL_EXTRA="$WL_EXTRA $ip"; done
    for ip in $(wl_current); do case " $WL_BUILTIN $WL_EXTRA " in *" $ip "*) ;; *) WL_EXTRA="$WL_EXTRA $ip" ;; esac; done   # pertahankan whitelist lama
    local WHITELIST; WHITELIST="$WL_BUILTIN$WL_EXTRA"

    # --- rencana
    local PORTS BANACTION SSHDLOG WEBLOG='' PW=no
    PORTS="$(ssh_ports)"; [ -n "$PORTS" ] || PORTS=22
    [ -n "$NEW_PORT" ] && case ",$PORTS," in *",$NEW_PORT,"*) ;; *) PORTS="$PORTS,$NEW_PORT" ;; esac
    BANACTION="$(detect_banaction)"; SSHDLOG="$(detect_sshd_log)"
    [ "$WEB_JAIL" -eq 1 ] && WEBLOG="$(detect_weblog || true)"
    [ "$KEEP_PASSWORD" -eq 1 ] && PW=yes
    local WEB_PROXY=''
    if [ -n "$WEBLOG" ]; then
        WEB_PROXY="$(detect_web_proxy "$WEBLOG" || true)"
        if [ -n "$WEB_PROXY" ]; then
            c_warn "Website di belakang $([ "$WEB_PROXY" = cloudflare ] && echo Cloudflare || echo 'reverse proxy'): log hanya berisi IP proxy -- jail web DILEWATI supaya pengunjung asli tidak ikut terblokir."
            c_warn "Atur nginx/apache agar mencatat IP asli pengunjung (real_ip / mod_remoteip), lalu jalankan pemasangan lagi."
            WEBLOG=''
        fi
    fi
    [ -z "$SHARED" ] && { [ -f "$SHARED_OFF" ] && SHARED=0 || SHARED=1; }
    local SVC_JAILS='' SVC_NAMES=''
    if [ "$SERVICE_JAILS" -eq 1 ]; then
        SVC_JAILS="$(service_jail_candidates)"
        SVC_NAMES="$(printf '%s\n' "$SVC_JAILS" | awk -F'|' '/^[a-z-]+\|/{print $1}' | paste -sd' ' -)"
    fi

    if [ "$DRY" -eq 1 ]; then
        echo; c_info "MODE UJI (--dry-run): tidak ada yang diubah."
        c_plan "Pasang paket: fail2ban$([ "$PKG" = apt ] && [ "$HAS_SYSTEMD" -eq 1 ] && echo ' python3-systemd')$( { [ "$PKG" = dnf ] || [ "$PKG" = yum ]; } && [ "$OS_ID" != fedora ] && echo ' (dari EPEL)')"
        c_plan "Kunci publik untuk root${EXTRA_USERS[*]:+ & ${EXTRA_USERS[*]}}: $(for k in ${KEYS[@]+"${KEYS[@]}"}; do printf '%s ' "${k##* }"; done)$([ "$EXISTING_KEYS" -gt 0 ] && echo "(+ $EXISTING_KEYS kunci yang sudah ada)")"
        c_plan "Port SSH: $PORTS$([ -n "$NEW_PORT" ] && echo " (port baru $NEW_PORT, port lama tetap dibuka)")"
        c_plan "Login password SSH: $([ "$PW" = no ] && echo 'DIMATIKAN (kunci saja)' || echo 'tetap aktif')"
        c_plan "Update keamanan otomatis: $([ "$AUTO_UPDATE" -eq 1 ] && echo ya || echo tidak)"
        c_plan "Jail web: ${WEBLOG:-tidak ($([ -n "$WEB_PROXY" ] && echo "website di belakang $WEB_PROXY" || echo 'nginx/apache tidak ditemukan atau --no-web-jail'))}"
        c_plan "Jail layanan lain: ${SVC_NAMES:-tidak ada (FTP/email tidak ditemukan)}"
        c_plan "Blokir bersama antar-server: $([ "$SHARED" = 1 ] && echo 'ya (IP dari aplikasi, port SSH)' || echo tidak)"
        c_plan "Laporan ke aplikasi: ${R_URL:-tidak}"
        c_plan "Reboot dari aplikasi: $(case $R_REBOOT in yes) echo diizinkan ;; no) echo 'tidak diizinkan' ;; *) [ -n "$R_URL" ] && echo 'ditanyakan saat laporan diaktifkan' || echo 'ditanyakan saat report setup' ;; esac)"
        c_plan "Perintah tersedia setelah ini: $SELF_INSTALL"
        echo; echo "----- $JAIL -----"; gen_jail "$WHITELIST" "$BANACTION" "$PORTS" "$SSHDLOG" "$WEBLOG" "$SHARED" "$(printf '%s\n' "$SVC_JAILS" | sed 's/^[a-z-]*|//')"
        echo; echo "----- $DROPIN (atau awal $SSHD_CONFIG) -----"
        printf 'Port %s\n' $(printf '%s' "$PORTS" | tr ',' ' ')
        gen_ssh_settings "$PW"
        exit 0
    fi

    start_backup

    # --- 1. kunci SSH
    local KEY_OK=0 u
    install_keys root ${KEYS[@]+"${KEYS[@]}"} && KEY_OK=1
    for u in ${EXTRA_USERS[@]+"${EXTRA_USERS[@]}"}; do install_keys "$u" ${KEYS[@]+"${KEYS[@]}"} || true; done
    [ "$KEEP_PASSWORD" -eq 0 ] && [ "$KEY_OK" -ne 1 ] && { PW=yes; c_warn "Kunci root belum terverifikasi -- login password SSH TETAP aktif supaya Anda tidak terkunci."; }

    # --- 2. fail2ban
    c_info "Memasang fail2ban..."
    case "$PKG" in
        dnf|yum)
            if [ "$OS_ID" != fedora ] && ! rpm -q epel-release >/dev/null 2>&1; then pkg_install epel-release || c_warn "epel-release gagal dipasang."; fi
            pkg_install fail2ban || die "Gagal memasang fail2ban." ;;
        apt)
            pkg_install fail2ban || die "Gagal memasang fail2ban."
            [ "$HAS_SYSTEMD" -eq 1 ] && { pkg_install python3-systemd >/dev/null 2>&1 || true; } ;;
        *) pkg_install fail2ban || die "Gagal memasang fail2ban." ;;
    esac
    have fail2ban-client || die "fail2ban-client tidak ditemukan setelah instalasi."
    if ! have nft && ! have iptables && [ "$BANACTION" != firewallcmd-rich-rules ]; then
        c_info "Firewall belum ada -- memasang nftables..."
        pkg_install nftables >/dev/null 2>&1 || pkg_install iptables >/dev/null 2>&1 || true
        [ "$HAS_SYSTEMD" -eq 1 ] && systemctl enable --now nftables >/dev/null 2>&1 || true
        BANACTION="$(detect_banaction)"
    fi

    mkdir -p /etc/fail2ban/fail2ban.d /etc/fail2ban/filter.d /etc/fail2ban/jail.d
    backup /etc/fail2ban/fail2ban.d/gisnet.local
    printf '[Definition]\nlogtarget = %s\n' "$F2B_LOG" > /etc/fail2ban/fail2ban.d/gisnet.local   # recidive membaca file ini
    backup /etc/fail2ban/filter.d/gisnet-recidive-ssh.conf; gen_recidive_filter > /etc/fail2ban/filter.d/gisnet-recidive-ssh.conf
    if [ -n "$WEBLOG" ]; then backup /etc/fail2ban/filter.d/gisnet-scan.conf; gen_scan_filter > /etc/fail2ban/filter.d/gisnet-scan.conf; fi
    backup /etc/fail2ban/filter.d/gisnet-shared.conf; gen_shared_filter > /etc/fail2ban/filter.d/gisnet-shared.conf
    backup "$JAIL"
    touch "$F2B_LOG" 2>/dev/null || true
    # Jail layanan (FTP/email) dipasang satu per satu: yang membuat konfigurasi gagal diuji dilewati.
    local OK_SVC='' blk name
    while IFS= read -r -d $'\x1e' blk; do
        [ -n "$blk" ] || continue
        name="${blk%%|*}"; blk="${blk#*|}"
        gen_jail "$WHITELIST" "$BANACTION" "$PORTS" "$SSHDLOG" "$WEBLOG" "$SHARED" "$OK_SVC
$blk" > "$JAIL"
        if fail2ban-client -t >/dev/null 2>&1; then OK_SVC="$OK_SVC
$blk"; c_ok "Jail layanan $name dipasang."
        else c_warn "Jail layanan $name dilewati (log layanannya tidak terbaca fail2ban)."; fi
    done < <(printf '%s' "$SVC_JAILS" | awk 'BEGIN{RS=""; ORS="\x1e"} {print}')
    gen_jail "$WHITELIST" "$BANACTION" "$PORTS" "$SSHDLOG" "$WEBLOG" "$SHARED" "$OK_SVC" > "$JAIL"
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    if [ -n "$WEB_PROXY" ]; then echo "$WEB_PROXY" > "$WEB_PROXY_STATE"; else rm -f "$WEB_PROXY_STATE"; fi
    if [ "$SHARED" = 1 ]; then rm -f "$SHARED_OFF"; else touch "$SHARED_OFF"; fi
    if ! { fail2ban-client -t >/dev/null 2>&1 || fail2ban-client -d >/dev/null 2>&1; }; then
        c_err "Konfigurasi fail2ban tidak valid:"; fail2ban-client -d 2>&1 | tail -5 || true
        restore_from "$BACKUP_DIR" quiet; die "Pengaturan dikembalikan."
    fi
    if [ "$HAS_SYSTEMD" -eq 1 ]; then systemctl enable fail2ban >/dev/null 2>&1 || true; systemctl restart fail2ban
    elif have rc-update; then rc-update add fail2ban default >/dev/null 2>&1 || true; rc-service fail2ban restart
    else service fail2ban restart; fi
    sleep 2
    for ip in $WL_EXTRA; do fail2ban-client unban "$ip" >/dev/null 2>&1 || true; done
    c_ok "fail2ban aktif (aksi $BANACTION, port SSH $PORTS${WEBLOG:+, jail web $WEBLOG})."

    # --- 3. SSH ketat (+ port baru)
    apply_ssh "$PW" "$PORTS"   # port aktif selalu ditulis supaya tidak kembali ke 22
    # Semua port SSH selain 22 dipastikan terbuka di firewall (memperbaiki port yang dulu
    # ditambah dari aplikasi saat ufw/firewalld belum terdeteksi -- lihat PATH di atas).
    local sp; for sp in $(printf '%s' "$PORTS" | tr ',' ' '); do [ "$sp" = 22 ] || open_port "$sp"; done

    # --- 4. update keamanan otomatis
    [ "$AUTO_UPDATE" -eq 1 ] && setup_auto_update

    # --- 5. perintah sistem + laporan
    install_self
    save_install_conf
    [ "$R_ALL" -eq 1 ] && allow_all_set on   # sebelum laporan pertama, supaya aplikasi langsung melihat izinnya
    if [ -n "$R_URL" ]; then report_setup "$R_URL" "$R_TOKEN" "$R_REBOOT" "$([ "$R_ALL" -eq 1 ] && echo yes || echo ask)"
    elif [ "$R_REBOOT" != ask ]; then allow_reboot_choose "$R_REBOOT"; fi   # berlaku saat laporan nanti diaktifkan

    echo
    echo "================================================================"
    echo " SELESAI -- $(hostname)   (cadangan: $BACKUP_DIR)"
    echo "================================================================"
    cmd_status
    if [ "$PW" = no ]; then
        c_warn "JANGAN tutup sesi ini dulu. Coba login baru dengan kunci di terminal lain:"
        echo "       ssh -p ${PORTS##*,} root@<ip-server>"
        c_warn "Kalau gagal: gisnet-secure-ssh restore"
    fi
}

install_keys() { # install_keys <user> <kunci...> -- pasang & verifikasi
    local user="$1" home dir file key ok=1; shift
    home="$(awk -F: -v u="$user" '$1==u{print $6}' /etc/passwd)"
    [ -n "$home" ] && [ -d "$home" ] || { c_warn "User '$user' tidak ditemukan -- dilewati."; return 1; }
    dir="$home/.ssh"; file="$dir/authorized_keys"
    mkdir -p "$dir"; backup "$file"; touch "$file"
    for key in "$@"; do
        if grep -qF "$(key_blob "$key")" "$file"; then c_ok "Kunci ${key##* } sudah ada untuk $user."
        else printf '%s\n' "$key" >> "$file"; c_ok "Kunci ${key##* } dipasang untuk $user."; fi
    done
    chmod 700 "$dir"; chmod 600 "$file"; chown -R "$user":"$(id -gn "$user")" "$dir"
    have restorecon && { restorecon -R "$dir" >/dev/null 2>&1 || true; }   # SELinux
    for key in "$@"; do grep -qF "$(key_blob "$key")" "$file" || ok=0; done
    [ "$ok" -eq 1 ]
}

apply_ssh() { # apply_ssh <yes|no> [daftar-port-koma]
    local pw="$1" ports="${2-}" settings re
    settings="$(gen_ssh_settings "$pw")"
    printf '%s\n' "$settings" | grep -q '^PasswordAuthentication' || die "sshd tidak dikenali (sshd -T gagal)."
    backup "$SSHD_CONFIG"
    # sshd memakai nilai PERTAMA: baris sama di sshd_config (di luar Match) dikomentari.
    re='^(PubkeyAuthentication|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PermitEmptyPasswords|PermitRootLogin|MaxAuthTries|LoginGraceTime'"$([ -n "$ports" ] && echo '|Port')"')[[:space:]]'
    awk -v re="$re" 'BEGIN{m=0} /^[[:space:]]*Match[[:space:]]/{m=1} {l=$0; sub(/^[[:space:]]+/,"",l)} !m && l ~ re {print "# (gisnet-secure-ssh) " $0; next} {print}' \
        "$SSHD_CONFIG" > "$SSHD_CONFIG.gisnet-tmp" && cat "$SSHD_CONFIG.gisnet-tmp" > "$SSHD_CONFIG" && rm -f "$SSHD_CONFIG.gisnet-tmp"
    local body; body="$( [ -n "$ports" ] && printf 'Port %s\n' $(printf '%s' "$ports" | tr ',' ' '); printf '%s\n' "$settings")"
    if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
        mkdir -p "$DROPIN_DIR"; backup "$DROPIN"
        { echo "# pengetatan SSH (gisnet-secure-ssh.sh v$SCRIPT_VERSION)"; printf '%s\n' "$body"; } > "$DROPIN"; chmod 644 "$DROPIN"
    else
        sed -i '/^# >>> gisnet-secure-ssh/,/^# <<< gisnet-secure-ssh/d' "$SSHD_CONFIG"
        { echo "# >>> gisnet-secure-ssh v$SCRIPT_VERSION"; printf '%s\n' "$body"; echo "# <<< gisnet-secure-ssh"; cat "$SSHD_CONFIG"; } > "$SSHD_CONFIG.gisnet-tmp"
        cat "$SSHD_CONFIG.gisnet-tmp" > "$SSHD_CONFIG"; rm -f "$SSHD_CONFIG.gisnet-tmp"
    fi
    if ! "$SSHD_BIN" -t 2>/tmp/gisnet-sshd-test.err; then
        c_err "Konfigurasi SSH tidak valid:"; cat /tmp/gisnet-sshd-test.err >&2
        restore_from "$BACKUP_DIR" quiet; die "Pengaturan dikembalikan."
    fi
    ssh_reload
    c_ok "SSH diperketat (login password: $pw${ports:+, port $ports})."
}

open_port() { # buka port SSH baru di SELinux & firewall
    local p="$1"
    if [ "$p" != 22 ] && have getenforce && [ "$(getenforce 2>/dev/null)" != Disabled ]; then
        have semanage || pkg_install policycoreutils-python-utils >/dev/null 2>&1 || pkg_install policycoreutils-python >/dev/null 2>&1 || true
        semanage port -a -t ssh_port_t -p tcp "$p" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$p" 2>/dev/null || c_warn "SELinux: gagal mendaftarkan port $p."
    fi
    if [ "$HAS_SYSTEMD" -eq 1 ] && systemctl is-active --quiet firewalld 2>/dev/null; then
        if firewall-cmd -q --query-port="$p/tcp" 2>/dev/null; then c_info "firewalld: port $p sudah dibuka."
        else firewall-cmd -q --permanent --add-port="$p/tcp" && firewall-cmd -q --reload && c_ok "firewalld: port $p dibuka."; fi
    elif have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then
        # Port yang sudah punya aturan apa pun (mis. hanya dari IP tertentu) tidak diubah.
        if ufw status 2>/dev/null | awk 'NR>3{print $1}' | grep -qE "^$p(/tcp)?$"; then c_info "ufw: port $p sudah punya aturan."
        else ufw allow "$p/tcp" >/dev/null && c_ok "ufw: port $p dibuka."; fi
    elif have nft && nft list ruleset 2>/dev/null | grep -q 'hook input.*policy drop' && ! nft list ruleset 2>/dev/null | grep -qE "dport (\{[^}]*\b$p\b|$p\b)"; then
        c_warn "Firewall nftables menolak koneksi masuk dan belum ada aturan untuk port $p -- buka manual, mis.: nft add rule inet filter input tcp dport $p accept (dan simpan di /etc/nftables.conf)."
    elif have iptables && iptables -S INPUT 2>/dev/null | grep -q '^-P INPUT DROP' && ! iptables -S INPUT 2>/dev/null | grep -qE -- "--dport $p\b"; then
        c_warn "Firewall iptables menolak koneksi masuk dan belum ada aturan untuk port $p -- buka manual: iptables -I INPUT -p tcp --dport $p -j ACCEPT (lalu simpan)."
    fi
    return 0
}

setup_auto_update() {
    case "$PKG" in
        apt)
            pkg_install unattended-upgrades >/dev/null 2>&1 || { c_warn "unattended-upgrades gagal dipasang."; return; }
            backup /etc/apt/apt.conf.d/20auto-upgrades
            printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > /etc/apt/apt.conf.d/20auto-upgrades
            c_ok "Update keamanan otomatis aktif (unattended-upgrades)." ;;
        dnf)
            pkg_install dnf-automatic >/dev/null 2>&1 || { c_warn "dnf-automatic gagal dipasang."; return; }
            local conf=/etc/dnf/automatic.conf
            if [ -f "$conf" ]; then
                backup "$conf"
                sed -i 's/^upgrade_type.*/upgrade_type = security/; s/^apply_updates.*/apply_updates = yes/' "$conf"
            fi
            systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || systemctl enable --now dnf-automatic-install.timer >/dev/null 2>&1 || true
            c_ok "Update keamanan otomatis aktif (dnf-automatic)." ;;
        yum)
            pkg_install yum-cron >/dev/null 2>&1 || { c_warn "yum-cron gagal dipasang."; return; }
            if [ -f /etc/yum/yum-cron.conf ]; then backup /etc/yum/yum-cron.conf; sed -i 's/^update_cmd.*/update_cmd = security/; s/^apply_updates.*/apply_updates = yes/' /etc/yum/yum-cron.conf; fi
            systemctl enable --now yum-cron >/dev/null 2>&1 || true
            c_ok "Update keamanan otomatis aktif (yum-cron)." ;;
        *) c_warn "Update otomatis belum didukung untuk $PKG -- dilewati." ;;
    esac
}
auto_update_status() {
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then echo "aktif (unattended-upgrades)"
    elif [ "${HAS_SYSTEMD:-0}" -eq 1 ] && { systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null || systemctl is-enabled --quiet dnf-automatic-install.timer 2>/dev/null; }; then echo "aktif (dnf-automatic)"
    elif [ "${HAS_SYSTEMD:-0}" -eq 1 ] && systemctl is-enabled --quiet yum-cron 2>/dev/null; then echo "aktif (yum-cron)"
    else echo "tidak aktif"; fi
}

install_self() { # salin skrip ke /usr/local/sbin supaya perintahnya bisa dipakai di mana saja
    local src="${BASH_SOURCE[0]:-}"
    if [ -n "$src" ] && [ -f "$src" ] && [ "$(readlink -f "$src")" != "$SELF_INSTALL" ]; then
        install -m 0755 "$src" "$SELF_INSTALL" && c_ok "Perintah tersedia: gisnet-secure-ssh (status, whitelist, key, ...)."
    elif [ ! -x "$SELF_INSTALL" ]; then
        c_warn "Skrip dijalankan lewat pipa -- simpan dulu sebagai file lalu jalankan lagi agar perintah 'gisnet-secure-ssh' tersedia."
    fi
}

# ================================================================= STATUS ===
cmd_status() {
    detect_os
    local running=tidak jails j banned total pw root ports keys
    have fail2ban-client && fail2ban-client ping >/dev/null 2>&1 && running=aktif
    pw="$("$SSHD_BIN" -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}')"
    root="$("$SSHD_BIN" -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2}')"
    ports="$(ssh_ports)"
    keys="$(grep -cE '^(ssh-|ecdsa-|sk-)' /root/.ssh/authorized_keys 2>/dev/null || true)"; keys="${keys:-0}"
    echo
    echo " Server        : $(hostname) -- $OS_NAME"
    echo " fail2ban      : $running"
    if [ "$running" = aktif ]; then
        jails="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' | tr ',' ' ')"
        for j in $jails; do
            banned="$(fail2ban-client status "$j" 2>/dev/null | awk -F: '/Currently banned/{gsub(/[ 	]/,"",$2); print $2}')"
            total="$(fail2ban-client status "$j" 2>/dev/null | awk -F: '/Total banned/{gsub(/[ 	]/,"",$2); print $2}')"
            printf '   - %-14s diblokir sekarang: %-4s total: %s\n' "$j" "${banned:-0}" "${total:-0}"
        done
    fi
    echo " Whitelist     : $(wl_current | paste -sd' ' - || true)"
    echo " SSH           : port ${ports:-?} · login password: ${pw:-?} · root: ${root:-?} · kunci root: $keys"
    echo " Update otomatis: $(auto_update_status)"
    echo " Laporan       : $([ -f "$REPORT_CONF" ] && . "$REPORT_CONF" && echo "aktif ke $REPORT_URL" || echo 'tidak aktif')"
    echo " Reboot via app: $([ -f "$ALLOW_REBOOT" ] && echo diizinkan || echo 'tidak diizinkan')$( s="$(reboot_scheduled_at)"; [ -n "$s" ] && echo " · terjadwal $(date -d "@$s" '+%d/%m %H:%M')" )"
    echo " Port via app  : $([ -f "$ALLOW_PORT" ] && echo diizinkan || echo 'tidak diizinkan') · whitelist: $(allows_whitelist && echo diizinkan || echo 'tidak') · DNS: $(allows_dns && echo diizinkan || echo 'tidak') · kunci: $([ -f "$ALLOW_KEY" ] && echo diizinkan || echo 'tidak')"
    echo " DNS           : $(dns_servers | paste -sd' ' - || true) ($(dns_manager))$(dns_ok || echo ' -- TIDAK BISA MENCARI NAMA')"
    echo " Update via app: $([ -f "$ALLOW_UPDATE" ] && echo diizinkan || echo 'tidak diizinkan') · blokir bersama: $([ -f "$SHARED_OFF" ] && echo 'tidak aktif' || echo aktif)"
    [ -f "$WEB_PROXY_STATE" ] && echo " Jail web      : dilewati -- website di belakang $(cat "$WEB_PROXY_STATE")"
    # --- pemeriksaan server
    local mt ma du l1 cpus
    read -r l1 _ < /proc/loadavg 2>/dev/null || l1='?'; cpus="$(nproc 2>/dev/null || echo '?')"
    mt="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"; ma="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
    du="$(df -Pk / 2>/dev/null | tail -1 | awk '{print $(NF-1)}')"
    echo " Kesehatan     : load $l1 / $cpus CPU · RAM $( [ -n "$mt" ] && [ -n "$ma" ] && echo "$(( (mt - ma) * 100 / mt ))%" || echo '?') · disk / ${du:-?}"
    local risky
    risky="$(checks_ports | grep -oE '\{[^}]*"risk":"[^"]+","firewall":"open"\}' | sed -E 's/.*"port":([0-9]+),.*"risk":"([^"]+)".*/\1 (\2)/' | sort -u | paste -sd',' - || true)"
    [ -n "$risky" ] && printf ' \033[33mPort berbahaya terbuka: %s -- pastikan diblokir firewall dari internet.\033[0m\n' "$risky"
    local susp
    susp="$(checks_processes | grep -oE '"name":"[^"]*","exe":"[^"]*","reason":"[a-z]+"' | sed -E 's/"name":"([^"]*)","exe":"([^"]*)","reason":"([a-z]+)"/\1 [\3] \2/' || true)"
    if [ -n "$susp" ]; then
        printf ' \033[31mProses mencurigakan:\033[0m\n'; printf '%s\n' "$susp" | sed 's/^/   /'
    fi
    local logins
    logins="$(checks_logins)"
    echo " Login SSH 7 hari: ${logins##*|} kali; terakhir:"
    printf '%s' "${logins%|*}" | grep -oE '\{[^}]*\}' | tail -5 | sed -E 's/.*"at":"([^"]*)","user":"([^"]*)","ip":"([^"]*)","method":"([^"]*)","key":"?([^"}]*)"?.*/   \1  \2 dari \3 (\4 \5)/; s/ null\)/)/' || true
    if [ -f "$F2B_LOG" ]; then
        echo " Blokir terakhir:"
        grep -E 'NOTICE +\[[^]]+\] Ban ' "$F2B_LOG" 2>/dev/null | tail -10 | awk '{for(i=1;i<=NF;i++) if($i=="Ban"){print "   " $1 " " substr($2,1,8) "  " $(i-1) "  " $(i+1)}}' | sed 's/\[\(.*\)\]/\1/' || true
    fi
    echo
}

# ============================================================ BAN / UNBAN ===
f2b_jails() { fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' | tr ',' ' '; }
cmd_banned() {
    need_root; have fail2ban-client || die "fail2ban belum terpasang."
    local j list n=0
    echo
    for j in $(f2b_jails); do
        list="$(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p')"
        [ -n "$list" ] || continue
        echo " [$j]"; for ip in $list; do n=$((n + 1)); echo "   $ip"; done
    done
    [ "$n" -gt 0 ] && echo " Total: $n IP diblokir." || echo " Tidak ada IP yang diblokir."
    echo
}
cmd_ban() {
    need_root; local ip="${1-}"
    [ -n "$ip" ] || { [ -n "$TTY" ] && ip="$(ask "IP yang diblokir: ")"; }
    valid_ip "$ip" || die "IP tidak valid: ${ip:-kosong}"
    wl_current | grep -qxF "$ip" && die "$ip ada di whitelist -- hapus dulu dari whitelist bila memang ingin diblokir."
    fail2ban-client set sshd banip "$ip" >/dev/null && c_ok "$ip diblokir (port SSH, jail sshd)."
}
cmd_unban() {
    need_root; local ip="${1-}"
    [ -n "$ip" ] || { [ -n "$TTY" ] && { cmd_banned; ip="$(ask "IP yang dibuka (atau 'all'): ")"; }; }
    if [ "$ip" = all ]; then confirm "Buka SEMUA blokir?" && fail2ban-client unban --all >/dev/null && c_ok "Semua blokir dibuka."; return; fi
    valid_ip "$ip" || die "IP tidak valid: ${ip:-kosong}"
    fail2ban-client unban "$ip" >/dev/null 2>&1 && c_ok "Blokir $ip dibuka." || c_warn "$ip tidak sedang diblokir."
}

# ============================================================== WHITELIST ===
wl_write() { # wl_write <ip ...> -- tulis ulang ignoreip lalu muat ulang fail2ban
    local list="$WL_BUILTIN" ip
    for ip in "$@"; do case " $list " in *" $ip "*) ;; *) list="$list $ip" ;; esac; done
    cp -a "$JAIL" "$JAIL.bak-$(date +%Y%m%d-%H%M%S)"
    awk -v v="$list" '/^[[:space:]]*ignoreip[[:space:]]*=/{print "ignoreip  = " v; next} {print}' "$JAIL" > "$JAIL.tmp" && cat "$JAIL.tmp" > "$JAIL" && rm -f "$JAIL.tmp"
    f2b_reload && c_ok "fail2ban dimuat ulang -- whitelist berlaku."
}
wl_list() {
    echo; echo "Whitelist fail2ban ($JAIL):"
    local ip n=0
    while read -r ip; do
        n=$((n + 1))
        case " $WL_BUILTIN " in *" $ip "*) printf '  %2d. %s  (bawaan, tidak bisa dihapus)\n' "$n" "$ip" ;; *) printf '  %2d. %s\n' "$n" "$ip" ;; esac
    done < <(wl_current)
    echo
}
wl_add() {
    local ips=("$@") ip added=() current
    if [ "${#ips[@]}" -eq 0 ]; then
        [ -n "$TTY" ] || die "Sebutkan IP: whitelist add <ip> [ip ...]"
        read -r -a ips <<< "$(ask "IP/subnet yang ditambahkan (pisahkan spasi): " | tr ',' ' ')"
    fi
    [ "${#ips[@]}" -gt 0 ] || die "Tidak ada IP yang dimasukkan."
    current="$(wl_current | tr '\n' ' ')"
    for ip in "${ips[@]}"; do
        valid_ip "$ip" || die "IP tidak valid: $ip"
        case " $current " in *" $ip "*) c_info "$ip sudah ada di whitelist." ;; *) current="$current $ip"; added+=("$ip") ;; esac
    done
    [ "${#added[@]}" -gt 0 ] || { wl_list; return 0; }
    # shellcheck disable=SC2086
    wl_write $current
    for ip in "${added[@]}"; do fail2ban-client unban "$ip" >/dev/null 2>&1 || true; c_ok "Ditambahkan: $ip"; done
    wl_list
}
wl_remove() {
    local ips=("$@") ip keep=() removed=0 cur resolved=() r drop
    if [ "${#ips[@]}" -eq 0 ]; then
        [ -n "$TTY" ] || die "Sebutkan IP: whitelist remove <ip> [ip ...]"
        wl_list
        read -r -a ips <<< "$(ask "IP yang dihapus (ketik IP atau nomornya, pisahkan spasi): " | tr ',' ' ')"
    fi
    [ "${#ips[@]}" -gt 0 ] || die "Tidak ada IP yang dimasukkan."
    mapfile -t cur < <(wl_current)
    for ip in "${ips[@]}"; do
        if [[ "$ip" =~ ^[0-9]+$ ]] && [ "$ip" -ge 1 ] && [ "$ip" -le "${#cur[@]}" ]; then resolved+=("${cur[$((ip - 1))]}"); else resolved+=("$ip"); fi
    done
    for ip in "${resolved[@]}"; do
        case " $WL_BUILTIN " in *" $ip "*) c_warn "$ip adalah bawaan -- tidak dihapus." ;; esac
        printf '%s\n' "${cur[@]}" | grep -qxF "$ip" || c_warn "$ip tidak ada di whitelist."
    done
    for ip in "${cur[@]}"; do
        drop=0; for r in "${resolved[@]}"; do [ "$r" = "$ip" ] && drop=1; done
        case " $WL_BUILTIN " in *" $ip "*) drop=0 ;; esac
        if [ "$drop" -eq 1 ]; then removed=$((removed + 1)); c_ok "Dihapus: $ip"; else keep+=("$ip"); fi
    done
    [ "$removed" -gt 0 ] || { wl_list; return 0; }
    wl_write ${keep[@]+"${keep[@]}"}
    wl_list
}
cmd_whitelist() {
    need_root
    [ -f "$JAIL" ] || die "Belum terpasang ($JAIL tidak ada). Jalankan dulu pemasangan."
    have fail2ban-client || die "fail2ban belum terpasang."
    local action="${1-}"; [ $# -gt 0 ] && shift
    case "$action" in
        list|lihat|ls) wl_list ;;
        add|tambah) wl_add "$@" ;;
        remove|hapus|rm|del) wl_remove "$@" ;;
        '')
            [ -n "$TTY" ] || { wl_list; return 0; }
            while :; do
                wl_list; echo "  1) Tambah IP    2) Hapus IP    3) Kembali"
                case "$(ask "Pilih [1-3]: ")" in 1) wl_add ;; 2) wl_remove ;; *) break ;; esac
            done ;;
        *) die "Perintah whitelist tidak dikenal: $action (list | add | remove)" ;;
    esac
}

# ============================================================ KUNCI SSH ===
key_file_of() { local home; home="$(awk -F: -v u="$1" '$1==u{print $6}' /etc/passwd)"; [ -n "$home" ] || die "User '$1' tidak ditemukan."; echo "$home/.ssh/authorized_keys"; }
key_list() { # key_list <user>
    local file n=0 line type comment fp tmp
    file="$(key_file_of "$1")"
    echo; echo "Kunci SSH user $1 ($file):"
    [ -f "$file" ] || { echo "  (belum ada)"; echo; return; }
    tmp="$(mktemp)"
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue ;; esac
        n=$((n + 1))
        printf '%s\n' "$line" > "$tmp"
        fp="$(ssh-keygen -lf "$tmp" 2>/dev/null | awk '{print $2}' || true)"
        type="$(printf '%s' "$line" | grep -oE '(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+)' | head -1 || true)"
        comment="$(printf '%s' "$line" | awk -v t="$type" '{for(i=1;i<=NF;i++) if($i==t){c=""; for(j=i+2;j<=NF;j++) c=c (c?" ":"") $j; print c; exit}}')"
        printf '  %2d. %-12s %-22s %s\n' "$n" "$type" "${comment:-(tanpa nama)}" "${fp:-}"
    done < "$file"
    rm -f "$tmp"; [ "$n" -gt 0 ] || echo "  (belum ada)"; echo
}
key_add() { # key_add <user> [kunci]
    local user="$1" key="${2-}"; [ $# -gt 0 ] && shift
    [ -n "$key" ] || { [ -n "$TTY" ] || die "Sebutkan kunci: key add \"ssh-ed25519 AAAA... nama\""; key="$(ask "Tempel kunci publik: " | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"; }
    valid_key "$key" || die "Kunci publik tidak valid (pastikan isi file .pub)."
    start_backup; install_keys "$user" "$key" >/dev/null && c_ok "Kunci ${key##* } dipasang untuk $user."
    [ -f "$BASELINE" ] && baseline_save key   # perubahan disengaja -- bukan "jejak penyusup"
    key_list "$user"
}
key_remove() { # key_remove <user> [nomor|nama]
    local user="$1" sel="${2-}" file total pw idx=0 line removed=''
    file="$(key_file_of "$user")"; [ -f "$file" ] || die "Belum ada kunci untuk $user."
    [ -n "$sel" ] || { [ -n "$TTY" ] || die "Sebutkan nomor/nama kunci: key remove <nomor>"; key_list "$user"; sel="$(ask "Nomor atau nama kunci yang dihapus: ")"; }
    total="$(grep -cvE '^[[:space:]]*(#|$)' "$file" || true)"
    pw="$("$SSHD_BIN" -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}')"
    [ "$total" -le 1 ] && [ "$pw" = no ] && die "Ini kunci TERAKHIR dan login password mati -- menghapusnya akan mengunci server. Tambah kunci lain dulu."
    start_backup; backup "$file"
    : > "$file.tmp"
    while IFS= read -r line; do
        case "$line" in ''|\#*) printf '%s\n' "$line" >> "$file.tmp"; continue ;; esac
        idx=$((idx + 1))
        if { [[ "$sel" =~ ^[0-9]+$ ]] && [ "$idx" -eq "$sel" ]; } || { ! [[ "$sel" =~ ^[0-9]+$ ]] && [ "${line##* }" = "$sel" ]; }; then
            [ -z "$removed" ] && { removed="${line##* }"; continue; }
        fi
        printf '%s\n' "$line" >> "$file.tmp"
    done < "$file"
    [ -n "$removed" ] || { rm -f "$file.tmp"; die "Kunci '$sel' tidak ditemukan."; }
    cat "$file.tmp" > "$file"; rm -f "$file.tmp"
    c_ok "Kunci '$removed' dihapus dari $user (cadangan: $BACKUP_DIR)."
    [ -f "$BASELINE" ] && baseline_save key   # perubahan disengaja -- bukan "jejak penyusup"
    key_list "$user"
}
cmd_key() {
    need_root; detect_os
    local action="${1-}" user=root args=(); [ $# -gt 0 ] && shift
    while [ $# -gt 0 ]; do case "$1" in --user) user="${2:?}"; shift 2 ;; *) args+=("$1"); shift ;; esac; done
    case "$action" in
        list|lihat|ls) key_list "$user" ;;
        add|tambah) key_add "$user" ${args[@]+"${args[@]}"} ;;
        remove|hapus|rm|del) key_remove "$user" ${args[@]+"${args[@]}"} ;;
        '')
            [ -n "$TTY" ] || { key_list "$user"; return 0; }
            while :; do
                key_list "$user"; echo "  1) Tambah kunci    2) Hapus kunci    3) Kembali"
                case "$(ask "Pilih [1-3]: ")" in 1) key_add "$user" ;; 2) key_remove "$user" ;; *) break ;; esac
            done ;;
        *) die "Perintah key tidak dikenal: $action (list | add | remove)" ;;
    esac
}

# ================================================================ PORT SSH ===
cmd_port() {
    need_root; detect_os
    local p="${1-}" remove_old=0 current pw newports
    [ "${2-}" = --remove-old ] && remove_old=1
    [ -n "$p" ] || { [ -n "$TTY" ] && p="$(ask "Port SSH baru (mis. 2269): ")"; }
    [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || die "Port tidak valid: ${p:-kosong}"
    current="$(ssh_ports)"; pw="$("$SSHD_BIN" -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}')"
    if [ "$remove_old" -eq 1 ]; then
        case ",$current," in *",$p,"*) ;; *) die "Port $p belum aktif -- tambahkan dulu: port $p, coba login, baru --remove-old." ;; esac
        confirm "Tutup port lama ($current) dan sisakan hanya $p? Pastikan login di port $p SUDAH berhasil." || die "Dibatalkan."
        newports="$p"
    else
        if have ss && ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$p\$" && ! case ",$current," in *",$p,"*) true ;; *) false ;; esac; then
            die "Port $p sudah dipakai program lain."
        fi
        case ",$current," in *",$p,"*) c_info "Port $p sudah aktif."; return 0 ;; esac
        newports="$current,$p"
    fi
    start_backup
    open_port "$p"
    apply_ssh "${pw:-no}" "$newports"
    if [ -f "$JAIL" ]; then
        backup "$JAIL"
        # Tulis "port = <baru>" tepat di bawah judul jail SSH dan buang baris port lamanya --
        # juga bila jail itu belum punya baris port (jail buatan tangan: default "ssh" = 22,
        # ditemukan di VM-1/VM-2 2026-10-30; tanpa ini port baru tidak dilindungi fail2ban).
        awk -v v="$newports" '/^\[/{s=$0; print; if (s=="[sshd]"||s=="[recidive]"||s=="[gisnet-shared]") print "port      = " v; next} (s=="[sshd]"||s=="[recidive]"||s=="[gisnet-shared]") && /^[[:space:]]*port[[:space:]]*=/{next} {print}' "$JAIL" > "$JAIL.tmp" && cat "$JAIL.tmp" > "$JAIL" && rm -f "$JAIL.tmp"
        f2b_reload || true
    fi
    if [ "$remove_old" -eq 1 ]; then c_ok "SSH sekarang hanya di port $p."
    else
        c_ok "Port $p ditambahkan (port lama $current tetap dibuka)."
        c_warn "Coba login di terminal lain: ssh -p $p root@<ip-server>"
        c_warn "Kalau berhasil, tutup port lama: gisnet-secure-ssh port $p --remove-old"
    fi
}

# ================================================================= RESTORE ===
restore_from() { # restore_from <folder> [quiet]
    local dir="$1" quiet="${2-}" path name state
    [ -f "$dir/MANIFEST" ] || die "Cadangan tidak valid: $dir"
    while IFS='|' read -r path name state; do
        [ -n "$path" ] || continue
        if [ "$state" = ada ]; then cp -a "$dir/$name" "$path"; [ -z "$quiet" ] && c_ok "Dikembalikan: $path"
        else rm -f "$path"; [ -z "$quiet" ] && c_ok "Dihapus (file baru): $path"; fi
    done < "$dir/MANIFEST"
    if "$SSHD_BIN" -t 2>/dev/null; then ssh_reload; else c_warn "Konfigurasi SSH hasil restore tidak valid -- periksa $SSHD_CONFIG."; fi
    have fail2ban-client && { f2b_reload || true; }
}
cmd_restore() {
    need_root; detect_os
    local dir="${1-}"
    [ -n "$dir" ] || dir="$(ls -1d /root/gisnet-secure-ssh-backup-* 2>/dev/null | sort | tail -1 || true)"
    [ -n "$dir" ] && [ -d "$dir" ] || die "Tidak ada cadangan di /root/gisnet-secure-ssh-backup-*."
    echo; echo "Cadangan: $dir"; sed 's/|.*|ada$/  (dikembalikan)/; s/||baru$/  (dihapus, file baru)/; s/^/  /' "$dir/MANIFEST"; echo
    echo "Cadangan lain: $(ls -1d /root/gisnet-secure-ssh-backup-* 2>/dev/null | wc -l) (pilih dengan: restore <folder>)"
    confirm "Kembalikan pengaturan dari cadangan ini?" || die "Dibatalkan."
    restore_from "$dir"
    c_ok "Selesai. Pengaturan dikembalikan ke kondisi sebelum $(basename "$dir" | sed 's/gisnet-secure-ssh-backup-//')."
}

# ============================================================ PEMERIKSAAN ===
# Port yang berbahaya bila terbuka ke internet (dicek: mendengarkan di semua alamat / alamat publik).
RISKY_PORTS='21:FTP 23:Telnet 111:rpcbind 139:SMB 445:SMB 873:rsync 2049:NFS 2375:Docker-API 2376:Docker-API 3000:Panel-web(GenieACS/Grafana) 3306:MySQL/MariaDB 3389:RDP 5432:PostgreSQL 5601:Kibana 5672:RabbitMQ 5900:VNC 6379:Redis 7557:GenieACS-NBI 7567:GenieACS-FS 8086:InfluxDB 9090:Prometheus/Cockpit 9200:Elasticsearch 10000:Webmin 11211:Memcached 15672:RabbitMQ-admin 27017:MongoDB'
MINER_NAMES='xmrig|xmr-stak|xmrstak|kdevtmpfsi|kinsing|minerd|cpuminer|ethminer|nbminer|t-rex|lolminer|phoenixminer|nanominer|teamredminer|gminer|srbminer|kthreaddi|kswapd0x|sysupdate|networkservice'

checks_health() {
    local cpus l1 l5 l15 mt ma st sf dt du
    cpus="$(nproc 2>/dev/null || echo 1)"
    read -r l1 l5 l15 _ < /proc/loadavg 2>/dev/null || { l1=0; l5=0; l15=0; }
    mt="$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)"; ma="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
    [ -n "$ma" ] || ma="$(awk '/^MemFree:/{print $2}' /proc/meminfo 2>/dev/null)"
    st="$(awk '/^SwapTotal:/{print $2}' /proc/meminfo 2>/dev/null)"; sf="$(awk '/^SwapFree:/{print $2}' /proc/meminfo 2>/dev/null)"
    # kolom "Use%" = kolom kedua dari belakang (nama device bisa berspasi)
    read -r dt du < <(df -Pk / 2>/dev/null | tail -1 | awk '{u=$(NF-1); gsub(/%/,"",u); print $2, u}') || true
    pct() { awk -v v="$1" 'BEGIN{v=int(v); if (v<0) v=0; if (v>100) v=100; print v}'; }
    num() { awk -v v="$1" 'BEGIN{printf "%.2f", (v+0 < 0 ? 0 : v+0)}'; }
    printf '{"cpus":%s,"load1":%s,"load5":%s,"load15":%s,"mem_total_mb":%s,"mem_used_pct":%s,"swap_used_pct":%s,"disk_total_gb":%s,"disk_used_pct":%s}' \
        "$(awk -v v="${cpus:-1}" 'BEGIN{print (int(v) > 0 ? int(v) : 1)}')" "$(num "${l1:-0}")" "$(num "${l5:-0}")" "$(num "${l15:-0}")" \
        "$(( ${mt:-0} / 1024 ))" \
        "$(pct "$( [ "${mt:-0}" -gt 0 ] && echo $(( (mt - ${ma:-0}) * 100 / mt )) || echo 0 )")" \
        "$(pct "$( [ "${st:-0}" -gt 0 ] && echo $(( (st - ${sf:-0}) * 100 / st )) || echo 0 )")" \
        "$(awk -v k="${dt:-0}" 'BEGIN{v=k/1048576; printf "%.1f", (v<0?0:v)}')" "$(pct "${du:-0}")"
}
# Apakah firewall membuka port ini untuk semua orang? open | restricted (hanya IP tertentu) | blocked.
# Dipakai hanya untuk port berbahaya: port yang sudah ditutup/dibatasi firewall tidak dihitung masalah.
fw_port_state() { # fw_port_state <port>
    local p="$1" lines
    if [ "${HAS_SYSTEMD:-0}" -eq 1 ] && systemctl is-active --quiet firewalld 2>/dev/null; then
        local z open=0 restr=0 rich zopen zblock svc
        for z in $( { firewall-cmd --get-active-zones 2>/dev/null | grep -v '^[[:space:]]'; firewall-cmd --get-default-zone 2>/dev/null; } | sort -u); do
            zopen=0; zblock=0
            rich="$(firewall-cmd --zone="$z" --list-rich-rules 2>/dev/null | grep -E "port port=\"?$p\"? protocol=\"?tcp" || true)"
            printf '%s\n' "$rich" | grep -v 'source' | grep -qE '\b(reject|drop)\b' && zblock=1
            printf '%s\n' "$rich" | grep 'source' | grep -q 'accept' && restr=1
            printf '%s\n' "$rich" | grep -v 'source' | grep -q 'accept' && zopen=1
            firewall-cmd -q --zone="$z" --query-port="$p/tcp" 2>/dev/null && zopen=1
            for svc in $(firewall-cmd --zone="$z" --list-services 2>/dev/null); do
                firewall-cmd --info-service="$svc" 2>/dev/null | grep -E '^[[:space:]]*ports:' | tr ' ' '\n' | grep -qx "$p/tcp" && zopen=1
            done
            [ "$zopen" -eq 1 ] && [ "$zblock" -eq 0 ] && open=1
        done
        if [ "$open" -eq 1 ]; then echo open; elif [ "$restr" -eq 1 ]; then echo restricted; else echo blocked; fi
        return 0
    fi
    if have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then
        lines="$(ufw status 2>/dev/null | awk -v p="$p" 'NR>4 && ($1 == p || $1 == p"/tcp")')"
        if printf '%s\n' "$lines" | grep -qE 'ALLOW( IN)?[[:space:]]+Anywhere'; then echo open
        elif printf '%s\n' "$lines" | grep -q 'ALLOW'; then echo restricted
        elif printf '%s\n' "$lines" | grep -qE 'DENY|REJECT'; then echo blocked
        elif ufw status verbose 2>/dev/null | grep -qE 'Default: (deny|reject) \(incoming\)'; then echo blocked
        else echo open; fi
        return 0
    fi
    # Ruleset dibaca SEKALI ke variabel lalu dicek tanpa pipa: "nft list ruleset | grep -q" di
    # server dengan ruleset besar (cPanel + set fail2ban, Kulo 2026-10-30) membuat nft kena SIGPIPE,
    # dan dengan pipefail pemeriksaannya dianggap gagal -> blok ini dilewati, hasil salah "open".
    local rules=''
    have nft && rules="$(nft list ruleset 2>/dev/null || true)"
    if [ -n "$rules" ] && grep -q 'hook input' <<< "$rules"; then
        # Baris untuk loopback (iifname "lo") hanya lalu lintas server sendiri -- tidak dihitung.
        lines="$(grep -E "dport (\{[^}]*[ ,]$p[ ,}][^}]*\}|\{ ?$p ?\}|$p\b)" <<< "$rules" | grep -v 'iifname "lo"' || true)"
        # drop/reject untuk semua sumber berlaku di base chain mana pun (mis. tabel sendiri
        # "gisnet_mysql" di Kulo, 2026-10-30) -- accept di tabel lain tidak bisa membatalkannya.
        if grep -E '\b(drop|reject)\b' <<< "$lines" | grep -qv 'saddr'; then
            echo blocked
        elif grep -q 'hook input.*policy drop' <<< "$rules"; then
            if printf '%s\n' "$lines" | grep 'accept' | grep -qv 'saddr'; then echo open
            elif printf '%s\n' "$lines" | grep -q 'accept'; then echo restricted
            else echo blocked; fi
        else
            if printf '%s\n' "$lines" | grep -qE '\b(drop|reject)\b' && ! printf '%s\n' "$lines" | grep -E '\b(drop|reject)\b' | grep -q 'saddr'; then echo blocked
            else echo open; fi
        fi
        return 0
    fi
    local ipt=''
    have iptables && ipt="$(iptables -S INPUT 2>/dev/null || true)"   # sekali, tanpa pipa (lihat catatan nft)
    if [ -n "$ipt" ]; then
        lines="$(grep -E -- "--dports? ([0-9,:]*,)?$p(,|\b)" <<< "$ipt" || true)"
        if grep -q '^-P INPUT DROP' <<< "$ipt"; then
            if grep 'ACCEPT' <<< "$lines" | grep -qv -- '-s '; then echo open
            elif grep -q 'ACCEPT' <<< "$lines"; then echo restricted
            else echo blocked; fi
        else
            grep -E 'DROP|REJECT' <<< "$lines" | grep -qv -- '-s ' && echo blocked || echo open
        fi
        return 0
    fi
    echo open
}
checks_ports() { # JSON array port TCP yang mendengarkan (bukan loopback)
    have ss || { printf '[]'; return; }
    local json p
    json="$(checks_ports_raw)"
    for p in $(printf '%s' "$json" | grep -oE '"@FW[0-9]+@"' | tr -dc '0-9\n' | sort -u); do
        json="${json//\"@FW$p@\"/\"$(fw_port_state "$p")\"}"
    done
    printf '%s' "$json"
}
checks_ports_raw() {
    ss -H -tlnp 2>/dev/null | awk -v risky="$RISKY_PORTS" '
        BEGIN { n = split(risky, r, " "); for (i = 1; i <= n; i++) { split(r[i], kv, ":"); lab[kv[1]] = kv[2]; gsub(/-/, " ", lab[kv[1]]) } }
        {
            local = $4; port = local; sub(/.*:/, "", port); addr = local; sub(/:[0-9]+$/, "", addr); gsub(/[\[\]]/, "", addr)
            sub(/%.*/, "", addr)
            if (addr ~ /^127\./ || addr == "::1") next
            proc = ""; if (match($0, /\(\("[^"]+"/)) { proc = substr($0, RSTART + 3, RLENGTH - 4) }
            pub = (addr == "0.0.0.0" || addr == "*" || addr == "::" || (addr !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|fe80|fd|fc)/)) ? "true" : "false"
            key = port "|" pub; if (seen[key]++) next
            risk = (pub == "true" && (port in lab)) ? "\"" lab[port] "\"" : "null"
            fw = (risk != "null") ? "\"@FW" port "@\"" : "null"
            sub(/ \(.*/, "", proc)   # "cpsrvd (SSL - ...)" -> "cpsrvd"
            gsub(/["\\]/, "", proc); gsub(/["\\]/, "", addr)
            out = out (out ? "," : "") sprintf("{\"port\":%d,\"proto\":\"tcp\",\"addr\":\"%s\",\"process\":\"%s\",\"public\":%s,\"risk\":%s,\"firewall\":%s}", port, addr, proc, pub, risk, fw)
            if (++cnt >= 60) exit
        }
        END { printf "[%s]", out }'
}
checks_processes() { # JSON array proses mencurigakan
    local out='' cnt=0 pid user pcpu etimes comm exe reason
    while read -r pid user pcpu etimes comm; do
        [ -n "$pid" ] || continue
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
        reason=''
        if printf '%s\n%s\n' "$comm" "${exe##*/}" | grep -qiE "^($MINER_NAMES)$"; then reason=miner
        elif [[ "$exe" =~ ^/(tmp|var/tmp|dev/shm)/ ]]; then reason=tmp
        elif awk -v c="$pcpu" -v e="$etimes" 'BEGIN{exit !(c >= 90 && e >= 1800)}'; then reason=cpu
        fi
        [ -n "$reason" ] || continue
        out="$out${out:+,}{\"pid\":$pid,\"user\":$(json_str "$user"),\"cpu\":${pcpu:-0},\"name\":$(json_str "$comm"),\"exe\":$(json_str "${exe% (deleted)}"),\"reason\":\"$reason\"}"
        cnt=$((cnt + 1)); [ "$cnt" -ge 20 ] && break
    done < <(ps -eo pid=,user=,pcpu=,etimes=,comm= 2>/dev/null)
    printf '[%s]' "$out"
}
checks_logins() { # cetak: <JSON array 10 login terakhir>|<jumlah 7 hari>
    local raw fpmap
    if have journalctl && [ "${HAS_SYSTEMD:-0}" -eq 1 ]; then
        raw="$(journalctl -q --no-pager -o short-iso -u ssh -u sshd --since '-7d' 2>/dev/null | grep 'Accepted ' || true)"
    else
        raw="$(cat /var/log/auth.log /var/log/secure 2>/dev/null | grep 'Accepted ' || true)"
    fi
    # sidik jari kunci -> nama kunci, dari authorized_keys root
    fpmap="$(f="$(awk -F: '$1=="root"{print $6}' /etc/passwd)/.ssh/authorized_keys"; [ -f "$f" ] && while IFS= read -r line; do
        case "$line" in ''|\#*) continue ;; esac
        fp="$(printf '%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}' || true)"; [ -n "$fp" ] && echo "$fp ${line##* }"
    done < "$f")"
    printf '%s\n' "$raw" | awk -v fpmap="$fpmap" '
        BEGIN { n = split(fpmap, l, "\n"); for (i = 1; i <= n; i++) { split(l[i], kv, " "); if (kv[1] != "") name[kv[1]] = kv[2] } }
        /Accepted / {
            total++
            at = $1; if (at ~ /T/) { sub(/T/, " ", at); at = substr(at, 1, 19) } else { at = $1 " " $2 " " $3 }
            for (i = 1; i <= NF; i++) {
                if ($i == "Accepted") method = $(i + 1)
                if ($i == "for") user = $(i + 1)
                if ($i == "from") ip = $(i + 1)
                if ($i ~ /^SHA256:/) fp = $i
            }
            key = (fp in name) ? "\"" name[fp] "\"" : "null"; fp = ""
            gsub(/["\\]/, "", user)
            rows[total] = sprintf("{\"at\":\"%s\",\"user\":\"%s\",\"ip\":\"%s\",\"method\":\"%s\",\"key\":%s}", at, user, ip, method, key)
        }
        END { s = (total > 10) ? total - 9 : 1; for (i = s; i <= total; i++) out = out (out ? "," : "") rows[i]; printf "[%s]|%d", out, total }'
}
checks_fields() { # potongan JSON (tanpa kurung kurawal) -- dipakai laporan & perintah "checks"
    local logins web jails
    logins="$(checks_logins)"
    web="$(cat "$WEB_PROXY_STATE" 2>/dev/null || true)"
    jails="$( { fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ' ' | tr ',' '\n' | grep -vxE 'sshd|recidive|gisnet-scan|gisnet-shared|' || true; } | awk '{printf "%s\"%s\"", (NR>1?",":""), $0}')"
    printf '"health":%s,"open_ports":%s,"suspicious":%s,"logins":%s,"logins_7d":%s,"web_proxy":%s,"service_jails":[%s],"changes":%s,"baseline_at":%s,"restricted_ports":[%s],"web_leaks":%s,"certs":%s,%s,"time":%s,"rootkit":%s' \
        "$(checks_health)" "$(checks_ports)" "$(checks_processes)" "${logins%|*}" "${logins##*|}" \
        "$([ -n "$web" ] && json_str "$web" || echo null)" "$jails" \
        "$(changes_json)" "$(sed -n 's/^# baseline //p' "$BASELINE" 2>/dev/null | head -1 | grep -E '^[0-9]+$' || echo null)" \
        "$(restricted_ports | paste -sd, -)" \
        "$(web_leaks_json)" "$(certs_json)" "$(ssh_fail_fields)" "$(time_json)" "$(rootkit_json)"
}
cmd_checks() { # cetak hasil pemeriksaan sebagai JSON (dipakai skrip status VM aplikasi)
    detect_os
    printf '{%s}\n' "$(checks_fields)"
}

# ================================================= JEJAK PENYUSUP (2.15) ===
# Belajar dari kasus xmrig (ACS1, 2026-10-26): penyusup meninggalkan cron/layanan/user/kunci
# baru. Kondisi normal dicatat sekali (baseline), lalu setiap laporan membandingkannya.
# File milik skrip ini sendiri tidak dihitung, supaya update/pasang ulang tidak memicu peringatan.
BASELINE="$STATE_DIR/baseline.txt"
MINER_PORTS='3333 4444 5555 6666 7777 8888 9999 14433 14444 45560 45700'
snapshot() { # cetak "jenis|item|sidik" -- cron, layanan systemd di /etc, user login/UID 0, kunci SSH
    local f u uid home shell line fp
    for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* \
             /var/spool/cron/* /var/spool/cron/crontabs/*; do
        [ -f "$f" ] || continue
        case "$f" in /etc/cron.d/gisnet-secure-ssh|*/.placeholder) continue ;; esac
        # 2.20: cron bawaan paket pemindai rootkit yang dipasang skrip ini sendiri (Accurate 2026-10-30).
        case "$f" in */rkhunter|*/chkrootkit) scanner_owned "$f" && continue ;; esac
        echo "cron|$f|$(sha256sum "$f" 2>/dev/null | cut -c1-16)"
    done
    for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/*.wants/*; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        case "$f" in */gisnet-restrict.service) continue ;; esac
        if [ -L "$f" ]; then echo "svc|$f|$(readlink "$f")"; else echo "svc|$f|$(sha256sum "$f" 2>/dev/null | cut -c1-16)"; fi
    done
    while IFS=: read -r u _ uid _ _ home shell; do
        case "$shell" in */nologin|*/false|'') [ "$uid" = 0 ] || continue ;; esac
        [ "$uid" = 0 ] || [ "$uid" -ge 1000 ] 2>/dev/null || continue
        echo "user|$u|uid=$uid $shell"
        [ -f "$home/.ssh/authorized_keys" ] || continue
        while IFS= read -r line; do
            case "$line" in ''|\#*) continue ;; esac
            fp="$(printf '%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}' || true)"
            [ -n "$fp" ] && echo "key|$u $fp|${line##* }"
        done < "$home/.ssh/authorized_keys"
    done < /etc/passwd
    # 2.16: program SUID (cara penyusup kembali jadi root) -- dicari paling sering sekali sejam.
    cached suid 3600 suid_list | while IFS= read -r f; do [ -n "$f" ] && echo "suid|$f|$(sha256sum "$f" 2>/dev/null | cut -c1-16)"; done
    # 2.16: port yang menerima koneksi dari internet -- layanan baru yang tiba-tiba terbuka.
    ss -H -tlnp 2>/dev/null | awk '{
        local = $4; port = local; sub(/.*:/, "", port); addr = local; sub(/:[0-9]+$/, "", addr); gsub(/[\[\]]/, "", addr); sub(/%.*/, "", addr)
        if (addr ~ /^127\./ || addr == "::1" || addr ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|fe80|fd|fc)/) next
        proc = ""; if (match($0, /\(\("[^"]+"/)) proc = substr($0, RSTART + 3, RLENGTH - 4); sub(/ .*/, "", proc)
        if (!seen[port]++) print "port|" port "/tcp|" proc
    }'
}
scanner_owned() { # file milik paket rkhunter/chkrootkit (dpkg/rpm)?
    local o=''
    if have dpkg-query; then o="$(dpkg-query -S "$1" 2>/dev/null || true)"; o="${o%%:*}"
    elif have rpm; then o="$(rpm -qf --qf '%{NAME}' "$1" 2>/dev/null || true)"; fi
    case "$o" in rkhunter|chkrootkit) return 0 ;; *) return 1 ;; esac
}
suid_list() { find / -xdev \( -path /proc -o -path /sys -o -path /run -o -path /snap \) -prune -o -type f -perm -4000 -print 2>/dev/null | sort | head -300; }
cached() { # cached <nama> <detik> <perintah..> -- hasil perintah disimpan, diulang hanya bila sudah basi
    local name="$1" ttl="$2" f; shift 2; f="$STATE_DIR/cache-$name"
    if [ -f "$f" ] && [ $(( $(date +%s) - $(stat -c %Y "$f" 2>/dev/null || echo 0) )) -lt "$ttl" ]; then cat "$f"; return 0; fi
    if [ -w "$STATE_DIR" ]; then "$@" > "$f.tmp" 2>/dev/null; mv -f "$f.tmp" "$f"; cat "$f"; else "$@" 2>/dev/null; fi
}

# ===================================== LONJAKAN LOGIN GAGAL (2.17) ===
# Percobaan login SSH gagal per jam & per 24 jam + IP terbanyak -- aplikasi menandai lonjakan
# mendadak (serangan terarah) walaupun fail2ban sudah memblokir.
SSH_FAIL_RE='Invalid user|Failed (password|publickey|keyboard-interactive)|authenticating user .*\[preauth\]|maximum authentication attempts|Did not receive identification|Unable to negotiate'
ssh_fail_lines() { # ssh_fail_lines <sejak> -- baris log sshd yang gagal (tanpa pipa ke grep -q: lihat catatan pipefail)
    have journalctl && [ "${HAS_SYSTEMD:-0}" -eq 1 ] || return 0
    journalctl -q --no-pager -o cat -u ssh -u sshd --since "$1" 2>/dev/null | grep -E "$SSH_FAIL_RE" || true
}
ssh_fail_fields() { # potongan JSON: "ssh_fail_1h":N,"ssh_fail_24h":N,"ssh_fail_top":[{"ip","count"}]
    local h1 h24 top
    h1="$(ssh_fail_lines '-1h')"
    h24="$(cached sshfail24 1800 ssh_fail_lines '-24h' | wc -l)"
    top="$(awk '{ for (i = 2; i <= NF; i++) if ($i == "port" && $(i-1) ~ /^[0-9a-fA-F.:]+$/ && $(i-1) ~ /[.:]/) { print $(i-1); break } }' <<< "$h1" \
        | sort | uniq -c | sort -rn | head -3 | awk '{printf "%s{\"ip\":\"%s\",\"count\":%d}", (NR>1?",":""), $2, $1}')"
    printf '"ssh_fail_1h":%d,"ssh_fail_24h":%d,"ssh_fail_top":[%s]' "$(grep -c . <<< "$h1" || true)" "${h24:-0}" "$top"
}

# ============================================ JAM & ROOTKIT (2.18) ===
time_json() { # {"synced":bool|null,"ntp":bool|null,"offset_ms":angka|null,"source":"..."}
    local synced=null ntp=null off=null src=none v
    if have timedatectl && [ "${HAS_SYSTEMD:-0}" -eq 1 ]; then
        v="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"; [ "$v" = yes ] && synced=true; [ "$v" = no ] && synced=false
        v="$(timedatectl show -p NTP --value 2>/dev/null || true)"; [ "$v" = yes ] && ntp=true; [ "$v" = no ] && ntp=false
    fi
    if have chronyc && v="$(chronyc -n tracking 2>/dev/null)" && [ -n "$v" ]; then
        src=chrony
        off="$(awk -F': *' '/^System time/{ split($2, a, " "); s = a[1] * 1000; if (a[3] == "slow") s = -s; printf "%.1f", s }' <<< "$v")"
    elif have timedatectl && v="$(timedatectl timesync-status 2>/dev/null)" && [ -n "$v" ]; then
        src=timesyncd
        off="$(awk '/Offset:/{ x = $2; m = 1; if (x ~ /us$/) m = 0.001; else if (x ~ /ms$/) m = 1; else if (x ~ /s$/) m = 1000; gsub(/[^0-9.+-]/, "", x); printf "%.1f", x * m }' <<< "$v")"
    elif have ntpq && ntpq -pn >/dev/null 2>&1; then
        src=ntpd
        off="$(ntpq -pn 2>/dev/null | awk '/^\*/{ printf "%.1f", $9 }')"
    fi
    printf '{"synced":%s,"ntp":%s,"offset_ms":%s,"source":"%s"}' "$synced" "$ntp" "${off:-null}" "$src"
}

# Pemindaian rootkit seminggu sekali, di LATAR BELAKANG (rkhunter bisa beberapa menit);
# laporan hanya membaca hasil terakhir. Sidik jari file (--propupd) hanya diperbarui bila
# ada update paket sejak pemindaian lalu -- supaya update sistem tidak jadi peringatan palsu.
ROOTKIT_RESULT="$STATE_DIR/rootkit.json"
ROOTKIT_EVERY=604800
# Naikkan bila daftar pengecualian di rkhunter_conf_local berubah -> semua server memindai ulang sekali.
ROOTKIT_CONF_VER=2
RKHUNTER_LOCAL=/etc/rkhunter.conf.local
rkhunter_conf_local() { # peringatan palsu yang umum (Debian/Ubuntu/RHEL) -- file dikelola skrip ini
    [ -f "$RKHUNTER_LOCAL" ] && ! grep -q '^# gisnet-secure-ssh' "$RKHUNTER_LOCAL" && return 0  # buatan admin: jangan disentuh
    local root
    # rkhunter hanya membaca sshd_config utama (bukan sshd_config.d) -- samakan dengan isinya,
    # aturan sebenarnya (sshd -T) tetap diperiksa & dilaporkan skrip ini sendiri.
    root="$(awk 'tolower($1)=="permitrootlogin"{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
    {
        echo "# gisnet-secure-ssh: dikelola otomatis, jangan diubah (buat file sendiri tanpa baris ini untuk mengambil alih)"
        echo "ALLOW_SSH_ROOT_USER=${root:-unset}"
        echo "ALLOWHIDDENFILE=/etc/.updated"
        echo "ALLOWHIDDENFILE=/usr/share/man/man5/.containerignore.5.gz"
        echo "ALLOWHIDDENFILE=/usr/share/man/man5/.dockerignore.5.gz"
        echo "ALLOWHIDDENDIR=/etc/.java"
        echo "ALLOWHIDDENDIR=/etc/.git"
        # cPanel mengganti banyak file milik paket sistem -> verifikasi paket selalu "gagal" (Kulo/Iwak/Eson).
        [ -d /usr/local/cpanel ] && echo "PKGMGR=NONE"
    } > "$RKHUNTER_LOCAL.tmp" && mv -f "$RKHUNTER_LOCAL.tmp" "$RKHUNTER_LOCAL"
}
rootkit_last_pkg_change() { # epoch perubahan paket terakhir (dpkg/dnf/yum)
    local t=0 f
    for f in /var/log/dpkg.log /var/lib/dpkg/status /var/lib/rpm/rpmdb.sqlite /var/lib/rpm/Packages /var/log/dnf.rpm.log; do
        [ -e "$f" ] && t=$(( $(stat -c %Y "$f" 2>/dev/null || echo 0) > t ? $(stat -c %Y "$f" 2>/dev/null || echo 0) : t ))
    done
    echo "$t"
}
rootkit_scan() { # dijalankan di latar belakang; menulis $ROOTKIT_RESULT
    local tool='' out warn=0 items='' line n=0 stamp="$STATE_DIR/rootkit-propupd"
    # 2.21: tanpa paket "recommends" -- dulu ikut terpasang server mail (exim4/postfix) di semua server Debian/Ubuntu.
    have rkhunter || APT_NO_RECOMMENDS=1 pkg_install rkhunter >/dev/null 2>&1 || true
    if have rkhunter; then
        tool=rkhunter
        rkhunter_conf_local
        # Paket EPEL (AlmaLinux/RHEL) tidak membawa daftar port backdoor -- unduh sekali.
        [ -s /var/lib/rkhunter/db/backdoorports.dat ] || rkhunter --update --nocolors >/dev/null 2>&1 || true
        if [ ! -f "$stamp" ] || [ "$(rootkit_last_pkg_change)" -gt "$(stat -c %Y "$stamp" 2>/dev/null || echo 0)" ]; then
            rkhunter --propupd --nocolors >/dev/null 2>&1 || true; touch "$stamp"
        fi
        out="$(rkhunter --check --sk --nocolors --rwo 2>/dev/null || true)"
    else
        have chkrootkit || pkg_install chkrootkit >/dev/null 2>&1 || true
        if have chkrootkit; then tool=chkrootkit; out="$(chkrootkit -q 2>/dev/null || true)"; fi
    fi
    if [ -z "$tool" ]; then
        printf '{"tool":null,"at":%s,"warnings":0,"items":[]}' "$(date +%s)" > "$ROOTKIT_RESULT"; return 0
    fi
    while IFS= read -r line; do
        line="$(sed 's/^[[:space:]]*//; s/[[:space:]]*$//' <<< "$line")"
        [ -n "$line" ] || continue
        warn=$((warn + 1))
        [ "$n" -lt 10 ] && { items="$items${items:+,}$(json_str "${line:0:200}")"; n=$((n + 1)); }
    done < <(grep -E 'Warning:|INFECTED|Possible|suspicious|Vulnerable' <<< "$out" || true)
    printf '{"tool":"%s","at":%s,"warnings":%d,"items":[%s]}' "$tool" "$(date +%s)" "$warn" "$items" > "$ROOTKIT_RESULT.tmp"
    mv -f "$ROOTKIT_RESULT.tmp" "$ROOTKIT_RESULT"
    echo "$ROOTKIT_CONF_VER" > "$STATE_DIR/rootkit-conf"
}
rootkit_json() { # hasil terakhir; jalankan pemindaian baru di latar belakang bila sudah > 7 hari
    local age=999999999
    [ -f "$ROOTKIT_RESULT" ] && age=$(( $(date +%s) - $(stat -c %Y "$ROOTKIT_RESULT" 2>/dev/null || echo 0) ))
    # Pengecualian peringatan palsu berubah sejak pemindaian terakhir -> pindai ulang sekarang.
    [ "$(cat "$STATE_DIR/rootkit-conf" 2>/dev/null || true)" = "$ROOTKIT_CONF_VER" ] || age=999999999
    if [ "$age" -ge "$ROOTKIT_EVERY" ] && [ -w "$STATE_DIR" ] && [ "$(id -u)" -eq 0 ] && [ -f "$SELF_INSTALL" ] \
       && ! pgrep -f "gisnet-secure-ssh rootkit-scan" >/dev/null 2>&1; then
        ( GISNET_NONINTERACTIVE=1 nohup nice -n 15 "$SELF_INSTALL" rootkit-scan </dev/null >/dev/null 2>&1 & ) 2>/dev/null || true
    fi
    if [ -f "$ROOTKIT_RESULT" ]; then cat "$ROOTKIT_RESULT"; else printf 'null'; fi
}

# ============================================ WEBSITE & SERTIFIKAT (2.16) ===
web_hosts() { # nama situs di server ini (nginx server_name, Apache ServerName/ServerAlias) -- maks 40
    { grep -rhoE '^\s*server_name\s+[^;]+' /etc/nginx/ 2>/dev/null | sed -E 's/^\s*server_name\s+//'
      grep -rhoiE '^\s*Server(Name|Alias)\s+.+' /etc/apache2/ /etc/httpd/ 2>/dev/null | sed -E 's/^\s*Server(Name|Alias)\s+//I'
    } | tr ' \t' '\n\n' | sed 's/:.*//' | grep -E '^[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,}$' | grep -vE '^(localhost|_)$|\.(local|localdomain|invalid)$' \
      | grep -viE '^(www\.|mail\.|webmail\.|cpanel\.|whm\.|webdisk\.|cpcalendars\.|cpcontacts\.|autodiscover\.|autoconfig\.|ftp\.)' | sort -u | head -40
}
web_leaks_scan() { # baris "host|path" untuk file rahasia yang BENAR-BENAR bisa diunduh (isi dicek)
    have curl || return 0
    local h p body re
    while IFS= read -r h; do
        [ -n "$h" ] || continue
        for p in '/.env:^[A-Z][A-Z0-9_]+=' '/.env.backup:^[A-Z][A-Z0-9_]+=' '/.git/config:\[core\]' \
                 '/info.php:phpinfo\(\)|PHP Version' '/phpinfo.php:phpinfo\(\)|PHP Version' \
                 '/backup.sql:CREATE TABLE|INSERT INTO' '/db.sql:CREATE TABLE|INSERT INTO' '/database.sql:CREATE TABLE|INSERT INTO'; do
            re="${p#*:}"; p="${p%%:*}"
            body="$(curl -sk --max-time 4 --max-filesize 200000 --resolve "$h:443:127.0.0.1" --resolve "$h:80:127.0.0.1" -L --max-redirs 2 \
                    -w '\n@@%{http_code}' "https://$h$p" 2>/dev/null || true)"
            [ "${body##*@@}" = 200 ] || continue
            grep -qE "$re" <<< "${body%@@*}" && echo "$h|$p"
        done
    done < <(web_hosts)
}
web_leaks_json() {
    local out='' h p
    while IFS='|' read -r h p; do
        [ -n "$h" ] && out="$out${out:+,}{\"host\":$(json_str "$h"),\"path\":$(json_str "$p")}"
    done < <(cached webleaks 3600 web_leaks_scan | head -20)
    printf '[%s]' "$out"
}
certs_scan() { # baris "nama|port|sisa-hari" untuk sertifikat yang habis < 21 hari (atau sudah habis)
    have openssl || return 0
    local h port end days
    while IFS= read -r h; do
        [ -n "$h" ] || continue
        for port in 443 465 993 995 2083 2087; do
            case "$port" in 443) ;; *) [ "$h" = "$(hostname -f 2>/dev/null || hostname)" ] || continue ;; esac
            ss -H -tln "sport = :$port" 2>/dev/null | grep -q . || continue
            end="$(echo | timeout 6 openssl s_client -connect "127.0.0.1:$port" -servername "$h" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
            [ -n "$end" ] || continue
            days=$(( ( $(date -d "$end" +%s 2>/dev/null || echo 0) - $(date +%s) ) / 86400 ))
            [ "$days" -lt 21 ] && echo "$h|$port|$days"
        done
    done < <({ web_hosts; hostname -f 2>/dev/null || hostname; } | sort -u)
}
certs_json() {
    local out='' h port days
    while IFS='|' read -r h port days; do
        [ -n "$h" ] && out="$out${out:+,}{\"name\":$(json_str "$h"),\"port\":$port,\"days\":$days}"
    done < <(cached certs 3600 certs_scan | head -20)
    printf '[%s]' "$out"
}
baseline_save() { # baseline_save [jenis] -- tanpa jenis: semuanya; dengan jenis: ganti bagian itu saja
    [ -w "$STATE_DIR" ] || { mkdir -p "$STATE_DIR" 2>/dev/null && chmod 700 "$STATE_DIR"; } || return 0
    # Laporan cron & laporan sesudah update bisa berjalan bersamaan (OMNI 2026-10-30): dulu file
    # dikosongkan lalu ditulis ulang, proses lain membaca file kosong -> baseline hilang. Sekarang
    # dikunci (flock) dan ditulis ke file sementara unik lalu ditukar sekaligus (mv atomik).
    (
        have flock && { exec 9>"$STATE_DIR/baseline.lock"; flock -w 60 9 || true; }
        local now tmp
        now="$(snapshot | sort -u)"
        tmp="$(mktemp "$STATE_DIR/baseline.XXXXXX")"
        {
            echo "# baseline $(date +%s)"
            if [ -n "${1-}" ] && [ -f "$BASELINE" ]; then
                { grep -v "^$1|" "$BASELINE" | grep -v '^#' || true; grep "^$1|" <<< "$now" || true; } | sort -u
            else
                printf '%s\n' "$now"
            fi
        } > "$tmp"
        chmod 600 "$tmp"; mv -f "$tmp" "$BASELINE"
    )
}
changes_json() { # JSON array perubahan sejak baseline + temuan langsung (program di /tmp, koneksi penambang)
    local now base out='' n=0 typ item sig old p f rest
    if [ ! -f "$BASELINE" ]; then baseline_save; printf '[]'; return 0; fi
    # Jenis yang belum ada sama sekali di baseline -- jenis baru dari versi ini, atau bagian yang
    # hilang karena balapan tulis di v2.16 (OMNI 2026-10-30) -- dicatat diam-diam sebagai normal,
    # bukan dilaporkan "baru" semuanya. Server normal selalu punya /etc/crontab & user root.
    for typ in cron svc user key suid port; do grep -q "^$typ|" "$BASELINE" || baseline_save "$typ"; done
    now="$(snapshot | sort -u)"; base="$(grep -v '^#' "$BASELINE" || true)"
    while IFS='|' read -r typ item sig; do
        [ -n "$typ" ] || continue
        old="$(awk -F'|' -v t="$typ" -v i="$item" '$1==t && $2==i {print $3; exit}' <<< "$base")"
        if [ -z "$old" ] && ! grep -qF "$typ|$item|" <<< "$base"; then p=baru
        elif [ "$old" != "$sig" ]; then p=berubah
        else continue; fi
        out="$out${out:+,}{\"type\":\"$typ\",\"item\":$(json_str "${item:0:200}"),\"change\":\"$p\",\"detail\":$(json_str "${sig:0:120}")}"
        n=$((n + 1)); [ "$n" -ge 30 ] && break
    done <<< "$now"
    # Program yang bisa dijalankan di folder sementara -- tempat favorit penyusup.
    while IFS= read -r f; do
        [ -n "$f" ] && [ "$n" -lt 30 ] || continue
        out="$out${out:+,}{\"type\":\"tmpexec\",\"item\":$(json_str "${f:0:200}"),\"change\":\"ada\",\"detail\":$(json_str "$(stat -c '%U %s byte' "$f" 2>/dev/null || true)")}"
        n=$((n + 1))
    done < <(find /tmp /var/tmp /dev/shm -xdev -maxdepth 3 -type f -perm -u+x -size +8k 2>/dev/null | head -10)
    # Koneksi keluar ke port khas kolam penambang kripto.
    while read -r rest; do
        [ -n "$rest" ] && [ "$n" -lt 30 ] || continue
        out="$out${out:+,}{\"type\":\"minerconn\",\"item\":$(json_str "${rest%% *}"),\"change\":\"ada\",\"detail\":$(json_str "${rest#* }")}"
        n=$((n + 1))
    done < <(ss -Htnp state established 2>/dev/null | awk -v ports=" $MINER_PORTS " '{peer=$4; port=peer; sub(/.*:/,"",port); if (index(ports, " " port " ")) { proc=""; if (match($0, /\(\("[^"]+"/)) proc=substr($0, RSTART+3, RLENGTH-4); print peer, proc } }' | head -5)
    printf '[%s]' "$out"
}
cmd_baseline() {
    need_root
    case "${1-show}" in
        accept|terima) baseline_save; c_ok "Kondisi sekarang dicatat sebagai normal (baseline baru)." ;;
        show|lihat|'') echo; echo " Baseline: $(sed -n 's/^# baseline //p' "$BASELINE" 2>/dev/null | head -1 | xargs -r -I{} date -d @{} '+%d/%m/%Y %H:%M' 2>/dev/null || echo 'belum ada')"
                       echo " Perubahan sejak baseline:"; changes_json | grep -oE '"type":"[a-z]+","item":"[^"]*","change":"[a-z]+"' | sed 's/"type":"//; s/","item":"/  /; s/","change":"/  (/; s/"$/)/; s/^/   /' || echo "   (tidak ada)"; echo ;;
        *) die "Perintah baseline tidak dikenal: $1 (show | accept)" ;;
    esac
}

# ========================================= BATASI PORT BERBAHAYA (2.15) ===
# Port (mis. 3306) hanya boleh diakses dari server ini sendiri: tabel nftables sendiri
# "gisnet_restrict" + layanan systemd supaya tetap berlaku setelah reboot.
RESTRICT_LIST="$STATE_DIR/restricted-ports"
RESTRICT_NFT="$STATE_DIR/restrict.nft"
RESTRICT_UNIT=/etc/systemd/system/gisnet-restrict.service
restricted_ports() { sort -un "$RESTRICT_LIST" 2>/dev/null | grep -E '^[0-9]+$' || true; }
restrict_apply() { # tulis & muat aturan dari daftar port
    have nft || { c_warn "nft tidak tersedia -- port tidak bisa dibatasi otomatis."; return 1; }
    local ports v4 v6 list
    list="$(restricted_ports | paste -sd, - | sed 's/,/, /g')"
    if [ -z "$list" ]; then
        nft delete table inet gisnet_restrict 2>/dev/null || true
        rm -f "$RESTRICT_NFT"; systemctl disable --now gisnet-restrict.service >/dev/null 2>&1 || true; rm -f "$RESTRICT_UNIT"
        systemctl daemon-reload >/dev/null 2>&1 || true
        return 0
    fi
    v4="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.' | paste -sd, - | sed 's/,/, /g')"
    v6="$(ip -6 addr show scope global 2>/dev/null | awk '/inet6/{sub(/\/.*/,"",$2); print $2}' | paste -sd, - | sed 's/,/, /g')"
    {
        echo "# gis-secured: port berbahaya hanya dari server ini sendiri (dibuat $(date '+%Y-%m-%d %H:%M'))"
        echo "table inet gisnet_restrict"
        echo "delete table inet gisnet_restrict"
        echo "table inet gisnet_restrict {"
        echo "    chain input {"
        echo "        type filter hook input priority -5; policy accept;"
        echo "        tcp dport { $list } iifname \"lo\" accept"
        [ -n "$v4" ] && echo "        tcp dport { $list } ip saddr { $v4 } accept"
        [ -n "$v6" ] && echo "        tcp dport { $list } ip6 saddr { $v6 } accept"
        echo "        tcp dport { $list } drop"
        echo "    }"
        echo "}"
    } > "$RESTRICT_NFT.tmp"
    nft -c -f "$RESTRICT_NFT.tmp" || { rm -f "$RESTRICT_NFT.tmp"; c_err "Aturan nftables tidak valid -- dibatalkan."; return 1; }
    mv -f "$RESTRICT_NFT.tmp" "$RESTRICT_NFT"; chmod 600 "$RESTRICT_NFT"
    nft -f "$RESTRICT_NFT"
    if [ "${HAS_SYSTEMD:-0}" -eq 1 ]; then
        printf '[Unit]\nDescription=gis-secured: batasi port berbahaya ke server ini sendiri\nAfter=network-online.target nftables.service firewalld.service ufw.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=%s -f %s\n\n[Install]\nWantedBy=multi-user.target\n' \
            "$(command -v nft)" "$RESTRICT_NFT" > "$RESTRICT_UNIT"
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl enable gisnet-restrict.service >/dev/null 2>&1 || true
    fi
    c_ok "Port dibatasi ke server ini sendiri: $list."
}
cmd_restrict() { # restrict [list | add <port> | remove <port>]
    need_root; detect_os
    local p="${2-}"
    case "${1-list}" in
        list|''|lihat) echo " Port dibatasi: $(restricted_ports | paste -sd' ' - | sed 's/^$/(tidak ada)/')" ;;
        add|tambah|remove|hapus)
            [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || die "Port tidak valid: ${p:-kosong}"
            case ",$(ssh_ports)," in *",$p,"*) die "Port $p dipakai SSH -- tidak boleh dibatasi (server bisa terkunci)." ;; esac
            mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"; touch "$RESTRICT_LIST"
            if [ "$1" = add ] || [ "$1" = tambah ]; then echo "$p" >> "$RESTRICT_LIST"
            else grep -vx "$p" "$RESTRICT_LIST" > "$RESTRICT_LIST.tmp" || true; mv -f "$RESTRICT_LIST.tmp" "$RESTRICT_LIST"; fi
            restricted_ports > "$RESTRICT_LIST.tmp"; mv -f "$RESTRICT_LIST.tmp" "$RESTRICT_LIST"
            restrict_apply ;;
        *) die "Perintah restrict tidak dikenal (list | add <port> | remove <port>)" ;;
    esac
}
report_apply_restrict() { # {"port_restrict":{"action":"add|remove","port":N}} -- perlu izin port
    local m action port
    m="$(printf '%s' "$1" | grep -oE '"port_restrict" *: *\{ *"action" *: *"(add|remove)" *, *"port" *: *[0-9]{1,5} *\}' | head -1 || true)"
    [ -n "$m" ] || return 0
    if [ ! -f "$ALLOW_PORT" ]; then c_warn "Aplikasi meminta batasi port, tetapi server ini tidak mengizinkan (report allow-port on)."; return 0; fi
    action="$(sed -E 's/.*"action" *: *"([a-z]+)".*/\1/' <<< "$m")"; port="$(sed -E 's/.*"port" *: *([0-9]+).*/\1/' <<< "$m")"
    logger -t gisnet-secure-ssh "batasi port $action $port diminta dari aplikasi" 2>/dev/null || true
    ( cmd_restrict "$action" "$port" ) >> /var/log/gisnet-secure-ssh-restrict.log 2>&1 || true
    ( GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" report now quiet </dev/null >/dev/null 2>&1 & ) 2>/dev/null || true
}
report_apply_baseline() { # {"baseline_accept":true} -- tandai kondisi sekarang normal (izin whitelist/port)
    grep -qE '"baseline_accept" *: *true' <<< "$1" || return 0
    if ! allows_whitelist; then c_warn "Aplikasi meminta terima baseline, tetapi server ini tidak mengizinkan."; return 0; fi
    logger -t gisnet-secure-ssh "baseline diterima dari aplikasi" 2>/dev/null || true
    baseline_save
    ( GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" report now quiet </dev/null >/dev/null 2>&1 & ) 2>/dev/null || true
}

# ======================================================== LAPORAN APLIKASI ===
json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\000-\037')"; }
report_json() {
    detect_os
    local running=false jails='' j banned total first=1 recent='' pw root ports ip
    have fail2ban-client && fail2ban-client ping >/dev/null 2>&1 && running=true
    if [ "$running" = true ]; then
        for j in $(f2b_jails); do
            banned="$(fail2ban-client status "$j" 2>/dev/null | awk -F: '/Currently banned/{gsub(/[ 	]/,"",$2); print $2}')"
            total="$(fail2ban-client status "$j" 2>/dev/null | awk -F: '/Total banned/{gsub(/[ 	]/,"",$2); print $2}')"
            [ "$first" -eq 1 ] && first=0 || jails="$jails,"
            jails="$jails{\"name\":$(json_str "$j"),\"banned\":${banned:-0},\"total\":${total:-0}}"
        done
    fi
    first=1
    if [ -f "$F2B_LOG" ]; then
        while read -r d t jail bip; do
            [ "$first" -eq 1 ] && first=0 || recent="$recent,"
            recent="$recent{\"at\":$(json_str "$d $t"),\"jail\":$(json_str "$jail"),\"ip\":$(json_str "$bip")}"
        done < <(grep -E 'NOTICE +\[[^]]+\] Ban ' "$F2B_LOG" 2>/dev/null | tail -10 | awk '{for(i=1;i<=NF;i++) if($i=="Ban"){j=$(i-1); gsub(/[\[\]]/,"",j); print $1, substr($2,1,8), j, $(i+1)}}')
    fi
    pw="$("$SSHD_BIN" -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}')"
    root="$("$SSHD_BIN" -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2}')"
    ports="$(ssh_ports)"
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    local allow=false reboot_req=false sched allow_up=false shared=false banned_ips='' allow_port=false
    [ -f "$ALLOW_PORT" ] && allow_port=true
    [ -f "$ALLOW_REBOOT" ] && allow=true
    [ -f "$ALLOW_UPDATE" ] && allow_up=true
    [ ! -f "$SHARED_OFF" ] && fail2ban-client status gisnet-shared >/dev/null 2>&1 && shared=true
    if [ "$running" = true ]; then
        banned_ips="$(for j in sshd recidive; do fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p'; done | tr ' ' '\n' | sed '/^$/d' | sort -u | head -300 | awk '{printf "%s\"%s\"", (NR>1?",":""), $0}')"
    fi
    [ -f /var/run/reboot-required ] && reboot_req=true
    sched="$(reboot_scheduled_at)"
    local allow_wl=false allow_dns=false dns_good=false allow_key=false
    [ -f "$ALLOW_KEY" ] && allow_key=true
    allows_whitelist && allow_wl=true
    allows_dns && allow_dns=true
    dns_ok && dns_good=true
    printf '{"version":%s,"hostname":%s,"os":%s,"ip":%s,"uptime_seconds":%s,"fail2ban_running":%s,"jails":[%s],"whitelist":%s,"ssh":{"ports":%s,"password_auth":%s,"root_login":%s},"auto_update":%s,"recent_bans":[%s],"allow_reboot":%s,"reboot_required":%s,"reboot_scheduled_at":%s,"allow_update":%s,"allow_port":%s,"allow_whitelist":%s,"allow_dns":%s,"allow_key":%s,"ssh_keys":[%s],"dns":{"servers":%s,"manager":%s,"ok":%s,"last_change":%s},"shared_blocklist":%s,"banned_ips":[%s],%s,"generated_at":%s}\n' \
        "$(json_str "$SCRIPT_VERSION")" "$(json_str "$(hostname)")" "$(json_str "$OS_NAME")" "$(json_str "$ip")" \
        "$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)" "$running" "$jails" \
        "$(json_str "$(wl_current | paste -sd' ' - || true)")" "$(json_str "$ports")" "$(json_str "${pw:-}")" "$(json_str "${root:-}")" \
        "$(json_str "$(auto_update_status)")" "$recent" "$allow" "$reboot_req" "${sched:-null}" "$allow_up" "$allow_port" \
        "$allow_wl" "$allow_dns" "$allow_key" "$(keys_json)" "$(json_str "$(dns_servers | head -6 | paste -sd' ' - || true)")" "$(json_str "$(dns_manager)")" "$dns_good" \
        "$(json_str "$(head -c 300 "$DNS_RESULT" 2>/dev/null || true)")" \
        "$shared" "$banned_ips" "$(checks_fields)" "$(date +%s)"
}
reboot_scheduled_at() { # epoch detik jadwal reboot systemd, kosong bila tidak ada
    local usec
    usec="$(sed -n 's/^USEC=//p' /run/systemd/shutdown/scheduled 2>/dev/null | head -1 || true)"
    [[ "$usec" =~ ^[0-9]+$ ]] && echo $((usec / 1000000))
    return 0
}
report_apply_reboot() { # report_apply_reboot <balasan-json> -- hanya now|midnight|cancel, hanya bila diizinkan
    local when
    when="$(printf '%s' "$1" | grep -oE '"reboot" *: *"(now|midnight|cancel)"' | grep -oE '(now|midnight|cancel)' | head -1 || true)"
    [ -n "$when" ] || return 0
    if [ ! -f "$ALLOW_REBOOT" ]; then c_warn "Aplikasi meminta reboot ($when), tetapi server ini tidak mengizinkan."; return 0; fi
    case "$when" in
        now)      shutdown -r +1 "Reboot diminta dari aplikasi GISNET" >/dev/null 2>&1 && c_ok "Reboot dijadwalkan 1 menit lagi (permintaan aplikasi)." ;;
        midnight) shutdown -r 00:00 "Reboot terjadwal dari aplikasi GISNET" >/dev/null 2>&1 && c_ok "Reboot dijadwalkan jam 00.00 (permintaan aplikasi)." ;;
        cancel)   shutdown -c >/dev/null 2>&1 || true; c_ok "Jadwal reboot dibatalkan (permintaan aplikasi)." ;;
    esac
    logger -t gisnet-secure-ssh "reboot $when diminta dari aplikasi" 2>/dev/null || true
    # Laporkan jadwal barunya langsung, supaya aplikasi tidak menunggu 5 menit.
    report_json | curl -sS -o /dev/null --max-time 20 -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -H "Authorization: Bearer $REPORT_TOKEN" --data-binary @- "$REPORT_URL" >/dev/null 2>&1 || true
}
report_send() {
    [ -f "$REPORT_CONF" ] || die "Laporan belum diatur: report setup <url> <token>"
    # shellcheck disable=SC1090
    . "$REPORT_CONF"
    have curl || pkg_install curl >/dev/null 2>&1 || die "curl tidak tersedia."
    local out code body resolve=()
    mapfile -t resolve < <(report_resolve_args)
    out="$(report_json | curl -sS -w '\n%{http_code}' --max-time 20 ${resolve[@]+"${resolve[@]}"} -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -H "Authorization: Bearer $REPORT_TOKEN" --data-binary @- "$REPORT_URL" 2>/dev/null || echo 000)"
    code="${out##*$'\n'}"; body="${out%$'\n'*}"; [ "$body" = "$out" ] && body=''
    case "$code" in 2*) [ "${1-}" = quiet ] || c_ok "Laporan terkirim ($code)." ;; *) c_err "Laporan gagal (HTTP $code)."; return 1 ;; esac
    [ "${#resolve[@]}" -gt 0 ] && [ "${1-}" != quiet ] && c_warn "DNS server ini tidak bisa mencari nama -- laporan dikirim lewat IP aplikasi terakhir."
    report_apply_reboot "$body"
    report_apply_shared "$body"
    report_apply_update "$body"
    report_apply_port "$body"
    report_apply_whitelist "$body"
    report_apply_dns "$body"
    report_apply_key "$body"
    report_apply_restrict "$body"
    report_apply_baseline "$body"
}
report_host() { # nama host dari REPORT_URL
    printf '%s' "${REPORT_URL-}" | sed -E 's#^[a-zA-Z]+://##; s#[/:?].*$##'
}
report_resolve_args() { # cetak "--resolve host:port:ip" bila DNS mati tetapi IP aplikasi pernah tersimpan
    local host port ip
    host="$(report_host)"; [ -n "$host" ] || return 0
    port="$(printf '%s' "$REPORT_URL" | sed -nE 's#^[a-zA-Z]+://[^/:]+:([0-9]+).*#\1#p')"
    [ -n "$port" ] || { case "$REPORT_URL" in http://*) port=80 ;; *) port=443 ;; esac; }
    ip="$(timeout 6 getent ahosts "$host" 2>/dev/null | awk '$2=="STREAM"{print $1; exit}' || true)"
    if [ -n "$ip" ]; then
        printf '%s\n' "$ip" > "$REPORT_IP_CACHE" 2>/dev/null || true
        return 0
    fi
    ip="$(head -1 "$REPORT_IP_CACHE" 2>/dev/null || true)"
    valid_ip "$ip" || return 0
    case "$ip" in *:*) ip="[$ip]" ;; esac
    printf '%s\n' --resolve "$host:$port:$ip"
}
report_apply_port() { # report_apply_port <balasan-json> -- {"ssh_port":{"action":"add|remove_old","port":N}}, perlu izin
    local m action port
    m="$(printf '%s' "$1" | grep -oE '"ssh_port" *: *\{ *"action" *: *"(add|remove_old)" *, *"port" *: *[0-9]{1,5} *\}' | head -1 || true)"
    [ -n "$m" ] || return 0
    action="$(printf '%s' "$m" | grep -oE '(add|remove_old)' | head -1)"
    port="$(printf '%s' "$m" | grep -oE '[0-9]{1,5} *\}' | tr -dc '0-9')"
    if [ ! -f "$ALLOW_PORT" ]; then c_warn "Aplikasi meminta ganti port SSH, tetapi server ini tidak mengizinkan."; return 0; fi
    if ! { [ "$port" = 22 ] || { [ "$port" -ge 1024 ] && [ "$port" -le 65535 ]; }; }; then
        c_warn "Port $port ditolak (hanya 22 atau 1024-65535)."; return 0
    fi
    logger -t gisnet-secure-ssh "port SSH $action $port diminta dari aplikasi" 2>/dev/null || true
    # Jalan di latar belakang: SSH dimuat ulang, lalu laporan baru dikirim supaya aplikasi melihat hasilnya.
    ( {
        if [ "$action" = remove_old ]; then GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" port "$port" --remove-old </dev/null
        else GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" port "$port" </dev/null; fi
        GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" report now quiet </dev/null
      } >> /var/log/gisnet-secure-ssh-port.log 2>&1 & ) 2>/dev/null || true
    c_ok "Permintaan port SSH ($action $port) dijalankan (log: /var/log/gisnet-secure-ssh-port.log)."
}
report_apply_shared() { # report_apply_shared <balasan-json> -- IP dari server lain, port SSH saja
    [ -f "$SHARED_OFF" ] && return 0
    fail2ban-client status gisnet-shared >/dev/null 2>&1 || return 0
    local list ip n=0 current wl
    list="$(printf '%s' "$1" | grep -oE '"shared_ban" *: *\[[^]]*\]' | grep -oE '"[0-9A-Fa-f:.]+"' | tr -d '"' | head -300 || true)"
    [ -n "$list" ] || return 0
    current=" $(fail2ban-client status gisnet-shared 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p') "
    wl=" $(wl_current | tr '\n' ' ') "
    for ip in $list; do
        valid_ip "$ip" || continue
        case "$current" in *" $ip "*) continue ;; esac
        case "$wl" in *" $ip "*) continue ;; esac
        fail2ban-client set gisnet-shared banip "$ip" >/dev/null 2>&1 && n=$((n + 1))
    done
    [ "$n" -gt 0 ] && logger -t gisnet-secure-ssh "blokir bersama: $n IP baru dari aplikasi" 2>/dev/null
    return 0
}
report_apply_update() { # report_apply_update <balasan-json> -- hanya bila diizinkan; skrip diunduh dari alamat tetap
    printf '%s' "$1" | grep -qE '"update" *: *true' || return 0
    if [ ! -f "$ALLOW_UPDATE" ]; then c_warn "Aplikasi meminta update skrip, tetapi server ini tidak mengizinkan."; return 0; fi
    logger -t gisnet-secure-ssh "update skrip diminta dari aplikasi" 2>/dev/null || true
    # Jalan di latar belakang: update memasang ulang & mengirim laporan baru sendiri.
    ( GISNET_NONINTERACTIVE=1 nohup "$SELF_INSTALL" update --quiet >> /var/log/gisnet-secure-ssh-update.log 2>&1 & ) 2>/dev/null || true
    c_ok "Update skrip dimulai (log: /var/log/gisnet-secure-ssh-update.log)."
}
# ===================================================== WHITELIST & DNS (2.9) ===
# Diubah dari aplikasi lewat balasan laporan. Izin: report allow-whitelist / allow-dns on,
# atau otomatis bila ganti port SSH sudah diizinkan (izin yang lebih berisiko).
allows_whitelist() { [ -f "$ALLOW_WHITELIST" ] || [ -f "$ALLOW_PORT" ]; }
allows_dns()       { [ -f "$ALLOW_DNS" ] || [ -f "$ALLOW_PORT" ]; }

wl_too_wide() { # subnet terlalu luas untuk whitelist dari aplikasi (melumpuhkan fail2ban)
    local ip="$1" bits
    case "$ip" in */*) bits="${ip##*/}" ;; *) return 1 ;; esac
    case "$ip" in *:*) [ "$bits" -lt 32 ] ;; *) [ "$bits" -lt 16 ] ;; esac
}
report_apply_whitelist() { # {"whitelist_change":{"add":["ip",..],"remove":["ip",..]}}
    local m add='' remove='' ip ok_add=() ok_remove=()
    m="$(printf '%s' "$1" | grep -oE '"whitelist_change" *: *\{[^}]*\}' | head -1 || true)"
    [ -n "$m" ] || return 0
    if ! allows_whitelist; then c_warn "Aplikasi meminta ubah whitelist, tetapi server ini tidak mengizinkan."; return 0; fi
    # Ambil isi [...] saja: kata kunci "add" sendiri lolos pola heksadesimal IPv6.
    add="$(printf '%s' "$m" | grep -oE '"add" *: *\[[^]]*\]' | sed 's/^[^[]*\[//' | grep -oE '"[0-9A-Fa-f:./]+"' | tr -d '"' | head -20 || true)"
    remove="$(printf '%s' "$m" | grep -oE '"remove" *: *\[[^]]*\]' | sed 's/^[^[]*\[//' | grep -oE '"[0-9A-Fa-f:./]+"' | tr -d '"' | head -20 || true)"
    for ip in $add; do
        if ! valid_ip "$ip"; then c_warn "Whitelist: $ip bukan IP yang valid -- dilewati."
        elif wl_too_wide "$ip"; then c_warn "Whitelist: $ip terlalu luas (minimal /16 IPv4, /32 IPv6) -- dilewati."
        else ok_add+=("$ip"); fi
    done
    for ip in $remove; do valid_ip "$ip" && ok_remove+=("$ip"); done
    [ "${#ok_add[@]}" -gt 0 ] || [ "${#ok_remove[@]}" -gt 0 ] || return 0
    logger -t gisnet-secure-ssh "whitelist dari aplikasi: tambah ${ok_add[*]-} hapus ${ok_remove[*]-}" 2>/dev/null || true
    {
        [ "${#ok_add[@]}" -gt 0 ] && wl_add "${ok_add[@]}"
        [ "${#ok_remove[@]}" -gt 0 ] && wl_remove "${ok_remove[@]}"
    } >> /var/log/gisnet-secure-ssh-whitelist.log 2>&1 || true
    c_ok "Whitelist diperbarui dari aplikasi (log: /var/log/gisnet-secure-ssh-whitelist.log)."
    # Laporan baru supaya aplikasi langsung melihat whitelist terbaru.
    ( GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" report now quiet </dev/null >/dev/null 2>&1 & ) 2>/dev/null || true
}

dns_manager() { # siapa yang mengatur /etc/resolv.conf
    local ns
    ns="$(awk '$1=="nameserver"{print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
    if [ "$ns" = 127.0.0.53 ] && have resolvectl; then echo systemd-resolved
    elif have nmcli && systemctl is-active --quiet NetworkManager 2>/dev/null && grep -q 'NetworkManager' /etc/resolv.conf 2>/dev/null; then echo networkmanager
    elif [ -L /etc/resolv.conf ]; then echo "symlink:$(readlink -f /etc/resolv.conf)"
    else echo file; fi
}
dns_servers() { # DNS yang benar-benar dipakai, satu per baris
    if [ "$(dns_manager)" = systemd-resolved ]; then
        resolvectl dns 2>/dev/null | sed 's/^[^:]*://' | tr ' ' '\n' | sed '/^$/d; s/#.*//' | awk '!seen[$0]++'
    else
        awk '$1=="nameserver"{print $2}' /etc/resolv.conf 2>/dev/null
    fi
}
dns_test_host() { # nama yang diuji: alamat aplikasi bila laporan aktif
    local h=''
    # shellcheck disable=SC1090
    [ -f "$REPORT_CONF" ] && h="$( . "$REPORT_CONF"; report_host )"
    echo "${h:-raw.githubusercontent.com}"
}
dns_ok() { timeout 6 getent ahosts "$(dns_test_host)" >/dev/null 2>&1; }

dns_set() { # dns_set <ip> [ip] [ip] [ip] -- ganti DNS, uji, kembalikan otomatis bila gagal
    local mgr ip v4='' v6='' bak con dev old ok=0 when max=3
    mgr="$(dns_manager)"; when="$(date '+%Y-%m-%d %H:%M')"
    # glibc hanya membaca 3 "nameserver" pertama di resolv.conf; systemd-resolved tidak terbatas.
    [ "$mgr" = systemd-resolved ] && max=4
    if [ $# -lt 1 ] || [ $# -gt "$max" ]; then
        [ $# -gt 3 ] && printf '%s gagal: %s alamat DNS -- server ini (%s) hanya memakai 3 pertama, DNS tidak diubah\n' "$when" "$#" "$mgr" > "$DNS_RESULT"
        die "Isi 1 sampai $max alamat DNS$([ "$max" -eq 3 ] && echo " (Linux hanya membaca 3 nameserver pertama di /etc/resolv.conf; 4 alamat hanya untuk systemd-resolved)")."
    fi
    for ip in "$@"; do
        case "$ip" in */*) die "DNS harus alamat IP tunggal, bukan subnet: $ip" ;; esac
        valid_ip "$ip" || die "Alamat DNS tidak valid: $ip"
        case "$ip" in *:*) v6="$v6 $ip" ;; *) v4="$v4 $ip" ;; esac
    done
    v4="${v4# }"; v6="${v6# }"
    bak="$STATE_DIR/dns-backup-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$bak"; chmod 700 "$STATE_DIR" "$bak"
    case "$mgr" in
        networkmanager)
            con="$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: '$2!="" && $2!="lo"{print $1; exit}')"
            dev="$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: '$2!="" && $2!="lo"{print $2; exit}')"
            [ -n "$con" ] || die "Koneksi NetworkManager aktif tidak ditemukan."
            # Satu file per kolom: alamat IPv6 berisi ':' yang bentrok dengan pemisah nmcli -g.
            for old in ipv4.dns ipv4.ignore-auto-dns ipv6.dns ipv6.ignore-auto-dns; do
                nmcli -g "$old" con show "$con" 2>/dev/null | sed 's/\\:/:/g' > "$bak/nm-$old"
            done
            nmcli con mod "$con" ipv4.dns "$v4" ipv4.ignore-auto-dns "$([ -n "$v4" ] && echo yes || echo no)" >/dev/null 2>&1 || true
            nmcli con mod "$con" ipv6.dns "$v6" ipv6.ignore-auto-dns "$([ -n "$v6" ] && echo yes || echo no)" >/dev/null 2>&1 || true
            nmcli dev reapply "$dev" >/dev/null 2>&1 || nmcli con up "$con" >/dev/null 2>&1 || true ;;
        systemd-resolved)
            mkdir -p /etc/systemd/resolved.conf.d
            [ -f /etc/systemd/resolved.conf.d/gisnet-dns.conf ] && cp -a /etc/systemd/resolved.conf.d/gisnet-dns.conf "$bak/"
            printf '# gis-secured: DNS dari aplikasi / perintah dns set (%s)\n[Resolve]\nDNS=%s\nDomains=~.\n' "$when" "$*" > /etc/systemd/resolved.conf.d/gisnet-dns.conf
            systemctl restart systemd-resolved >/dev/null 2>&1 || true ;;
        file)
            cp -a /etc/resolv.conf "$bak/resolv.conf"
            { grep -vE '^[[:space:]]*nameserver[[:space:]]' /etc/resolv.conf 2>/dev/null | grep -v '^# gis-secured'
              echo "# gis-secured: DNS diganti $when"
              for ip in "$@"; do echo "nameserver $ip"; done; } > /etc/resolv.conf.gisnet-tmp
            cat /etc/resolv.conf.gisnet-tmp > /etc/resolv.conf; rm -f /etc/resolv.conf.gisnet-tmp ;;
        *)
            rmdir "$bak" 2>/dev/null || true
            printf '%s gagal: /etc/resolv.conf diatur %s -- ubah manual\n' "$when" "${mgr#symlink:}" > "$DNS_RESULT"
            die "/etc/resolv.conf diatur oleh ${mgr#symlink:} -- DNS tidak diubah, ubah manual." ;;
    esac
    sleep 3
    for _ in 1 2 3; do dns_ok && { ok=1; break; }; sleep 2; done
    if [ "$ok" -eq 1 ]; then
        printf '%s berhasil: %s (%s)\n' "$when" "$*" "$mgr" > "$DNS_RESULT"
        c_ok "DNS diganti ke: $* ($mgr) -- $(dns_test_host) bisa ditemukan."
        logger -t gisnet-secure-ssh "DNS diganti ke $*" 2>/dev/null || true
        return 0
    fi
    # Gagal: kembalikan pengaturan lama supaya server tidak kehilangan DNS.
    case "$mgr" in
        networkmanager)
            nmcli con mod "$con" ipv4.dns "$(tr ',' ' ' < "$bak/nm-ipv4.dns")" ipv4.ignore-auto-dns "$(cat "$bak/nm-ipv4.ignore-auto-dns" 2>/dev/null || echo no)" >/dev/null 2>&1 || true
            nmcli con mod "$con" ipv6.dns "$(tr ',' ' ' < "$bak/nm-ipv6.dns")" ipv6.ignore-auto-dns "$(cat "$bak/nm-ipv6.ignore-auto-dns" 2>/dev/null || echo no)" >/dev/null 2>&1 || true
            nmcli dev reapply "$dev" >/dev/null 2>&1 || nmcli con up "$con" >/dev/null 2>&1 || true ;;
        systemd-resolved)
            if [ -f "$bak/gisnet-dns.conf" ]; then cp -a "$bak/gisnet-dns.conf" /etc/systemd/resolved.conf.d/; else rm -f /etc/systemd/resolved.conf.d/gisnet-dns.conf; fi
            systemctl restart systemd-resolved >/dev/null 2>&1 || true ;;
        file) cat "$bak/resolv.conf" > /etc/resolv.conf ;;
    esac
    printf '%s gagal: %s tidak bisa mencari %s -- dikembalikan ke DNS lama\n' "$when" "$*" "$(dns_test_host)" > "$DNS_RESULT"
    logger -t gisnet-secure-ssh "ganti DNS ke $* gagal, dikembalikan" 2>/dev/null || true
    die "DNS $* tidak bisa mencari $(dns_test_host) -- pengaturan lama dikembalikan."
}
report_apply_dns() { # {"dns_change":{"servers":["ip","ip"]}}
    local m list
    m="$(printf '%s' "$1" | grep -oE '"dns_change" *: *\{ *"servers" *: *\[[^]]*\] *\}' | head -1 || true)"
    [ -n "$m" ] || return 0
    if ! allows_dns; then c_warn "Aplikasi meminta ganti DNS, tetapi server ini tidak mengizinkan."; return 0; fi
    list="$(printf '%s' "$m" | sed 's/^[^[]*\[//' | grep -oE '"[0-9A-Fa-f:.]+"' | tr -d '"' | head -4 | paste -sd' ' -)"
    [ -n "$list" ] || return 0
    logger -t gisnet-secure-ssh "ganti DNS ke $list diminta dari aplikasi" 2>/dev/null || true
    # Latar belakang: uji + kembalikan otomatis, lalu kirim laporan baru berisi hasilnya.
    # shellcheck disable=SC2086
    ( { GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" dns set $list </dev/null
        GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" report now quiet </dev/null
      } >> /var/log/gisnet-secure-ssh-dns.log 2>&1 & ) 2>/dev/null || true
    c_ok "Permintaan ganti DNS ($list) dijalankan (log: /var/log/gisnet-secure-ssh-dns.log)."
}
keys_json() { # kunci SSH root untuk laporan: [{"type","comment","fp"}] -- tanpa isi kunci
    local file line tmp type comment fp first=1
    file="$(awk -F: '$1=="root"{print $6}' /etc/passwd)/.ssh/authorized_keys"
    [ -f "$file" ] || return 0
    tmp="$(mktemp)"
    while IFS= read -r line; do
        case "$line" in ''|\#*) continue ;; esac
        printf '%s\n' "$line" > "$tmp"
        fp="$(ssh-keygen -lf "$tmp" 2>/dev/null | awk '{print $2}' || true)"
        type="$(printf '%s' "$line" | grep -oE '(ssh-ed25519|ssh-rsa|ecdsa-sha2-[a-z0-9]+|sk-[a-z0-9@.-]+)' | head -1 || true)"
        comment="$(printf '%s' "$line" | awk -v t="$type" '{for(i=1;i<=NF;i++) if($i==t){c=""; for(j=i+2;j<=NF;j++) c=c (c?" ":"") $j; print c; exit}}')"
        [ "$first" -eq 1 ] || printf ','
        first=0
        printf '{"type":%s,"comment":%s,"fp":%s}' "$(json_str "$type")" "$(json_str "${comment:0:100}")" "$(json_str "$fp")"
    done < <(head -50 "$file")
    rm -f "$tmp"
}
report_apply_key() { # {"ssh_key":{"action":"add","key":"ssh-ed25519 AAAA.. nama"}} / {"action":"remove","fp":"SHA256:.."}
    local m action key fp file line tmp idx=0 sel=''
    m="$(printf '%s' "$1" | grep -oE '"ssh_key" *: *\{ *"action" *: *"(add|remove)" *, *"(key|fp)" *: *"[^"]+" *\}' | head -1 || true)"
    [ -n "$m" ] || return 0
    if [ ! -f "$ALLOW_KEY" ]; then c_warn "Aplikasi meminta ubah kunci SSH, tetapi server ini tidak mengizinkan."; return 0; fi
    action="$(printf '%s' "$m" | sed -E 's/.*"action" *: *"([a-z]+)".*/\1/')"
    {
        if [ "$action" = add ]; then
            key="$(printf '%s' "$m" | sed -E 's/.*"key" *: *"([^"]+)".*/\1/')"
            logger -t gisnet-secure-ssh "kunci SSH ${key##* } ditambahkan dari aplikasi" 2>/dev/null || true
            ( key_add root "$key" )   # subshell: kunci tidak valid tidak menghentikan laporan
        else
            fp="$(printf '%s' "$m" | sed -E 's/.*"fp" *: *"([^"]+)".*/\1/')"
            file="$(key_file_of root)"; tmp="$(mktemp)"
            while IFS= read -r line; do
                case "$line" in ''|\#*) continue ;; esac
                idx=$((idx + 1)); printf '%s\n' "$line" > "$tmp"
                [ "$(ssh-keygen -lf "$tmp" 2>/dev/null | awk '{print $2}')" = "$fp" ] && { sel="$idx"; break; }
            done < "$file"
            rm -f "$tmp"
            if [ -n "$sel" ]; then
                logger -t gisnet-secure-ssh "kunci SSH $fp dihapus dari aplikasi" 2>/dev/null || true
                ( key_remove root "$sel" )   # subshell: die (mis. kunci terakhir) tidak menghentikan laporan
            else c_warn "Kunci $fp tidak ditemukan -- tidak ada yang dihapus."; fi
        fi
    } >> /var/log/gisnet-secure-ssh-key.log 2>&1 || true
    c_ok "Permintaan kunci SSH ($action) dijalankan (log: /var/log/gisnet-secure-ssh-key.log)."
    ( GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" report now quiet </dev/null >/dev/null 2>&1 & ) 2>/dev/null || true
}
cmd_dns() {
    case "${1-show}" in
        show|lihat|'')
            echo; echo " DNS dipakai : $(dns_servers | paste -sd' ' - || true)"
            echo " Diatur oleh : $(dns_manager)"
            echo " Uji nama    : $(dns_test_host) -> $(dns_ok && echo bisa || echo 'GAGAL')"
            [ -f "$DNS_RESULT" ] && echo " Terakhir    : $(cat "$DNS_RESULT")"
            echo ;;
        set|ganti) need_root; shift; dns_set "$@" ;;
        *) die "Perintah dns tidak dikenal: $1 (show | set <ip> [ip] [ip] [ip])" ;;
    esac
}

allow_all_set() { # allow_all_set on|off -- semua izin perintah dari aplikasi sekaligus, tanpa mengirim laporan
    local f
    if [ "$1" = on ]; then
        mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
        for f in "$ALLOW_REBOOT" "$ALLOW_UPDATE" "$ALLOW_PORT" "$ALLOW_WHITELIST" "$ALLOW_DNS" "$ALLOW_KEY"; do touch "$f"; chmod 600 "$f"; done
        c_ok "SEMUA perintah dari aplikasi diizinkan: reboot, update skrip, port SSH, whitelist, DNS, kunci SSH root."
    else
        rm -f "$ALLOW_REBOOT" "$ALLOW_UPDATE" "$ALLOW_PORT" "$ALLOW_WHITELIST" "$ALLOW_DNS" "$ALLOW_KEY"
        c_ok "Semua perintah dari aplikasi dicabut (laporan status tetap jalan)."
    fi
}
allow_reboot_set() { # allow_reboot_set on|off -- tanpa mengirim laporan
    if [ "$1" = on ]; then
        mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"; touch "$ALLOW_REBOOT"; chmod 600 "$ALLOW_REBOOT"
        c_ok "Reboot dari aplikasi DIIZINKAN (hanya reboot sekarang / jam 00.00 / batal)."
    else
        rm -f "$ALLOW_REBOOT"; c_ok "Reboot dari aplikasi tidak diizinkan."
    fi
}
allow_reboot_choose() { # allow_reboot_choose yes|no|ask -- ask: tanya bila ada terminal & belum diizinkan
    case "$1" in
        yes) allow_reboot_set on ;;
        no)  allow_reboot_set off ;;
        *)
            if [ -f "$ALLOW_REBOOT" ]; then c_info "Reboot dari aplikasi sudah diizinkan (cabut: report allow-reboot off)."
            elif [ -n "$TTY" ]; then
                echo
                echo "Aplikasi bisa meminta server ini reboot (sekarang / jam 00.00 / batal), mis. setelah update kernel."
                if confirm "Izinkan reboot dari aplikasi?"; then allow_reboot_set on
                else c_info "Reboot dari aplikasi tidak diizinkan (ubah kapan saja: report allow-reboot on)."; fi
            fi ;;
    esac
}
allow_update_set() { # allow_update_set on|off
    if [ "$1" = on ]; then
        mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"; touch "$ALLOW_UPDATE"; chmod 600 "$ALLOW_UPDATE"
        c_ok "Update skrip dari aplikasi DIIZINKAN (diunduh dari GitHub hadynett/gis-secured, pengaturan tetap)."
    else
        rm -f "$ALLOW_UPDATE"; c_ok "Update skrip dari aplikasi tidak diizinkan."
    fi
}
allow_update_choose() { # allow_update_choose yes|no|ask
    case "$1" in
        yes) allow_update_set on ;;
        no)  allow_update_set off ;;
        *)
            if [ -f "$ALLOW_UPDATE" ]; then c_info "Update skrip dari aplikasi sudah diizinkan (cabut: report allow-update off)."
            elif [ -n "$TTY" ]; then
                echo
                echo "Aplikasi bisa meminta server ini memperbarui skrip ini ke versi terbaru (pengaturan tetap)."
                if confirm "Izinkan update skrip dari aplikasi?"; then allow_update_set on
                else c_info "Update dari aplikasi tidak diizinkan (ubah kapan saja: report allow-update on)."; fi
            fi ;;
    esac
}
report_setup() { # report_setup <url> <token> [yes|no|ask] [yes|no|ask] -- izin reboot, izin update dari aplikasi
    local url="$1" token="$2" reboot="${3:-ask}" upd="${4:-ask}"
    case "$url" in https://*|http://*) ;; *) die "URL laporan harus diawali https://" ;; esac
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    printf 'REPORT_URL=%q\nREPORT_TOKEN=%q\n' "$url" "$token" > "$REPORT_CONF"; chmod 600 "$REPORT_CONF"
    allow_reboot_choose "$reboot"
    allow_update_choose "$upd"
    install_self
    if [ -d /etc/cron.d ]; then
        printf 'SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n*/5 * * * * root %s report now quiet >/dev/null 2>&1\n' "$SELF_INSTALL" > /etc/cron.d/gisnet-secure-ssh
        chmod 644 /etc/cron.d/gisnet-secure-ssh
    else
        ( crontab -l 2>/dev/null | grep -v 'gisnet-secure-ssh report'; echo "*/5 * * * * $SELF_INSTALL report now quiet >/dev/null 2>&1" ) | crontab -
    fi
    report_send || c_warn "Pengiriman pertama gagal -- periksa URL/token. Jadwal tetap terpasang (tiap 5 menit)."
    c_ok "Laporan status ke aplikasi aktif (tiap 5 menit)."
}
cmd_report() {
    need_root; detect_os
    case "${1-now}" in
        now|kirim) report_send "${2-}" ;;
        setup|atur)
            local url='' token='' reboot=ask upd=ask a
            shift
            for a in "$@"; do
                case "$a" in
                    --allow-reboot) reboot=yes ;;
                    --no-allow-reboot) reboot=no ;;
                    --allow-update) upd=yes ;;
                    --no-allow-update) upd=no ;;
                    --allow-port) mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"; touch "$ALLOW_PORT"; chmod 600 "$ALLOW_PORT"; c_ok "Ganti port SSH dari aplikasi DIIZINKAN." ;;
                    --allow-all) allow_all_set on; reboot=yes; upd=yes ;;
                    *) if [ -z "$url" ]; then url="$a"; elif [ -z "$token" ]; then token="$a"; fi ;;
                esac
            done
            [ -n "$url" ] || url="$(ask "URL laporan (dari aplikasi): ")"
            [ -n "$token" ] || token="$(ask "Token laporan: ")"
            report_setup "$url" "$token" "$reboot" "$upd" ;;
        off|matikan) rm -f "$REPORT_CONF" /etc/cron.d/gisnet-secure-ssh; ( crontab -l 2>/dev/null | grep -v 'gisnet-secure-ssh report' ) | crontab - 2>/dev/null || true; c_ok "Laporan dimatikan." ;;
        json) report_json ;;
        allow-reboot|izin-reboot)
            case "${2-}" in
                on|ya) allow_reboot_set on; [ -f "$REPORT_CONF" ] && { report_send quiet || true; } ;;
                off|tidak) allow_reboot_set off; [ -f "$REPORT_CONF" ] && { report_send quiet || true; } ;;
                *) echo "Reboot dari aplikasi: $([ -f "$ALLOW_REBOOT" ] && echo diizinkan || echo 'tidak diizinkan') (ubah: report allow-reboot on|off)" ;;
            esac ;;
        allow-port|izin-port)
            case "${2-}" in
                on|ya) mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"; touch "$ALLOW_PORT"; chmod 600 "$ALLOW_PORT"
                       c_ok "Ganti port SSH dari aplikasi DIIZINKAN (tambah port baru; port lama ditutup hanya setelah port baru terbukti bisa dihubungi)."
                       [ -f "$REPORT_CONF" ] && { report_send quiet || true; } ;;
                off|tidak) rm -f "$ALLOW_PORT"; c_ok "Ganti port SSH dari aplikasi tidak diizinkan."
                       [ -f "$REPORT_CONF" ] && { report_send quiet || true; } ;;
                *) echo "Ganti port SSH dari aplikasi: $([ -f "$ALLOW_PORT" ] && echo diizinkan || echo 'tidak diizinkan') (ubah: report allow-port on|off)" ;;
            esac ;;
        allow-all|izin-semua)
            case "${2-}" in
                on|ya)     allow_all_set on;  [ -f "$REPORT_CONF" ] && { report_send quiet || true; } ;;
                off|tidak) allow_all_set off; [ -f "$REPORT_CONF" ] && { report_send quiet || true; } ;;
                *) echo "Pakai: report allow-all on|off (reboot, update, port, whitelist, DNS, kunci SSH sekaligus)" ;;
            esac ;;
        allow-whitelist|allow-dns|allow-key|izin-whitelist|izin-dns|izin-kunci)
            local f what
            case "$1" in
                *whitelist) f="$ALLOW_WHITELIST"; what='Ubah whitelist' ;;
                *dns)       f="$ALLOW_DNS"; what='Ganti DNS' ;;
                *)          f="$ALLOW_KEY"; what='Tambah/hapus kunci SSH root' ;;
            esac
            case "${2-}" in
                on|ya) mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"; touch "$f"; chmod 600 "$f"; c_ok "$what dari aplikasi DIIZINKAN."
                       [ -f "$REPORT_CONF" ] && { report_send quiet || true; } ;;
                off|tidak) rm -f "$f"; c_ok "$what dari aplikasi tidak diizinkan$([ "$f" != "$ALLOW_KEY" ] && [ -f "$ALLOW_PORT" ] && echo ' (tetapi masih ikut izin port: report allow-port off untuk mencabut semuanya)')."
                       [ -f "$REPORT_CONF" ] && { report_send quiet || true; } ;;
                *) echo "$what dari aplikasi: $([ -f "$f" ] && echo diizinkan || echo 'tidak diizinkan') (ubah: report $1 on|off)" ;;
            esac ;;
        allow-update|izin-update)
            case "${2-}" in
                on|ya) allow_update_set on; [ -f "$REPORT_CONF" ] && { report_send quiet || true; } ;;
                off|tidak) allow_update_set off; [ -f "$REPORT_CONF" ] && { report_send quiet || true; } ;;
                *) echo "Update skrip dari aplikasi: $([ -f "$ALLOW_UPDATE" ] && echo diizinkan || echo 'tidak diizinkan') (ubah: report allow-update on|off)" ;;
            esac ;;
        shared-blocklist|blokir-bersama)
            case "${2-}" in
                on|ya) rm -f "$SHARED_OFF"; c_ok "Blokir bersama aktif -- jalankan pemasangan ulang bila jail gisnet-shared belum ada (gisnet-secure-ssh update --force)." ;;
                off|tidak) mkdir -p "$STATE_DIR"; touch "$SHARED_OFF"; fail2ban-client unban --all >/dev/null 2>&1 || true; c_ok "Blokir bersama dimatikan (IP dari server lain tidak diblokir lagi)." ;;
                *) echo "Blokir bersama: $([ -f "$SHARED_OFF" ] && echo 'tidak aktif' || echo aktif) (ubah: report shared-blocklist on|off)" ;;
            esac ;;
        *) die "Perintah report tidak dikenal (now | setup <url> <token> | allow-reboot on|off | allow-update on|off | allow-port on|off | allow-whitelist on|off | allow-dns on|off | allow-key on|off | allow-all on|off | shared-blocklist on|off | off | json)" ;;
    esac
}

# ================================================================== UPDATE ===
cmd_update() { # update [--check] [--force] [--quiet] -- unduh versi terbaru lalu pasang ulang dengan pengaturan sama
    need_root; detect_os
    local check=0 force=0 quiet=0 url="${GISNET_UPDATE_URL:-$UPDATE_URL_DEFAULT}" tmp latest
    while [ $# -gt 0 ]; do
        case "$1" in --check) check=1 ;; --force) force=1 ;; --quiet) quiet=1 ;; *) die "Opsi update tidak dikenal: $1" ;; esac; shift
    done
    have curl || pkg_install curl >/dev/null 2>&1 || die "curl tidak tersedia."
    tmp="$(mktemp)"
    # Repo private: GH_TOKEN=<token read-only> gisnet-secure-ssh update
    if [ -n "${GH_TOKEN-}" ]; then
        curl -fsSL --max-time 60 -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github.raw' \
            https://api.github.com/repos/hadynett/gis-secured/contents/gisnet-secure-ssh.sh -o "$tmp" || { rm -f "$tmp"; die "Gagal mengunduh (periksa GH_TOKEN)."; }
    else
        curl -fsSL --max-time 60 "$url" -o "$tmp" || { rm -f "$tmp"; die "Gagal mengunduh $url (repo private? pakai GH_TOKEN=...)."; }
    fi
    grep -q '^SCRIPT_VERSION=' "$tmp" && bash -n "$tmp" || { rm -f "$tmp"; die "File yang diunduh bukan skrip yang valid -- dibatalkan."; }
    latest="$(sed -n "s/^SCRIPT_VERSION='\([0-9.]*\)'.*/\1/p" "$tmp" | head -1)"
    echo "Versi terpasang: $SCRIPT_VERSION · versi terbaru: ${latest:-?}"
    if [ "$check" -eq 1 ]; then rm -f "$tmp"; return 0; fi
    if [ "$force" -eq 0 ] && [ "$(printf '%s\n%s\n' "$latest" "$SCRIPT_VERSION" | sort -V | tail -1)" = "$SCRIPT_VERSION" ]; then
        rm -f "$tmp"; c_ok "Sudah versi terbaru."; return 0
    fi
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    [ -f "$SELF_INSTALL" ] && cp -a "$SELF_INSTALL" "$STATE_DIR/gisnet-secure-ssh.prev"
    install -m 0755 "$tmp" "$SELF_INSTALL"; rm -f "$tmp"
    c_ok "Skrip diperbarui ke $latest ($SELF_INSTALL; versi lama: $STATE_DIR/gisnet-secure-ssh.prev)."
    if [ -f "$JAIL" ] && [ -f "$INSTALL_CONF" -o -f "$REPORT_CONF" ]; then
        c_info "Memasang ulang dengan pengaturan yang sama..."
        if [ "$quiet" -eq 1 ]; then GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" install </dev/null >/dev/null
        else GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" install </dev/null; fi
        [ -f "$REPORT_CONF" ] && { GISNET_NONINTERACTIVE=1 "$SELF_INSTALL" report now quiet </dev/null || true; }
    else
        c_info "Belum pernah dipasang lengkap di server ini -- jalankan: gisnet-secure-ssh install"
    fi
}

# ==================================================================== MENU ===
cmd_menu() {
    need_root; [ -n "$TTY" ] || die "Menu butuh terminal interaktif."
    while :; do
        echo
        echo "=== gis-secured v$SCRIPT_VERSION -- $(hostname) ==="
        echo "  1) Status keamanan        5) Ganti / tambah port SSH"
        echo "  2) Kelola whitelist       6) Kembalikan dari cadangan"
        echo "  3) Kelola kunci SSH       7) Kirim laporan ke aplikasi"
        echo "  4) IP terblokir / buka    8) Pasang ulang / perbarui"
        echo "  0) Keluar"
        case "$(ask "Pilih: ")" in
            1) cmd_status ;;
            2) cmd_whitelist ;;
            3) cmd_key ;;
            4) cmd_banned; case "$(ask "u = buka blokir, b = blokir IP, Enter = kembali: ")" in u) cmd_unban ;; b) cmd_ban ;; esac ;;
            5) cmd_port ;;
            6) cmd_restore || true ;;
            7) cmd_report now || true ;;
            8) cmd_install ;;
            0|'') break ;;
        esac
    done
}

# =================================================================== UTAMA ===
case "${1-}" in
    menu)                 shift; cmd_menu ;;
    status)               shift; cmd_status ;;
    banned)               shift; cmd_banned ;;
    ban)                  shift; cmd_ban "$@" ;;
    unban)                shift; cmd_unban "$@" ;;
    whitelist)            shift; cmd_whitelist "$@" ;;
    key|keys|kunci)       shift; cmd_key "$@" ;;
    port)                 shift; cmd_port "$@" ;;
    dns)                  shift; cmd_dns "$@" ;;
    baseline)             shift; cmd_baseline "$@" ;;
    restrict|batasi)      shift; cmd_restrict "$@" ;;
    rootkit-scan)         shift; need_root; detect_os; rootkit_scan; cat "$ROOTKIT_RESULT"; echo ;;
    restore)              shift; cmd_restore "$@" ;;
    report|laporan)       shift; cmd_report "$@" ;;
    checks|periksa)       shift; cmd_checks ;;
    update|perbarui)      shift; cmd_update "$@" ;;
    install|pasang)       shift; cmd_install "$@" ;;
    -h|--help|help)       usage ;;
    -v|--version|version) echo "gis-secured v$SCRIPT_VERSION (perintah: gisnet-secure-ssh)" ;;
    *)                    cmd_install "$@" ;;
esac
