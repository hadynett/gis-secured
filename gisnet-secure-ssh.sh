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
#     report [now|setup <url> <token>|off] laporan status ke aplikasi pemantau
#
#  PENGAMAN: password SSH baru dimatikan setelah kunci terverifikasi; semua file
#  dicadangkan (/root/gisnet-secure-ssh-backup-<waktu>/); konfigurasi diuji
#  sebelum dipakai; semua blokir HANYA port yang diserang (aman untuk IP NAT
#  bersama). JANGAN tutup sesi SSH yang sedang dipakai sebelum mencoba login
#  baru di terminal lain.
# =============================================================================
set -euo pipefail

VERSION='2.0'
SELF_INSTALL=/usr/local/sbin/gisnet-secure-ssh
STATE_DIR=/etc/gisnet-secure-ssh
REPORT_CONF="$STATE_DIR/report.conf"
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
if [ -r /dev/tty ] && { : < /dev/tty; } 2>/dev/null; then TTY=/dev/tty; fi
ask() { local reply=''; printf '%s' "$1" > /dev/tty; IFS= read -r reply < /dev/tty || true; printf '%s' "$reply"; }
confirm() { [ -n "$TTY" ] || return 0; case "$(lower "$(ask "$1 [y/N]: ")")" in y|ya|yes) return 0 ;; *) return 1 ;; esac; }
need_root() { [ "$(id -u)" -eq 0 ] || die "Jalankan sebagai root (sudo)."; }

# ------------------------------------------------------------- deteksi OS ---
detect_os() {
    [ -r /etc/os-release ] && . /etc/os-release || true
    OS_ID="${ID:-unknown}"
    OS_NAME="${PRETTY_NAME:-$OS_ID}"
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
        apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
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
gen_jail() { # gen_jail <whitelist> <banaction> <ports> <sshd-log> [weblog]
    local wl="$1" ba="$2" ports="$3" sshdlog="$4" weblog="${5-}"
    cat <<EOF
# fail2ban -- dipasang gisnet-secure-ssh.sh v$VERSION ($(date '+%Y-%m-%d %H:%M'))
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
    local KEYS=() WL_INPUT='' WL_GIVEN=0 EXTRA_USERS=() KEEP_PASSWORD=0 NEW_PORT='' AUTO_UPDATE=1 WEB_JAIL=1 DRY=0 R_URL='' R_TOKEN=''
    while [ $# -gt 0 ]; do
        case "$1" in
            --key) KEYS+=("${2:?--key butuh nilai}"); shift 2 ;;
            --whitelist) WL_INPUT="${2-}"; WL_GIVEN=1; shift 2 ;;
            --user) EXTRA_USERS+=("${2:?--user butuh nilai}"); shift 2 ;;
            --keep-password) KEEP_PASSWORD=1; shift ;;
            --ssh-port) NEW_PORT="${2:?--ssh-port butuh nilai}"; shift 2 ;;
            --no-auto-update) AUTO_UPDATE=0; shift ;;
            --no-web-jail) WEB_JAIL=0; shift ;;
            --report-url) R_URL="${2:?}"; shift 2 ;;
            --report-token) R_TOKEN="${2:?}"; shift 2 ;;
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

    # --- kunci publik
    if [ "${#KEYS[@]}" -eq 0 ]; then
        [ -n "$TTY" ] || die "Tidak ada terminal untuk bertanya -- berikan kunci lewat --key \"ssh-ed25519 AAAA...\"."
        echo
        echo "Tempel KUNCI PUBLIK SSH Anda (isi file .pub, diawali ssh-ed25519 / ssh-rsa / ecdsa-sha2-...)."
        echo "Satu kunci per baris; tekan Enter pada baris kosong bila selesai."
        local line
        while :; do
            line="$(ask "Kunci publik #$(( ${#KEYS[@]} + 1 )): " | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
            if [ -z "$line" ]; then [ "${#KEYS[@]}" -gt 0 ] && break; c_warn "Minimal satu kunci publik."; continue; fi
            if valid_key "$line"; then KEYS+=("$line"); c_ok "Kunci diterima (${line##* })."
            else c_warn "Bukan kunci publik SSH yang valid (pastikan isi file .pub, bukan kunci privat)."; fi
        done
    fi
    local k; for k in "${KEYS[@]}"; do valid_key "$k" || die "Kunci publik tidak valid: ${k:0:40}..."; done

    # --- whitelist
    if [ "$WL_GIVEN" -eq 0 ] && [ -n "$TTY" ]; then
        echo; echo "IP / subnet yang TIDAK BOLEH diblokir fail2ban (mis. IP kantor). Pisahkan dengan spasi."
        WL_INPUT="$(ask "Whitelist (Enter untuk lewati): ")"
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

    if [ "$DRY" -eq 1 ]; then
        echo; c_info "MODE UJI (--dry-run): tidak ada yang diubah."
        c_plan "Pasang paket: fail2ban$([ "$PKG" = apt ] && [ "$HAS_SYSTEMD" -eq 1 ] && echo ' python3-systemd')$( { [ "$PKG" = dnf ] || [ "$PKG" = yum ]; } && [ "$OS_ID" != fedora ] && echo ' (dari EPEL)')"
        c_plan "Kunci publik untuk root${EXTRA_USERS[*]:+ & ${EXTRA_USERS[*]}}: $(for k in "${KEYS[@]}"; do printf '%s ' "${k##* }"; done)"
        c_plan "Port SSH: $PORTS$([ -n "$NEW_PORT" ] && echo " (port baru $NEW_PORT, port lama tetap dibuka)")"
        c_plan "Login password SSH: $([ "$PW" = no ] && echo 'DIMATIKAN (kunci saja)' || echo 'tetap aktif')"
        c_plan "Update keamanan otomatis: $([ "$AUTO_UPDATE" -eq 1 ] && echo ya || echo tidak)"
        c_plan "Jail web: ${WEBLOG:-tidak (nginx/apache tidak ditemukan atau --no-web-jail)}"
        c_plan "Laporan ke aplikasi: ${R_URL:-tidak}"
        c_plan "Perintah tersedia setelah ini: $SELF_INSTALL"
        echo; echo "----- $JAIL -----"; gen_jail "$WHITELIST" "$BANACTION" "$PORTS" "$SSHDLOG" "$WEBLOG"
        echo; echo "----- $DROPIN (atau awal $SSHD_CONFIG) -----"
        printf 'Port %s\n' $(printf '%s' "$PORTS" | tr ',' ' ')
        gen_ssh_settings "$PW"
        exit 0
    fi

    start_backup

    # --- 1. kunci SSH
    local KEY_OK=0 u
    install_keys root "${KEYS[@]}" && KEY_OK=1
    for u in ${EXTRA_USERS[@]+"${EXTRA_USERS[@]}"}; do install_keys "$u" "${KEYS[@]}" || true; done
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
    backup "$JAIL"; gen_jail "$WHITELIST" "$BANACTION" "$PORTS" "$SSHDLOG" "$WEBLOG" > "$JAIL"
    touch "$F2B_LOG" 2>/dev/null || true
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
    [ -n "$NEW_PORT" ] && open_port "$NEW_PORT"

    # --- 4. update keamanan otomatis
    [ "$AUTO_UPDATE" -eq 1 ] && setup_auto_update

    # --- 5. perintah sistem + laporan
    install_self
    [ -n "$R_URL" ] && report_setup "$R_URL" "$R_TOKEN"

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
        { echo "# pengetatan SSH (gisnet-secure-ssh.sh v$VERSION)"; printf '%s\n' "$body"; } > "$DROPIN"; chmod 644 "$DROPIN"
    else
        sed -i '/^# >>> gisnet-secure-ssh/,/^# <<< gisnet-secure-ssh/d' "$SSHD_CONFIG"
        { echo "# >>> gisnet-secure-ssh v$VERSION"; printf '%s\n' "$body"; echo "# <<< gisnet-secure-ssh"; cat "$SSHD_CONFIG"; } > "$SSHD_CONFIG.gisnet-tmp"
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
    if have getenforce && [ "$(getenforce 2>/dev/null)" != Disabled ]; then
        have semanage || pkg_install policycoreutils-python-utils >/dev/null 2>&1 || pkg_install policycoreutils-python >/dev/null 2>&1 || true
        semanage port -a -t ssh_port_t -p tcp "$p" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$p" 2>/dev/null || c_warn "SELinux: gagal mendaftarkan port $p."
    fi
    if [ "$HAS_SYSTEMD" -eq 1 ] && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd -q --permanent --add-port="$p/tcp" && firewall-cmd -q --reload && c_ok "firewalld: port $p dibuka."
    elif have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then
        ufw allow "$p/tcp" >/dev/null && c_ok "ufw: port $p dibuka."
    fi
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
        awk -v v="$newports" '/^\[/{s=$0} (s=="[sshd]"||s=="[recidive]") && /^[[:space:]]*port[[:space:]]*=/{print "port      = " v; next} {print}' "$JAIL" > "$JAIL.tmp" && cat "$JAIL.tmp" > "$JAIL" && rm -f "$JAIL.tmp"
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
    printf '{"version":%s,"hostname":%s,"os":%s,"ip":%s,"uptime_seconds":%s,"fail2ban_running":%s,"jails":[%s],"whitelist":%s,"ssh":{"ports":%s,"password_auth":%s,"root_login":%s},"auto_update":%s,"recent_bans":[%s],"generated_at":%s}\n' \
        "$(json_str "$VERSION")" "$(json_str "$(hostname)")" "$(json_str "$OS_NAME")" "$(json_str "$ip")" \
        "$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo 0)" "$running" "$jails" \
        "$(json_str "$(wl_current | paste -sd' ' - || true)")" "$(json_str "$ports")" "$(json_str "${pw:-}")" "$(json_str "${root:-}")" \
        "$(json_str "$(auto_update_status)")" "$recent" "$(date +%s)"
}
report_send() {
    [ -f "$REPORT_CONF" ] || die "Laporan belum diatur: report setup <url> <token>"
    # shellcheck disable=SC1090
    . "$REPORT_CONF"
    have curl || pkg_install curl >/dev/null 2>&1 || die "curl tidak tersedia."
    local code
    code="$(report_json | curl -sS -o /dev/null -w '%{http_code}' --max-time 20 -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -H "Authorization: Bearer $REPORT_TOKEN" --data-binary @- "$REPORT_URL" || echo 000)"
    case "$code" in 2*) [ "${1-}" = quiet ] || c_ok "Laporan terkirim ($code)." ;; *) c_err "Laporan gagal (HTTP $code)."; return 1 ;; esac
}
report_setup() { # report_setup <url> <token>
    local url="$1" token="$2"
    case "$url" in https://*|http://*) ;; *) die "URL laporan harus diawali https://" ;; esac
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    printf 'REPORT_URL=%q\nREPORT_TOKEN=%q\n' "$url" "$token" > "$REPORT_CONF"; chmod 600 "$REPORT_CONF"
    install_self
    if [ -d /etc/cron.d ]; then
        printf 'SHELL=/bin/bash\n*/5 * * * * root %s report now quiet >/dev/null 2>&1\n' "$SELF_INSTALL" > /etc/cron.d/gisnet-secure-ssh
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
            local url="${2-}" token="${3-}"
            [ -n "$url" ] || url="$(ask "URL laporan (dari aplikasi): ")"
            [ -n "$token" ] || token="$(ask "Token laporan: ")"
            report_setup "$url" "$token" ;;
        off|matikan) rm -f "$REPORT_CONF" /etc/cron.d/gisnet-secure-ssh; ( crontab -l 2>/dev/null | grep -v 'gisnet-secure-ssh report' ) | crontab - 2>/dev/null || true; c_ok "Laporan dimatikan." ;;
        json) report_json ;;
        *) die "Perintah report tidak dikenal (now | setup <url> <token> | off | json)" ;;
    esac
}

# ==================================================================== MENU ===
cmd_menu() {
    need_root; [ -n "$TTY" ] || die "Menu butuh terminal interaktif."
    while :; do
        echo
        echo "=== gisnet-secure-ssh v$VERSION -- $(hostname) ==="
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
    restore)              shift; cmd_restore "$@" ;;
    report|laporan)       shift; cmd_report "$@" ;;
    install|pasang)       shift; cmd_install "$@" ;;
    -h|--help|help)       usage ;;
    -v|--version|version) echo "gisnet-secure-ssh v$VERSION" ;;
    *)                    cmd_install "$@" ;;
esac
