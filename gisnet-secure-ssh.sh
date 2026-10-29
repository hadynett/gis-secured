#!/usr/bin/env bash
# =============================================================================
#  gisnet-secure-ssh.sh -- pasang fail2ban + kunci SSH + pengetatan SSH
#
#  Mendukung: Debian, Ubuntu, AlmaLinux/Rocky/RHEL/CentOS/Fedora, openSUSE,
#  Arch, Alpine (deteksi otomatis lewat /etc/os-release).
#
#  Yang dilakukan:
#   1. Memasang kunci publik SSH Anda ke root (ditanyakan saat dijalankan,
#      atau lewat --key). Kunci TIDAK disimpan di skrip ini.
#   2. Memasang & menyalakan fail2ban:
#        - jail sshd (mode aggressive): blokir 24 jam setelah 5x gagal/10 menit;
#        - recidive: diblokir 3x sehari -> 1 minggu;
#        - SEMUA blokir hanya ke port SSH (aman untuk IP NAT bersama);
#        - whitelist IP/subnet yang tidak pernah diblokir (ditanyakan, atau --whitelist).
#   3. Pengetatan SSH: login hanya dengan kunci (password dimatikan), root
#      hanya boleh dengan kunci, batas percobaan login.
#
#  Pengaman:
#   - Password SSH baru dimatikan SETELAH kunci terpasang & terverifikasi.
#   - Semua file yang diubah dicadangkan ke /root/gisnet-secure-ssh-backup-<waktu>/.
#   - Konfigurasi sshd & fail2ban diuji sebelum dipakai; gagal -> dikembalikan.
#   - IP whitelist yang sedang terblokir langsung dibuka.
#
#  Pemakaian (sebagai root):
#     bash gisnet-secure-ssh.sh                       # interaktif: tanya kunci & whitelist
#     curl -fsSL <url-raw>/gisnet-secure-ssh.sh | sudo bash   # juga interaktif
#     bash gisnet-secure-ssh.sh --key "ssh-ed25519 AAAA... nama" --whitelist "203.0.113.5"
#     bash gisnet-secure-ssh.sh --user deploy         # kunci juga untuk user 'deploy'
#     bash gisnet-secure-ssh.sh --keep-password       # jangan matikan login password
#   --key boleh diulang untuk beberapa kunci; --whitelist berisi IP/subnet
#   dipisah spasi (IPv4/IPv6, boleh CIDR).
#
#  PENTING: JANGAN tutup sesi SSH yang sedang dipakai sebelum mencoba login
#  baru dengan kunci di jendela/terminal lain.
# =============================================================================
set -euo pipefail

KEYS=()
WHITELIST_INPUT=''
WHITELIST_GIVEN=0
EXTRA_USERS=()
KEEP_PASSWORD=0

# ------------------------------------------------------------------ bantuan ---
c_ok()   { printf '\033[32m[OK]\033[0m %s\n' "$*"; }
c_info() { printf '\033[36m[..]\033[0m %s\n' "$*"; }
c_warn() { printf '\033[33m[!!]\033[0m %s\n' "$*"; }
c_err()  { printf '\033[31m[XX]\033[0m %s\n' "$*" >&2; }
die()    { c_err "$*"; exit 1; }
have()   { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '2,37p' "${BASH_SOURCE[0]:-$0}" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0; }

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

while [ $# -gt 0 ]; do
    case "$1" in
        --key) KEYS+=("${2:?--key butuh nilai}"); shift 2 ;;
        --whitelist) WHITELIST_INPUT="${2-}"; WHITELIST_GIVEN=1; shift 2 ;;
        --user) EXTRA_USERS+=("${2:?--user butuh nilai}"); shift 2 ;;
        --keep-password) KEEP_PASSWORD=1; shift ;;
        -h|--help) usage ;;
        *) die "Opsi tidak dikenal: $1 (lihat --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "Jalankan sebagai root (sudo bash gisnet-secure-ssh.sh)."

# Pertanyaan dibaca dari terminal (/dev/tty) supaya tetap bisa dijawab walau
# skrip dijalankan lewat "curl ... | bash".
TTY=''
if [ -r /dev/tty ] && { : < /dev/tty; } 2>/dev/null; then TTY=/dev/tty; fi
ask() { local prompt="$1" reply=''; printf '%s' "$prompt" > /dev/tty; IFS= read -r reply < /dev/tty || true; printf '%s' "$reply"; }

if [ "${#KEYS[@]}" -eq 0 ]; then
    [ -n "$TTY" ] || die "Tidak ada terminal untuk bertanya -- berikan kunci lewat --key \"ssh-ed25519 AAAA...\"."
    echo
    echo "Tempel KUNCI PUBLIK SSH Anda (isi file .pub, diawali ssh-ed25519 / ssh-rsa / ecdsa-sha2-...)."
    echo "Satu kunci per baris; tekan Enter pada baris kosong bila selesai."
    while :; do
        line="$(ask "Kunci publik #$(( ${#KEYS[@]} + 1 )): ")"
        line="$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        if [ -z "$line" ]; then
            [ "${#KEYS[@]}" -gt 0 ] && break
            c_warn "Minimal satu kunci publik."; continue
        fi
        if valid_key "$line"; then KEYS+=("$line"); c_ok "Kunci diterima (${line##* })."
        else c_warn "Bukan kunci publik SSH yang valid -- coba lagi (pastikan file .pub, bukan kunci privat)."
        fi
    done
fi
for k in "${KEYS[@]}"; do valid_key "$k" || die "Kunci publik tidak valid: ${k:0:40}..."; done

if [ "$WHITELIST_GIVEN" -eq 0 ] && [ -n "$TTY" ]; then
    echo
    echo "IP / subnet yang TIDAK BOLEH diblokir fail2ban (mis. IP kantor). Pisahkan dengan spasi."
    WHITELIST_INPUT="$(ask "Whitelist (Enter untuk lewati): ")"
fi
WHITELIST_EXTRA=''
for ip in $(printf '%s' "$WHITELIST_INPUT" | tr ',' ' '); do
    if valid_ip "$ip"; then WHITELIST_EXTRA="$WHITELIST_EXTRA $ip"; else die "IP whitelist tidak valid: $ip"; fi
done
WHITELIST_EXTRA="${WHITELIST_EXTRA# }"

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/gisnet-secure-ssh-backup-$STAMP"
mkdir -p "$BACKUP_DIR"
backup() { [ -e "$1" ] && cp -a "$1" "$BACKUP_DIR/$(echo "$1" | tr '/' '_')" || true; }

# ---------------------------------------------------------------- deteksi OS ---
[ -r /etc/os-release ] && . /etc/os-release || true
OS_ID="${ID:-unknown}"
OS_LIKE="${ID_LIKE:-}"
c_info "Sistem: ${PRETTY_NAME:-$OS_ID}"

PKG=''
if have apt-get; then PKG=apt
elif have dnf; then PKG=dnf
elif have yum; then PKG=yum
elif have zypper; then PKG=zypper
elif have pacman; then PKG=pacman
elif have apk; then PKG=apk
else die "Pengelola paket tidak dikenali (butuh apt/dnf/yum/zypper/pacman/apk)."
fi
HAS_SYSTEMD=0; [ -d /run/systemd/system ] && HAS_SYSTEMD=1

pkg_install() {
    case "$PKG" in
        apt)    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
        dnf)    dnf install -y -q "$@" ;;
        yum)    yum install -y -q "$@" ;;
        zypper) zypper --non-interactive install -y "$@" ;;
        pacman) pacman -Sy --noconfirm --needed "$@" ;;
        apk)    apk add --no-cache "$@" ;;
    esac
}

svc() { # svc <aksi> <nama...> -- coba beberapa nama layanan (ssh/sshd)
    local action="$1"; shift
    for name in "$@"; do
        if [ "$HAS_SYSTEMD" -eq 1 ]; then
            if systemctl cat "$name.service" >/dev/null 2>&1; then
                systemctl "$action" "$name" && return 0
            fi
        elif have rc-service && [ -e "/etc/init.d/$name" ]; then
            rc-service "$name" "$action" && return 0
        elif have service; then
            service "$name" "$action" >/dev/null 2>&1 && return 0
        fi
    done
    return 1
}

# ------------------------------------------------------- 1. kunci publik SSH ---
install_key() { # install_key <user>
    local user="$1" home
    home="$(awk -F: -v u="$user" '$1==u{print $6}' /etc/passwd)"
    [ -n "$home" ] && [ -d "$home" ] || { c_warn "User '$user' tidak ditemukan -- dilewati."; return 1; }
    local dir="$home/.ssh" file="$home/.ssh/authorized_keys"
    mkdir -p "$dir"; touch "$file"; backup "$file"
    local key blob ok=1
    for key in "${KEYS[@]}"; do
        blob="$(printf '%s' "$key" | awk '{print $2}')"
        if grep -qF "$blob" "$file"; then
            c_ok "Kunci ${key##* } sudah ada untuk $user."
        else
            printf '%s\n' "$key" >> "$file"
            c_ok "Kunci ${key##* } dipasang untuk $user ($file)."
        fi
    done
    chmod 700 "$dir"; chmod 600 "$file"
    chown -R "$user":"$(id -gn "$user")" "$dir"
    have restorecon && restorecon -R "$dir" >/dev/null 2>&1 || true   # SELinux (Alma/RHEL)
    for key in "${KEYS[@]}"; do
        grep -qF "$(printf '%s' "$key" | awk '{print $2}')" "$file" || ok=0
    done
    [ "$ok" -eq 1 ]
}

KEY_OK=0
install_key root && KEY_OK=1
for u in "${EXTRA_USERS[@]}"; do install_key "$u" || true; done

# ------------------------------------------------------------ 2. fail2ban ---
c_info "Memasang fail2ban..."
case "$PKG" in
    dnf|yum)
        # fail2ban ada di EPEL untuk Alma/Rocky/RHEL/CentOS (Fedora sudah punya).
        if [ "$OS_ID" != "fedora" ] && ! rpm -q epel-release >/dev/null 2>&1; then
            pkg_install epel-release || c_warn "epel-release gagal dipasang -- mencoba fail2ban langsung."
        fi
        pkg_install fail2ban || die "Gagal memasang fail2ban."
        ;;
    apt)
        pkg_install fail2ban || die "Gagal memasang fail2ban."
        # Backend systemd butuh modul python systemd (Debian 12+ tidak punya auth.log).
        [ "$HAS_SYSTEMD" -eq 1 ] && pkg_install python3-systemd >/dev/null 2>&1 || true
        ;;
    *) pkg_install fail2ban || die "Gagal memasang fail2ban." ;;
esac
have fail2ban-client || die "fail2ban-client tidak ditemukan setelah instalasi."

# Port SSH yang sedang dipakai (bisa lebih dari satu, mis. 22 dan 2269).
SSHD_BIN="$(command -v sshd || echo /usr/sbin/sshd)"
SSH_PORTS="$("$SSHD_BIN" -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un | paste -sd, - || true)"
[ -n "$SSH_PORTS" ] || SSH_PORTS=22
c_info "Port SSH terdeteksi: $SSH_PORTS"

# Aksi blokir sesuai firewall yang ada -- selalu khusus port SSH saja.
if [ "$HAS_SYSTEMD" -eq 1 ] && systemctl is-active --quiet firewalld 2>/dev/null; then
    BANACTION='firewallcmd-rich-rules'
elif have nft; then
    BANACTION='nftables-multiport'
elif have iptables; then
    BANACTION='iptables-multiport'
else
    c_info "Firewall belum ada -- memasang nftables..."
    pkg_install nftables >/dev/null 2>&1 || pkg_install iptables >/dev/null 2>&1 || true
    if have nft; then BANACTION='nftables-multiport'; [ "$HAS_SYSTEMD" -eq 1 ] && systemctl enable --now nftables >/dev/null 2>&1 || true
    else BANACTION='iptables-multiport'; fi
fi
c_info "Aksi blokir: $BANACTION (hanya port $SSH_PORTS)"

# Sumber log: journald kalau ada systemd, selain itu file log SSH.
if [ "$HAS_SYSTEMD" -eq 1 ]; then
    SSHD_LOG='backend  = systemd'
else
    LOGFILE=/var/log/auth.log
    [ -f /var/log/secure ] && LOGFILE=/var/log/secure
    [ -f /var/log/messages ] && [ ! -f /var/log/auth.log ] && [ ! -f /var/log/secure ] && LOGFILE=/var/log/messages
    SSHD_LOG="backend  = auto
logpath  = $LOGFILE"
fi

# Log fail2ban dipastikan ke file -- dibaca jail recidive (sebagian distro
# default-nya ke journal).
F2B_LOG=/var/log/fail2ban.log
mkdir -p /etc/fail2ban/fail2ban.d
backup /etc/fail2ban/fail2ban.d/gisnet.local
printf '[Definition]
logtarget = %s
' "$F2B_LOG" > /etc/fail2ban/fail2ban.d/gisnet.local

WHITELIST="127.0.0.1/8 ::1 $WHITELIST_EXTRA"
WHITELIST="${WHITELIST% }"
JAIL=/etc/fail2ban/jail.d/gisnet.local
FILTER=/etc/fail2ban/filter.d/gisnet-recidive-ssh.conf
backup "$JAIL"; backup "$FILTER"

cat > "$FILTER" <<'EOF'
# recidive khusus jail sshd (dipasang gisnet-secure-ssh.sh).
[Definition]
failregex = NOTICE\s+\[sshd\]\s+Ban\s+<HOST>\s*$
ignoreregex =
EOF

cat > "$JAIL" <<EOF
# fail2ban -- dipasang gisnet-secure-ssh.sh $STAMP
# Semua blokir HANYA port SSH (bukan semua port) -- aman untuk IP NAT bersama.
[DEFAULT]
ignoreip  = $WHITELIST
bantime   = 24h
findtime  = 10m
maxretry  = 5
banaction = $BANACTION

[sshd]
enabled  = true
mode     = aggressive
port     = $SSH_PORTS
$SSHD_LOG

# Diblokir berulang (3x sehari) -> 1 minggu, tetap hanya port SSH.
[recidive]
enabled   = true
filter    = gisnet-recidive-ssh
logpath   = $F2B_LOG
banaction = $BANACTION
port      = $SSH_PORTS
bantime   = 1w
findtime  = 1d
maxretry  = 3
EOF
touch "$F2B_LOG" 2>/dev/null || true

if fail2ban-client -t >/dev/null 2>&1 || fail2ban-client -d >/dev/null 2>&1; then
    c_ok "Konfigurasi fail2ban valid."
else
    c_err "Konfigurasi fail2ban tidak valid -- mengembalikan cadangan."
    fail2ban-client -d 2>&1 | tail -5 || true
    rm -f "$JAIL"; [ -e "$BACKUP_DIR/_etc_fail2ban_jail.d_gisnet.local" ] && cp -a "$BACKUP_DIR/_etc_fail2ban_jail.d_gisnet.local" "$JAIL"
    die "Periksa pesan di atas."
fi

if [ "$HAS_SYSTEMD" -eq 1 ]; then
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban
elif have rc-update; then
    rc-update add fail2ban default >/dev/null 2>&1 || true
    rc-service fail2ban restart
else
    service fail2ban restart
fi
sleep 2

# IP whitelist yang (mungkin) sedang terblokir langsung dibuka.
for ip in $WHITELIST_EXTRA; do
    fail2ban-client unban "$ip" >/dev/null 2>&1 || true
done
c_ok "fail2ban aktif."

# ----------------------------------------------------------- 3. SSH ketat ---
SSHD_CONFIG=/etc/ssh/sshd_config
[ -f "$SSHD_CONFIG" ] || die "$SSHD_CONFIG tidak ditemukan."
backup "$SSHD_CONFIG"

if [ "$KEEP_PASSWORD" -eq 1 ]; then
    PW=yes
    c_warn "--keep-password: login password SSH TETAP aktif."
elif [ "$KEY_OK" -ne 1 ]; then
    PW=yes
    c_warn "Kunci root belum terverifikasi -- login password SSH TETAP aktif supaya Anda tidak terkunci."
else
    PW=no
fi

SETTINGS="PubkeyAuthentication yes
PasswordAuthentication $PW
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
PermitRootLogin prohibit-password
MaxAuthTries 4
LoginGraceTime 30"

# sshd memakai nilai PERTAMA yang ditemui. Baris yang sama di sshd_config
# (di luar blok Match) dikomentari dulu, lalu nilai GISNET ditaruh di file
# drop-in yang terbaca paling awal (00-) -- atau, kalau sshd_config tidak
# memakai Include, di bagian atas sshd_config.
# Hanya opsi yang dikenali versi OpenSSH di server ini (mis. OpenSSH 8.0 di
# Alma 8 belum kenal KbdInteractiveAuthentication).
SUPPORTED="$("$SSHD_BIN" -T 2>/dev/null | awk '{print tolower($1)}')"
SETTINGS="$(printf '%s
' "$SETTINGS" | while read -r kw val; do printf '%s
' "$SUPPORTED" | grep -qx "$(printf '%s' "$kw" | tr 'A-Z' 'a-z')" && printf '%s %s
' "$kw" "$val"; done)"
printf '%s
' "$SETTINGS" | grep -q '^PasswordAuthentication' || die "sshd tidak dikenali (sshd -T gagal)."

KEYS_RE='^(PubkeyAuthentication|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PermitEmptyPasswords|PermitRootLogin|MaxAuthTries|LoginGraceTime)[[:space:]]'
awk -v re="$KEYS_RE" '
    BEGIN { inmatch = 0 }
    /^[[:space:]]*Match[[:space:]]/ { inmatch = 1 }
    { line = $0; sub(/^[[:space:]]+/, "", line) }
    !inmatch && line ~ re { print "# (gisnet-secure-ssh) " $0; next }
    { print }
' "$SSHD_CONFIG" > "$SSHD_CONFIG.gisnet-tmp" && cat "$SSHD_CONFIG.gisnet-tmp" > "$SSHD_CONFIG" && rm -f "$SSHD_CONFIG.gisnet-tmp"

DROPIN=''
if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"; then
    mkdir -p /etc/ssh/sshd_config.d
    DROPIN=/etc/ssh/sshd_config.d/00-gisnet.conf
    backup "$DROPIN"
    { echo "# pengetatan SSH (gisnet-secure-ssh.sh $STAMP)"; echo "$SETTINGS"; } > "$DROPIN"
    chmod 644 "$DROPIN"
    c_info "Pengaturan SSH ditulis ke $DROPIN"
else
    { echo "# >>> gisnet-secure-ssh.sh $STAMP"; echo "$SETTINGS"; echo "# <<< gisnet-secure-ssh.sh"; echo; cat "$SSHD_CONFIG"; } > "$SSHD_CONFIG.gisnet-tmp"
    cat "$SSHD_CONFIG.gisnet-tmp" > "$SSHD_CONFIG"; rm -f "$SSHD_CONFIG.gisnet-tmp"
    c_info "Pengaturan SSH ditulis di awal $SSHD_CONFIG"
fi

if ! "$SSHD_BIN" -t 2>/tmp/gisnet-sshd-test.err; then
    c_err "Konfigurasi SSH tidak valid -- mengembalikan cadangan:"
    cat /tmp/gisnet-sshd-test.err >&2
    cp -a "$BACKUP_DIR/_etc_ssh_sshd_config" "$SSHD_CONFIG"
    [ -n "$DROPIN" ] && rm -f "$DROPIN"
    die "SSH tidak diubah."
fi

svc reload ssh sshd || svc restart ssh sshd || c_warn "Gagal reload layanan SSH -- jalankan manual: systemctl reload sshd (atau ssh)."
c_ok "SSH diperketat (login password: $PW)."

# -------------------------------------------------------------- ringkasan ---
EFFECTIVE="$("$SSHD_BIN" -T 2>/dev/null | grep -Ei '^(passwordauthentication|permitrootlogin|pubkeyauthentication) ' || true)"
echo
echo "================================================================"
echo " SELESAI -- $(hostname)"
echo "----------------------------------------------------------------"
echo " Kunci publik     : ${#KEYS[@]} kunci (root${EXTRA_USERS[*]:+, ${EXTRA_USERS[*]}})"
echo " Port SSH         : $SSH_PORTS"
echo " Whitelist        : $WHITELIST"
echo " fail2ban         : sshd (aggressive) + recidive, aksi $BANACTION"
echo " SSH efektif      :"
echo "$EFFECTIVE" | sed 's/^/                    /'
echo " Cadangan         : $BACKUP_DIR"
echo "----------------------------------------------------------------"
fail2ban-client status sshd 2>/dev/null | sed 's/^/ /' || true
echo "================================================================"
if [ "$PW" = no ]; then
    c_warn "JANGAN tutup sesi ini dulu. Coba login baru dengan kunci di terminal lain:"
    echo "       ssh -p ${SSH_PORTS%%,*} root@<ip-server>"
    c_warn "Kalau gagal, kembalikan dari $BACKUP_DIR lalu: systemctl reload sshd"
fi
