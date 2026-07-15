#!/usr/bin/env bash
# Ubuntu Server Security Report
# SSH attacks, port scans, UFW blocks and Fail2ban activity.

set -u
set -o pipefail

HOURS="${1:-12}"

if ! [[ "$HOURS" =~ ^[0-9]+$ ]] || (( HOURS < 1 || HOURS > 720 )); then
    echo "Kullanım: $0 [saat]"
    echo "Örnek: $0 12"
    exit 1
fi

SINCE="$HOURS hours ago"

if (( EUID == 0 )); then
    SUDO=""
else
    if ! command -v sudo >/dev/null 2>&1; then
        echo "Hata: Bu betik root yetkisi veya sudo gerektirir."
        exit 1
    fi
    sudo -v || exit 1
    SUDO="sudo"
fi

section() {
    printf '\n============================================================\n'
    printf ' %s\n' "$1"
    printf '============================================================\n'
}

no_result() {
    echo "Kayıt bulunamadı."
}

SSHD_PATTERN='Invalid user|Failed password|authentication failure|banner exchange|Unable to negotiate|Connection closed|maximum authentication attempts|Too many authentication failures|Bad protocol version|Did not receive identification string|kex_exchange_identification|Connection reset|Connection refused|POSSIBLE BREAK-IN'

UFW_LOG="$($SUDO journalctl -k --since "$SINCE" --no-pager 2>/dev/null | grep -E '\[UFW (BLOCK|LIMIT|REJECT)\]' || true)"
SSH_LOG="$($SUDO journalctl _COMM=sshd --since "$SINCE" --no-pager 2>/dev/null | grep -Ei "$SSHD_PATTERN" || true)"

section "UBUNTU SUNUCU GÜVENLİK RAPORU"
echo "Sunucu       : $(hostname)"
echo "Rapor zamanı : $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "Zaman aralığı: Son $HOURS saat"
echo "Çekirdek     : $(uname -r)"

section "1. UFW TARAFINDAN ENGELLENEN TÜM BAĞLANTILAR"
if [[ -n "$UFW_LOG" ]]; then
    printf '%s\n' "$UFW_LOG"
else
    no_result
fi

section "2. EN ÇOK ENGELLENEN KAYNAK IP ADRESLERİ"
if [[ -n "$UFW_LOG" ]]; then
    printf '%s\n' "$UFW_LOG" |
        grep -oP 'SRC=\K[^ ]+' |
        sort | uniq -c | sort -nr || true
else
    no_result
fi

section "3. EN ÇOK DENENEN HEDEF PORTLAR"
if [[ -n "$UFW_LOG" ]]; then
    printf '%s\n' "$UFW_LOG" |
        grep -oP 'DPT=\K[0-9]+' |
        sort | uniq -c | sort -nr || true
else
    no_result
fi

section "4. IP + PROTOKOL + HEDEF PORT ÖZETİ"
if [[ -n "$UFW_LOG" ]]; then
    printf '%s\n' "$UFW_LOG" |
        awk '
        {
            src=""; proto=""; dpt="";
            for (i=1; i<=NF; i++) {
                if ($i ~ /^SRC=/)   {split($i,a,"="); src=a[2]}
                if ($i ~ /^PROTO=/) {split($i,a,"="); proto=a[2]}
                if ($i ~ /^DPT=/)   {split($i,a,"="); dpt=a[2]}
            }
            if (src != "" && dpt != "") print src, proto, dpt;
        }' |
        sort | uniq -c | sort -nr || true
else
    no_result
fi

section "5. TÜM ŞÜPHELİ SSH OLAYLARI"
if [[ -n "$SSH_LOG" ]]; then
    printf '%s\n' "$SSH_LOG"
else
    no_result
fi

section "6. SSH OLAYLARINDA GÖRÜLEN IP ADRESLERİ"
if [[ -n "$SSH_LOG" ]]; then
    printf '%s\n' "$SSH_LOG" |
        grep -oP '(?:from |rhost=|Connection from |Connection closed by |with )\K[0-9a-fA-F:.]+' |
        sort | uniq -c | sort -nr || true
else
    no_result
fi

section "7. DENENEN SSH KULLANICI ADLARI"
USER_SUMMARY="$($SUDO journalctl _COMM=sshd --since "$SINCE" --no-pager 2>/dev/null |
    grep -oP 'Invalid user \K\S+|Failed password for invalid user \K\S+|Failed password for \K\S+|user=\K\S+' |
    grep -Ev '^(invalid|Failed)$' |
    sort | uniq -c | sort -nr || true)"
if [[ -n "$USER_SUMMARY" ]]; then
    printf '%s\n' "$USER_SUMMARY"
else
    no_result
fi

section "8. SON $HOURS SAATTEKİ FAIL2BAN İŞLEMLERİ"
if command -v fail2ban-client >/dev/null 2>&1; then
    if $SUDO test -f /var/log/fail2ban.log; then
        F2B_LOG="$($SUDO awk -v start="$(date -d "$SINCE" '+%Y-%m-%d %H:%M:%S')" \
            'substr($0,1,19) >= start' /var/log/fail2ban.log 2>/dev/null |
            grep -E 'Found |Ban |Unban |Restore Ban|Increase Ban|already banned' || true)"
    else
        F2B_LOG="$($SUDO journalctl -u fail2ban --since "$SINCE" --no-pager 2>/dev/null |
            grep -E 'Found |Ban |Unban |Restore Ban|Increase Ban|already banned' || true)"
    fi

    if [[ -n "$F2B_LOG" ]]; then
        printf '%s\n' "$F2B_LOG"
    else
        no_result
    fi
else
    echo "Fail2ban kurulu değil veya fail2ban-client PATH içinde değil."
fi

section "9. FAIL2BAN JAIL DURUMLARI"
if command -v fail2ban-client >/dev/null 2>&1; then
    STATUS="$($SUDO fail2ban-client status 2>/dev/null || true)"
    if [[ -n "$STATUS" ]]; then
        printf '%s\n' "$STATUS"

        JAILS="$(printf '%s\n' "$STATUS" |
            sed -n 's/.*Jail list:[[:space:]]*//p' |
            tr ',' ' ')"

        for jail in $JAILS; do
            jail="$(echo "$jail" | xargs)"
            [[ -z "$jail" ]] && continue
            echo
            echo "--- Jail: $jail ---"
            $SUDO fail2ban-client status "$jail" 2>/dev/null || true
        done
    else
        echo "Fail2ban çalışmıyor veya durum bilgisi alınamadı."
    fi
else
    echo "Fail2ban kurulu değil."
fi

section "10. BAŞARILI SSH GİRİŞLERİ"
SUCCESS_LOG="$($SUDO journalctl _COMM=sshd --since "$SINCE" --no-pager 2>/dev/null |
    grep -E 'Accepted password|Accepted publickey|Accepted keyboard-interactive' || true)"
if [[ -n "$SUCCESS_LOG" ]]; then
    printf '%s\n' "$SUCCESS_LOG"
else
    echo "Başarılı SSH girişi görünmüyor."
fi

section "11. ROOT, SUDO VE CRON HAREKETLERİ"
ROOT_LOG="$($SUDO journalctl --since "$SINCE" --no-pager 2>/dev/null |
    grep -Ei 'sudo.*COMMAND=|session opened for user root|su:.*session opened|CRON.*session opened for user root' || true)"
if [[ -n "$ROOT_LOG" ]]; then
    printf '%s\n' "$ROOT_LOG"
else
    no_result
fi

section "12. DİNLENEN TCP/UDP PORTLARI"
$SUDO ss -tulpen 2>/dev/null || no_result

section "13. UFW DURUMU"
if command -v ufw >/dev/null 2>&1; then
    $SUDO ufw status verbose 2>/dev/null || true
else
    echo "UFW kurulu değil."
fi

section "14. BAŞARISIZ SYSTEMD SERVİSLERİ"
FAILED_UNITS="$($SUDO systemctl --failed --no-pager 2>/dev/null || true)"
if [[ -n "$FAILED_UNITS" ]]; then
    printf '%s\n' "$FAILED_UNITS"
else
    no_result
fi

section "RAPOR TAMAMLANDI"
echo "Not: Bu betik yalnızca günlükleri okur; firewall veya servis ayarlarını değiştirmez."
