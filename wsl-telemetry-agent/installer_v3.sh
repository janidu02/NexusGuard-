#!/bin/bash

# ===========================
# Windows log location universal
# ===========================
WIN_LOG_DIR="/mnt/c/ProgramData/NexusGuard"
WIN_LOG_FILE="$WIN_LOG_DIR/command_stream.log"

mkdir -p "$WIN_LOG_DIR"
touch "$WIN_LOG_FILE"

echo "[+] Windows log file ensured at: $WIN_LOG_FILE"
echo

# ===========================
# NEXUSGUARD BLOCK
# Format:
# timestamp|command|PID=...|user|host|distro
# Command is redacted before logging
# ===========================
read -r -d '' LOG_BLOCK << 'EOF'
# === NexusGuard Command Logger ===
export NEXUSGUARD_CMD_STREAM="/mnt/c/ProgramData/NexusGuard/command_stream.log"
export LAST_NEXUSGUARD_CMD=""
export NEXUSGUARD_IN_LOGGER="0"

# Determine real user even under sudo/su
nexusguard_get_user() {
    if [[ -n "${SUDO_USER:-}" ]]; then
        echo "$SUDO_USER"
    elif [[ -n "${LOGNAME:-}" ]]; then
        echo "$LOGNAME"
    else
        echo "$USER"
    fi
}

# Determine distro name + WSL distro
nexusguard_get_distro() {
    local linux_name="Linux"
    local linux_ver=""

    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        [[ -n "${NAME:-}" ]] && linux_name="$NAME"
        [[ -n "${VERSION_ID:-}" ]] && linux_ver="$VERSION_ID"
    fi

    local wsl_part=""
    if [[ -n "${WSL_DISTRO_NAME:-}" ]]; then
        wsl_part=" (WSL=${WSL_DISTRO_NAME})"
    fi

    if [[ -n "$linux_ver" ]]; then
        echo "${linux_name} ${linux_ver}${wsl_part}"
    else
        echo "${linux_name}${wsl_part}"
    fi
}

# Redact secrets before writing commands to disk
nexusguard_redact_cmd() {
    local cmd="$1"

    # Keep log delimiter safe
    cmd="${cmd//|/<PIPE>}"

    cmd="$(printf '%s' "$cmd" | sed -E '
s/((^|[[:space:];])([A-Za-z_][A-Za-z0-9_]*(PASSWORD|PASSWD|PASS|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|SECRET[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|AUTH|JWT|BEARER|COOKIE|SESSION|WEBHOOK|CONNECTION[_-]?STRING)[A-Za-z0-9_]*)=)([^[:space:]]+)/\1<REDACTED>/gI
s/(Authorization:[[:space:]]*Bearer[[:space:]]+)[^[:space:]]+/\1<REDACTED>/gI
s/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]+/\1<REDACTED>/gI
s/(--?(password|passwd|pass|token|secret|api-key|apikey|access-key|secret-key|client-secret)[=[:space:]]+)[^[:space:]]+/\1<REDACTED>/gI
s/([[:space:]]-p)[^[:space:]]+/\1<REDACTED>/g
s/([[:space:]]-p[[:space:]]+)[^[:space:]]+/\1<REDACTED>/g
s#(https?://)[^/@[:space:]]+@#\1<REDACTED>@#gI
s#(ftp://)[^/@[:space:]]+@#\1<REDACTED>@#gI
')"

    printf '%s' "$cmd"
}

# --- Pre-exec hook for normal commands ---
nexusguard_preexec() {
    [[ $- != *i* ]] && return

    # Prevent recursion inside logger
    [[ "${NEXUSGUARD_IN_LOGGER:-0}" == "1" ]] && return
    export NEXUSGUARD_IN_LOGGER="1"

    local raw_cmd
    raw_cmd="$(history 1 | sed 's/^ *[0-9]\+ *//')"

    if [[ -z "$raw_cmd" ]]; then
        export NEXUSGUARD_IN_LOGGER="0"
        return
    fi

    # Prevent duplicate logging when Enter is pressed
    if [[ "$raw_cmd" == "$LAST_NEXUSGUARD_CMD" ]]; then
        export NEXUSGUARD_IN_LOGGER="0"
        return
    fi
    export LAST_NEXUSGUARD_CMD="$raw_cmd"

    # Skip shell noise and logger internals
    case "$raw_cmd" in
        history*|trap*|source*|alias*|unalias*|*NexusGuard*|*installer* )
            export NEXUSGUARD_IN_LOGGER="0"
            return ;;
        nmap*|masscan*|sqlmap*|hydra*|nikto*|john*|hashcat*|msfconsole*|gobuster*|ffuf*|tcpdump*|ping* )
            export NEXUSGUARD_IN_LOGGER="0"
            return ;;
    esac

    local safe_cmd ts user host distro
    safe_cmd="$(nexusguard_redact_cmd "$raw_cmd")"
    ts="$(date "+%Y-%m-%dT%H:%M:%S%z")"
    user="$(nexusguard_get_user)"
    host="$(hostname)"
    distro="$(nexusguard_get_distro)"

    echo "${ts}|${safe_cmd}|PID=null|${user}|${host}|${distro}" >> "$NEXUSGUARD_CMD_STREAM"

    export NEXUSGUARD_IN_LOGGER="0"
}

# Avoid duplicate traps
if [[ -z "${NEXUSGUARD_TRAP_SET:-}" ]]; then
    export NEXUSGUARD_TRAP_SET="1"
    trap 'nexusguard_preexec' DEBUG
fi

# --- PID wrapper for heavy tools ---
nexusguard_exec() {
    local raw_cmd="$*"
    local safe_cmd ts user host distro

    safe_cmd="$(nexusguard_redact_cmd "$raw_cmd")"
    ts="$(date "+%Y-%m-%dT%H:%M:%S%z")"
    user="$(nexusguard_get_user)"
    host="$(hostname)"
    distro="$(nexusguard_get_distro)"

    command "$@" &
    local pid=$!

    echo "${ts}|${safe_cmd}|PID=${pid}|${user}|${host}|${distro}" >> "$NEXUSGUARD_CMD_STREAM"
    wait "$pid"
}

# Heavy tool aliases
alias nmap='nexusguard_exec nmap'
alias sshpass='nexusguard_exec sshpass'
alias masscan='nexusguard_exec masscan'
alias sqlmap='nexusguard_exec sqlmap'
alias hydra='nexusguard_exec hydra'
alias nikto='nexusguard_exec nikto'
alias john='nexusguard_exec john'
alias hashcat='nexusguard_exec hashcat'
alias msfconsole='nexusguard_exec msfconsole'
alias gobuster='nexusguard_exec gobuster'
alias ffuf='nexusguard_exec ffuf'
alias tcpdump='nexusguard_exec tcpdump'
alias ping='nexusguard_exec ping'
# === End NexusGuard Command Logger ===
EOF

# ===========================
# Replace old NexusGuard block safely
# ===========================
install_or_replace_block() {
    local target_file="$1"
    local use_sudo="$2"

    if [[ "$use_sudo" == "yes" ]]; then
        sudo touch "$target_file"
        sudo cp "$target_file" "${target_file}.nexusguard_backup_$(date +%Y%m%d_%H%M%S)"
        sudo sed -i '/# === NexusGuard Command Logger ===/,/# === End NexusGuard Command Logger ===/d' "$target_file"
        printf "\n%s\n" "$LOG_BLOCK" | sudo tee -a "$target_file" >/dev/null
    else
        touch "$target_file"
        cp "$target_file" "${target_file}.nexusguard_backup_$(date +%Y%m%d_%H%M%S)"
        sed -i '/# === NexusGuard Command Logger ===/,/# === End NexusGuard Command Logger ===/d' "$target_file"
        printf "\n%s\n" "$LOG_BLOCK" >> "$target_file"
    fi
}

echo "[+] Updating ~/.bashrc"
install_or_replace_block "$HOME/.bashrc" "no"
echo "    → Installed secure redaction logger"

echo "[+] Updating /root/.bashrc"
install_or_replace_block "/root/.bashrc" "yes"
echo "    → Installed secure redaction logger"

echo
echo "[✓] NexusGuard secure logger installed successfully!"
echo "[!] Run:"
echo "    source ~/.bashrc"
echo "    sudo su"
echo "    source /root/.bashrc"
echo
echo "[!] Test redaction:"
echo "    export AWS_SECRET_ACCESS_KEY=SECRET123"
echo "    curl -H \"Authorization: Bearer TOKEN123\" https://example.com"
echo "    mysql -u root -pMyPassword"
echo
echo "[!] Check:"
echo "    tail -n 10 /mnt/c/ProgramData/NexusGuard/command_stream.log"