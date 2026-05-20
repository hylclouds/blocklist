#!/usr/bin/env bash
# ============================================================
#  proxy_nuke.sh — Full Proxy Detection & Hardening Script
#  Covers: macOS + Linux
#  Tasks:  1) Kill proxy processes & daemons
#          2) Flush pf/iptables NAT rules
#          3) Remove proxy env vars from shell & system files
#          4) Harden Podman & Docker against proxy inheritance
# ============================================================

set -euo pipefail
LOGFILE="/tmp/proxy_nuke_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

# ── Detect OS ──────────────────────────────────────────────
OS="$(uname -s)"
[[ "$OS" == "Darwin" ]] && PLATFORM="macos" || PLATFORM="linux"
echo "============================================"
echo " proxy_nuke.sh | Platform: $PLATFORM"
echo " Started: $(date)"
echo " Log: $LOGFILE"
echo "============================================"

# ── Shared vars ────────────────────────────────────────────
PROXY_VARS=(
  http_proxy https_proxy ftp_proxy socks_proxy all_proxy no_proxy
  HTTP_PROXY HTTPS_PROXY FTP_PROXY SOCKS_PROXY ALL_PROXY NO_PROXY
)

PROXY_PROCS=(
  ss-local ss-redir ss-tunnel sslocal
  shadowsocks shadowsocks-rust shadowproxy
  v2ray xray sing-box
  redsocks redsocks2
  mitmproxy mitmweb mitmdump
  tun2socks gost trojan trojan-go
  privoxy squid 3proxy
  proxychains proxychains4
  proxifier surge
)

PROXY_KEYWORDS="shadowsocks|redsocks|tun2socks|v2ray|xray|mitmproxy|gost|trojan|proxychains|privoxy|squid|3proxy|sing.box|surge"

SHELL_CFGS=(
  "$HOME/.zshrc"
  "$HOME/.zprofile"
  "$HOME/.zshenv"
  "$HOME/.bashrc"
  "$HOME/.bash_profile"
  "$HOME/.profile"
)

SYS_CFGS=(
  "/etc/environment"
  "/etc/profile"
  "/etc/zshrc"
  "/etc/zprofile"
)

# ── Helper functions ───────────────────────────────────────
log_section() { echo; echo "══ $1 ══"; }
ok()  { echo "  ✅  $1"; }
warn(){ echo "  ⚠️   $1"; }
skip(){ echo "  —   $1"; }

scrub_file() {
  local f="$1"
  [[ -f "$f" ]] || return
  local pattern
  pattern="$(printf '%s|' "${PROXY_VARS[@]}")"
  pattern="${pattern%|}"
  if grep -qiE "$pattern" "$f" 2>/dev/null; then
    cp "$f" "${f}.bak.$(date +%Y%m%d_%H%M%S)"
    sed -i.tmp -E \
      "/[Ee]xport[[:space:]]+($pattern)/d; \
       /($pattern)[[:space:]]*=/d" \
      "$f" && rm -f "${f}.tmp"
    ok "Scrubbed: $f"
  fi
}

# ══════════════════════════════════════════════════════════
# SECTION 1: KILL PROXY PROCESSES
# ══════════════════════════════════════════════════════════
log_section "1. Killing proxy processes"
for proc in "${PROXY_PROCS[@]}"; do
  if pgrep -x "$proc" &>/dev/null; then
    if [[ "$PLATFORM" == "macos" ]]; then
      sudo pkill -x "$proc" 2>/dev/null && ok "Killed: $proc" || warn "Could not kill: $proc"
    else
      pkill -x "$proc" 2>/dev/null && ok "Killed: $proc" || warn "Could not kill: $proc"
    fi
  fi
done

# ══════════════════════════════════════════════════════════
# SECTION 2: FLUSH FIREWALL RULES
# ══════════════════════════════════════════════════════════
log_section "2. Flushing firewall NAT/redirect rules"

if [[ "$PLATFORM" == "macos" ]]; then
  sudo pfctl -F nat   2>/dev/null && ok "pf NAT table flushed"   || skip "pf NAT flush skipped"
  sudo pfctl -F rules 2>/dev/null && ok "pf rules table flushed" || skip "pf rules flush skipped"
else
  # iptables
  for table in nat mangle; do
    iptables  -t "$table" -F 2>/dev/null && ok "iptables $table flushed"  || skip "iptables $table unavailable"
    iptables  -t "$table" -X 2>/dev/null || true
    ip6tables -t "$table" -F 2>/dev/null && ok "ip6tables $table flushed" || skip "ip6tables $table unavailable"
    ip6tables -t "$table" -X 2>/dev/null || true
  done
  # nftables
  if command -v nft &>/dev/null; then
    nft flush ruleset 2>/dev/null && ok "nftables ruleset flushed" || skip "nftables flush skipped"
  fi
  # Policy routing (tproxy)
  ip rule del fwmark 0x1 lookup 100  2>/dev/null || true
  ip route del local default dev lo table 100 2>/dev/null || true
  ip rule flush 2>/dev/null || true
  ip rule add priority 0     lookup local   2>/dev/null || true
  ip rule add priority 32766 lookup main    2>/dev/null || true
  ip rule add priority 32767 lookup default 2>/dev/null || true
  ok "Policy routing rules reset"
  # IP forwarding off
  sysctl -w net.ipv4.ip_forward=0         2>/dev/null || true
  sysctl -w net.ipv6.conf.all.forwarding=0 2>/dev/null || true
  ok "IP forwarding disabled"
fi

# ══════════════════════════════════════════════════════════
# SECTION 3: REMOVE PROXY LAUNCH AGENTS / SYSTEMD UNITS
# ══════════════════════════════════════════════════════════
log_section "3. Removing proxy daemons"

if [[ "$PLATFORM" == "macos" ]]; then
  PLIST_DIRS=(
    "$HOME/Library/LaunchAgents"
    "/Library/LaunchAgents"
    "/Library/LaunchDaemons"
  )
  for dir in "${PLIST_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r plist; do
      if grep -qiE "$PROXY_KEYWORDS" "$plist" 2>/dev/null; then
        label=$(defaults read "$plist" Label 2>/dev/null || basename "$plist" .plist)
        sudo launchctl unload -w "$plist" 2>/dev/null || true
        sudo launchctl remove "$label"    2>/dev/null || true
        ok "Unloaded LaunchAgent: $plist"
      fi
    done < <(find "$dir" -name "*.plist" 2>/dev/null)
  done
else
  # systemd
  systemctl list-units --type=service --all --no-pager --plain 2>/dev/null \
    | awk '{print $1}' \
    | grep -iE "$PROXY_KEYWORDS" \
    | while read -r unit; do
        systemctl stop    "$unit" 2>/dev/null || true
        systemctl disable "$unit" 2>/dev/null || true
        ok "Disabled systemd unit: $unit"
      done
  find /etc/systemd/system/ /lib/systemd/system/ -name "*.service" 2>/dev/null \
    | xargs grep -liE "$PROXY_KEYWORDS" 2>/dev/null \
    | while read -r svcfile; do
        unit=$(basename "$svcfile")
        systemctl stop    "$unit" 2>/dev/null || true
        systemctl disable "$unit" 2>/dev/null || true
        ok "Disabled unit file: $svcfile"
      done
fi

# ══════════════════════════════════════════════════════════
# SECTION 4: REMOVE TUN/UTUN INTERFACES
# ══════════════════════════════════════════════════════════
log_section "4. Removing stray TUN interfaces"

if [[ "$PLATFORM" == "macos" ]]; then
  for iface in $(ifconfig -l | tr ' ' '\n' | grep -E '^(tun|utun)[0-9]+'); do
    sudo ifconfig "$iface" down 2>/dev/null && ok "Brought down: $iface" || skip "$iface"
  done
else
  for iface in $(ip link show 2>/dev/null | grep -oP '(?<=\d: )(tun|tap)[^\s@:]+'); do
    ip link set  "$iface" down   2>/dev/null || true
    ip link delete "$iface"      2>/dev/null && ok "Removed: $iface" || skip "$iface"
  done
fi

# ═════════════════════════���════════════════════════════════
# SECTION 5: DETECT + REMOVE PROXY ENVIRONMENT VARIABLES
# ══════════════════════════════════════════════════════════
log_section "5. Detecting proxy environment variables"

FOUND_ENV=false
for var in "${PROXY_VARS[@]}"; do
  val="${!var:-}"
  if [[ -n "$val" ]]; then
    warn "SET: $var='$val'"
    FOUND_ENV=true
  fi
done
$FOUND_ENV || ok "No proxy vars in current environment"

log_section "5a. Unsetting current shell vars"
for var in "${PROXY_VARS[@]}"; do
  if [[ -n "${!var:-}" ]]; then
    unset "$var" && ok "Unset: $var"
  fi
done

log_section "5b. Scrubbing shell config files"
ALL_CFGS=("${SHELL_CFGS[@]}" "${SYS_CFGS[@]}")
[[ "$PLATFORM" == "linux" ]] && ALL_CFGS+=(/etc/profile.d/*.sh /etc/environment.d/*)
for cfg in "${ALL_CFGS[@]}"; do
  scrub_file "$cfg"
done

# GNOME desktop proxy reset
if command -v gsettings &>/dev/null; then
  log_section "5c. Resetting GNOME proxy"
  gsettings set org.gnome.system.proxy mode 'none' 2>/dev/null && ok "GNOME proxy set to none"
fi

# macOS networksetup proxy reset
if [[ "$PLATFORM" == "macos" ]]; then
  log_section "5c. Resetting macOS network proxy settings"
  while IFS= read -r svc; do
    [[ "$svc" == \!* ]] && continue
    networksetup -setwebproxystate       "$svc" off 2>/dev/null || true
    networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
    networksetup -setsocksfirewallproxystate "$svc" off 2>/dev/null || true
    networksetup -setautoproxystate      "$svc" off 2>/dev/null || true
    ok "Cleared proxy on: $svc"
  done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
fi

# ══════════════════════════════════════════════════════════
# SECTION 6: HARDEN PODMAN & DOCKER
# ══════════════════════════════════════════════════════════
log_section "6. Hardening Podman against proxy inheritance"

CONTAINERS_CONF_USER="${XDG_CONFIG_HOME:-$HOME/.config}/containers/containers.conf"
mkdir -p "$(dirname "$CONTAINERS_CONF_USER")"

# Backup existing config
[[ -f "$CONTAINERS_CONF_USER" ]] && cp "$CONTAINERS_CONF_USER" "${CONTAINERS_CONF_USER}.bak.$(date +%Y%m%d_%H%M%S)"

cat > "$CONTAINERS_CONF_USER" <<'EOF'
[containers]
# Block proxy var inheritance from host into containers
http_proxy = false

# Explicitly clear proxy vars in default container environment
env = [
  "HTTP_PROXY=",
  "HTTPS_PROXY=",
  "http_proxy=",
  "https_proxy=",
  "FTP_PROXY=",
  "ftp_proxy=",
  "SOCKS_PROXY=",
  "socks_proxy=",
  "ALL_PROXY=",
  "all_proxy=",
  "NO_PROXY=localhost,127.0.0.1,::1",
  "no_proxy=localhost,127.0.0.1,::1"
]

[machine]
# Block proxy inheritance at Podman machine start
env = [
  "HTTP_PROXY=",
  "HTTPS_PROXY=",
  "http_proxy=",
  "https_proxy=",
  "ALL_PROXY=",
  "all_proxy="
]
EOF
ok "Written: $CONTAINERS_CONF_USER"

# Reload podman machine if running
if command -v podman &>/dev/null; then
  podman system service --time=0 &>/dev/null || true
  ok "Podman config applied (new containers will inherit clean env)"
fi

log_section "6b. Hardening Docker against proxy inheritance"
DOCKER_CONFIG_DIR="$HOME/.docker"
DOCKER_CONFIG="$DOCKER_CONFIG_DIR/config.json"
mkdir -p "$DOCKER_CONFIG_DIR"

# Merge proxy block into existing Docker config.json using Python (avoids jq dependency)
python3 - <<PYEOF
import json, os, sys

path = "$DOCKER_CONFIG"
cfg = {}
if os.path.exists(path):
    with open(path) as f:
        try:
            cfg = json.load(f)
        except json.JSONDecodeError:
            pass

cfg.setdefault("proxies", {})["default"] = {
    "httpProxy":  "",
    "httpsProxy": "",
    "ftpProxy":   "",
    "noProxy":    "localhost,127.0.0.1,::1"
}

with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
print("  ✅  Written: {}".format(path))
PYEOF

# Docker daemon.json — clear proxies at daemon level
DOCKER_DAEMON_JSON="/etc/docker/daemon.json"
if [[ -f "$DOCKER_DAEMON_JSON" ]] || [[ "$EUID" -eq 0 ]]; then
  python3 - <<PYEOF
import json, os

path = "$DOCKER_DAEMON_JSON"
cfg = {}
if os.path.exists(path):
    with open(path) as f:
        try:
            cfg = json.load(f)
        except:
            pass
cfg["proxies"] = {"http-proxy": "", "https-proxy": "", "no-proxy": "localhost,127.0.0.1"}
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
print("  ✅  Written: {}".format(path))
PYEOF
  [[ "$PLATFORM" == "linux" ]] && systemctl reload docker 2>/dev/null && ok "Docker daemon reloaded" || true
fi

# ══════════════════════════════════════════════════════════
# SECTION 7: FLUSH DNS
# ══════════════════════════════════════════════════════════
log_section "7. Flushing DNS cache"
if [[ "$PLATFORM" == "macos" ]]; then
  sudo dscacheutil -flushcache
  sudo killall -HUP mDNSResponder 2>/dev/null || true
  ok "macOS DNS cache flushed"
else
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    resolvectl flush-caches 2>/dev/null && ok "systemd-resolved cache flushed"
  elif command -v nscd &>/dev/null; then
    service nscd restart 2>/dev/null && ok "nscd restarted"
  fi
fi

# ══════════════════════════════════════════════════════════
# VERIFICATION
# ══════════════════════════════════════════════════════════
log_section "FINAL VERIFICATION"
CLEAN=true
for var in "${PROXY_VARS[@]}"; do
  if [[ -n "${!var:-}" ]]; then
    warn "Still set: $var='${!var}'"
    CLEAN=false
  fi
done
$CLEAN && ok "All proxy env vars cleared in current shell"

if command -v podman &>/dev/null; then
  RESULT=$(podman run --rm alpine sh -c 'env | grep -iE "proxy" || echo "✅ No proxy vars"' 2>/dev/null || echo "podman not running")
  echo "  Podman container env check: $RESULT"
fi

echo ""
echo "============================================"
echo " proxy_nuke.sh COMPLETE"
echo " Log: $LOGFILE"
echo " ⚠️  Open a NEW terminal to clear inherited env"
echo " ⚠️  Run 'source ~/.zshrc' or ~/.bashrc"
echo "============================================"