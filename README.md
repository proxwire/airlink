# airlink

Turn a Linux machine into a **wireless access point** on a chosen WiFi adapter, with a rogue DHCP server and an optional interception stack on top. The wireless sibling of [proxlink](../jackin) — same DHCP / DNS / Burp / credential-capture core, but clients associate over the air instead of an ethernet cable. Built for **pen testing** (evil-twin / captive setups, unknown wireless clients), **lab and field work** where you need a device to join a network you control, and **quick links** to WiFi gear when you don't know its SSID or subnet. *Wireless link active.*

> ### Authorized use only
>
> airlink is an offensive wireless tool. It runs a rogue access point and DHCP server, can spoof DNS, transparently intercept HTTPS, capture credentials from traffic, sniff nearby devices' probe requests, deauthenticate clients, and capture WPA handshakes. Use it **only** on equipment and networks you own or have explicit written permission to test.
>
> Operating a rogue AP, deauthenticating clients, or capturing handshakes on a network you don't control is illegal in most jurisdictions (in the US, e.g., the Computer Fraud and Abuse Act and FCC rules on interference). You are responsible for how you use it.

## Features

- **Access point** — Uses `hostapd` to broadcast a WiFi network. **Open** by default, or **WPA2-PSK** with `-k <passphrase>` for clients that refuse open networks
- **DHCP server** — Uses `dnsmasq` to hand out IPs on a configurable subnet to clients that associate
- **SSID / channel / band** — Set the network name with `-e`, the channel with `-c` (1–14 = 2.4GHz, 36+ = 5GHz)
- **Hidden SSID** — `-H` runs the AP without broadcasting its name
- **BSSID spoofing** — `-m random` or `-m aa:bb:cc:dd:ee:ff` sets the AP's MAC via `macchanger`; the original is restored on exit
- **Probe-request sniffing + SSID clone** — `-P` puts the adapter into monitor mode *before* the AP starts, sniffs the probe requests nearby devices broadcast (the networks they remember and are looking for), and offers to **clone one as your SSID** (evil twin). Works on a single adapter because the AP isn't up yet
- **Second-adapter recon** — `-M <iface>` puts a second adapter into monitor mode so you can sniff, deauth, and capture handshakes **while the AP keeps running** on the first. Required on radios that can't do AP + monitor at once (most can't)
- **Live probe sniff** — Press **`p`** to sniff probe requests during a session (needs `-M`)
- **WPA handshake capture** — Press **`w`** to capture a target AP's 4-way handshake with `airodump-ng`, firing a few deauths to prompt a reassociation (needs `-M`). Confirms the handshake with `aircrack-ng` and saves the `.cap`
- **Deauthentication** — Press **`x`** to deauth a specific client (or all clients) off a target AP with `aireplay-ng` — knock a device off the real network so it reassociates to yours (needs `-M`)
- **Station list** — Press **`t`** (or **Enter**) to list clients currently associated to your AP, matched to their DHCP leases
- **Device watcher** — Always on. Uses dnsmasq's `--dhcp-script` hook to announce new and reconnecting clients automatically, with an immediate `arp-scan`
- **DNS query logging** — Always on. Every domain a client resolves is logged to `logs/dns.log`. Press **`l`** to tail the last 30 entries
- **DNS spoofing** — `-D` redirects all DNS queries back to your machine via dnsmasq's `address=/#/` directive
- **Optional internet sharing** — Share internet from another interface (e.g. `eth0`) to the wireless network via NAT/iptables, with an optional single-destination allowlist (`-o`)
- **Credential capture** — Press **`c`** to capture traffic for 60s and extract creds (NTLM, HTTP basic, SQL, SMB, Kerberos, etc.) via **PCredz** or **NetCredz** if installed
- **Rolling background pcap** — `-r` starts a continuous background capture in 5-minute rotating files (last ~1 hour kept in `creds/`)
- **Burp redirect + CA cert server** — With **`-b [port]`**, client HTTP/HTTPS (80, 443) is transparently redirected to a Burp proxy on the host; a self-signed CA is generated and served at `http://GATEWAY/ca.crt` (default port 8080)
- **Cleanup on exit** — Stops hostapd, removes iptables rules, releases both adapters back to NetworkManager, restores a spoofed MAC, and restores the host's original IP-forwarding setting when you stop the script (Ctrl+C)

## Requirements

- Linux with `root` (or `sudo`)
- A **wireless adapter that supports AP mode** (check with `iw phy phyN info` → *Supported interface modes* includes `AP`)
- **hostapd** — Runs the access point
- **dnsmasq** — DHCP/DNS server
- **iw** — Wireless interface control (mode, channel)
- **arp-scan** — Client discovery
- **tcpdump** — Used for probe sniffing, credential capture, and rolling pcap
- **iptables** — For NAT when using internet sharing (`-s`) or Burp redirect (`-b`)
- **aircrack-ng suite** (optional) — `airodump-ng` / `aireplay-ng` for handshake capture (`w`) and deauth (`x`)
- **macchanger** (optional) — For BSSID spoofing (`-m`)
- **openssl** / **python3** (optional) — Auto-generates and serves a CA cert when `-b` is used
- **PCredz** or **NetCredz** (optional) — To extract credentials from captures

### Install dependencies (Debian/Kali/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y hostapd dnsmasq iw arp-scan tcpdump iptables aircrack-ng macchanger
# Optional: credential extraction (Kali often has pcredz)
sudo apt-get install -y pcredz
```

> **Note:** installing `hostapd` on Debian/Kali often leaves its systemd unit masked. That's fine — airlink launches `hostapd` directly, not through systemd.

## Two radios, one caveat

Most WiFi chipsets **cannot run an access point and monitor mode on the same radio at the same time**. Check yours:

```bash
iw phy phy0 info | grep -A6 'valid interface combinations'
```

If the AP/monitor combination isn't listed, then:

- The **`-P` startup probe scan** still works on a single adapter, because it sniffs *before* the AP comes up and switches back to AP mode afterward.
- The **live recon keys (`p`, `w`, `x`)** require a **second adapter** via `-M`. Without it, those keys print a hint and do nothing; the AP and everything else still run normally.

## Usage

Run as **root** (e.g. `sudo ./airlink.sh`).

```text
./airlink.sh [-i iface] [-e ssid] [-c channel] [-k passphrase] [-H] [-m bssid]
             [-M mon_iface] [-P] [-p prefix] [-s internet_iface] [-b [port]]
             [-o allow_dest] [-D] [-r]
```

| Option | Description |
|--------|-------------|
| `-i iface` | Wireless interface for the AP. Default: `wlan0` |
| `-e ssid` | SSID / network name to broadcast. Default: `airlink` |
| `-c channel` | Channel: 1–14 = 2.4GHz, 36+ = 5GHz. Default: `6` |
| `-k passphrase` | WPA2 passphrase (8–63 chars). Omit for an **open** network |
| `-H` | Hidden SSID (do not broadcast the name) |
| `-m bssid` | Spoof the AP's BSSID: `random` or `aa:bb:cc:dd:ee:ff` |
| `-M iface` | Second adapter → monitor mode for live sniff/deauth/handshake |
| `-P` | Sniff probe requests at startup and offer to clone an SSID |
| `-p prefix` | Network prefix as `X.Y.Z` (e.g. `10.0.0`). Default: `10.0.0` |
| `-s iface` | Interface with internet to share via NAT to the wireless network |
| `-b [port]` | Redirect client HTTP/HTTPS (80, 443) to Burp. Default port: **8080** |
| `-o allow_dest` | With `-s`, only allow client traffic to this single IP/domain |
| `-D` | Spoof all DNS queries back to this machine |
| `-r` | Record rolling background pcap (5min chunks, last ~1hr kept in `creds/`) |
| `-h` | Show usage |

> **Note:** all three `-b` forms work — `-b` (default port), `-b8443`, and `-b 8443`.

- `-h` works without root; everything else requires it.
- The script sets the AP's gateway IP to `PREFIX.1` (e.g. `10.0.0.1`).
- DHCP range is `PREFIX.3`–`PREFIX.200`, lease 12h.
- While running: **Enter** = scan + stations; **`t`** = stations; **`c`** = capture creds; **`l`** = tail DNS log; **`p`** = probe sniff*; **`w`** = WPA handshake*; **`x`** = deauth*. (* need `-M`.) **Ctrl+C** = exit and cleanup.

### Access point modes

**Open network on the default adapter and subnet:**

```bash
sudo ./airlink.sh
```

**Named WPA2 network on channel 1:**

```bash
sudo ./airlink.sh -e "Guest WiFi" -c 1 -k "hunter2hunter2"
```

**Hidden network with a spoofed BSSID:**

```bash
sudo ./airlink.sh -e CorpNet -H -m random
```

### Probe sniffing and SSID cloning

Nearby phones and laptops constantly broadcast **probe requests** — the names of networks they remember and want to rejoin. `-P` captures these before the AP starts and lets you clone one:

```bash
sudo ./airlink.sh -P
```

1. The adapter goes into monitor mode and sniffs probe requests for ~15s.
2. It lists the named SSIDs devices are looking for.
3. Pick one by number to broadcast it as your AP (or press Enter to keep the default). A device that remembers an **open** network with that name may then auto-join.
4. The adapter switches to AP mode and the network comes up.

With a **second adapter** (`-M`), press **`p`** during a session to sniff probes live without taking the AP down.

### Second adapter: handshake capture and deauth

Plug in a second monitor-capable adapter and pass it with `-M`:

```bash
sudo ./airlink.sh -e FreeWiFi -M wlan1
```

- **`w`** — Prompts for a target BSSID and channel, tunes `wlan1` to it, runs `airodump-ng`, fires a few deauths to force a client reassociation, and saves the WPA handshake to `creds/handshake_<ts>-01.cap`. Crack it offline with `aircrack-ng -w <wordlist> <cap>`.
- **`x`** — Prompts for a target BSSID, channel, and optional client MAC (blank = all clients), then deauthenticates with `aireplay-ng`. Use this to knock a device off the real AP so it reassociates to your clone.

Deauth and handshake capture are the standard aircrack workflow; they are **actively disruptive** and legal only against networks you're authorized to test.

### Internet sharing, DNS, Burp

These behave exactly as in [proxlink](../jackin) — see that README for the details of `-s`, `-o`, `-D`, `-b`, the CA server, and rolling pcap. In short:

**Give clients internet while proxying through Burp (full interception session):**

```bash
sudo ./airlink.sh -e "Airport WiFi" -s eth0 -b -r
```

**Open AP, share internet, spoof all DNS to yourself, rolling capture:**

```bash
sudo ./airlink.sh -s eth0 -D -r
```

**Lock clients to a single destination:**

```bash
sudo ./airlink.sh -s eth0 -o example.com
```

## When this might not work

- **Adapter doesn't support AP mode** — Some cheap USB adapters are station-only. Check `iw phy phyN info` for `AP` under *Supported interface modes*. If it's absent, hostapd will fail to start.
- **hostapd exits immediately** — Usually a channel not permitted by your regulatory domain, a soft/hard `rfkill` block, or the radio being busy (NetworkManager grabbing it back). The script releases the interface from NetworkManager and unblocks rfkill, and prints the last lines of hostapd's log on failure. Set your regdomain with `iw reg set <CC>` for 5GHz channels.
- **5GHz / DFS channels** — DFS channels need a country code and radar detection; prefer 2.4GHz (1/6/11) or a non-DFS 5GHz channel (36/40/44/48) for reliability.
- **AP + monitor on one radio** — Not supported by most chipsets (see *Two radios, one caveat*). Use `-M` with a second adapter for live `p`/`w`/`x`.
- **NetworkManager fights for the card** — The script sets the interface `managed no` for the session and restores it on exit. If NM was reconfigured mid-session it may still interfere; `nmcli dev set <iface> managed no` manually if needed.
- **Clients won't join an open network** — Modern phones warn on or avoid open networks. Use `-k` for WPA2, or clone a known open SSID with `-P`.
- **No probe requests seen** — Devices often only probe when their screen wakes or WiFi toggles. Run `-P` (or `p`) again with a device active nearby.
- **IPv4 only** — DHCP, ARP scanning and detection are all IPv4.

## Notes

- **Root required** — Everything except `-h` exits with an error if not run as root.
- **Paths are script-relative** — `creds/`, `logs/`, `serve/` and `ca/` are created next to `airlink.sh`, so you can run it by absolute path from anywhere.
- **File ownership** — Output directories are mode `700` and chowned to the user who invoked `sudo`, so captures stay private but open in Wireshark without root.
- **hostapd runs directly** — Not via systemd, so a masked `hostapd.service` doesn't matter. The config is written to a temp dir and removed on exit.
- **Interface handoff** — The AP (and monitor) interfaces are taken from NetworkManager with `nmcli dev set … managed no` for the session and handed back on exit. A spoofed MAC is reset with `macchanger -p`.
- **Backup** — Writes a custom config to `/etc/dnsmasq.d/custom-dhcp.conf` and backs up `/etc/dnsmasq.conf` to `/etc/dnsmasq.conf.bak` (only on first run).
- **Other DHCP servers are stopped** — At startup the script stops `dnsmasq`, `dhclient` and `isc-dhcp-server`. As with proxlink, this also stops a libvirt/LXD dnsmasq if one is running.
- **IP forwarding** — `-s`/`-b` enable `net.ipv4.ip_forward` and cleanup restores whatever the host had before.
- **Cleanup** — On exit (Ctrl+C or SIGTERM): stops hostapd and dnsmasq, removes `custom-dhcp.conf`, kills background processes (rolling pcap, CA server, device watcher), removes NAT/redirect rules, releases both adapters back to NetworkManager, restores any spoofed MAC, and removes its temp directory.

## License

MIT — see [LICENSE](LICENSE).
