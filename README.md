# arp-poison

ARP spoofing and MITM tool written in Rust. Poisons ARP caches on specific targets — not the whole subnet — and optionally impersonates a victim at the packet level using a TUN interface.

Built as a learning project after seeing a similar tool used in a red team environment.

---

## Setup

### Linux

Enable IP forwarding or you'll DoS the victim instead of MITMing them:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Then run as root:

```bash
sudo ./arp-poison -i eth0 -t 192.168.1.50 -g 192.168.1.1
```

### Windows

Install **[Npcap](https://npcap.com/)** first. During setup, check **"Install Npcap in WinPcap API-compatible Mode"**.

Enable IP routing (run as Administrator):

```powershell
netsh interface ipv4 set interface "Wi-Fi" forwarding=enabled
```

Windows uses NPF paths instead of interface names. Find yours with:

```powershell
.\arp-poison.exe --list
```

```
NAME                                          MAC                  DESCRIPTION
----------------------------------------------------------------------------------------------------
\Device\NPF_{06A578A5-8609-494F-95C7-9F6B6DD8786F} 00:15:5d:e4:06:26    Hyper-V Virtual Ethernet Adapter
\Device\NPF_{BA8B0DB9-D651-44FF-BE3D-6EC6A6F896E2} 74:56:3c:be:fc:32    Realtek PCIe GbE Family Controller
```

Then pass the full path as the interface:

```powershell
.\arp-poison.exe -i "\Device\NPF_{BA8B0DB9-D651-44FF-BE3D-6EC6A6F896E2}" -t 192.168.1.50 -g 192.168.1.1
```

---

## Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--interface` | `-i` | | Network interface (e.g. `eth0`, `wlan0`) |
| `--targets` | `-t` | | Victim IP(s), comma-separated or repeated |
| `--gateway` | `-g` | | Router IP |
| `--interval` | | `2` | Seconds between unicast poison packets |
| `--arp-timeout` | | `3` | ARP resolution timeout per attempt (seconds) |
| `--mitm` | `-m` | | Enable packet-level MITM via TUN (Linux only) |
| `--impersonate` | | | Which target to impersonate in MITM mode (required if multiple targets) |
| `--pcap` | | | Write captured traffic to a PCAP file |
| `--restore` | `-r` | | Send correct ARP mappings to fix a poisoned network |
| `--debug` | `-d` | | Print each packet sent/received |
| `--list` | `-l` | | List interfaces and exit |

---

## MITM mode (`--mitm`)

Standard ARP poisoning puts your machine in the traffic path, but your outbound traffic still looks like you. MITM mode goes further: a `tun0` interface is created with the victim's IP, and everything flows through it.

What happens when you run with `--mitm`:

- **Your traffic out** → read from `tun0`, wrapped in an ethernet frame with the victim's MAC as source, sent to the gateway. From the network's perspective, you are the victim.
- **Traffic in for the victim** → intercepted from the raw channel, ethernet header stripped, IP packet written back into `tun0`. Your applications receive it normally.
- **Victim's own traffic** → forwarded to the gateway so they stay online and don't notice anything unusual.
- On Ctrl+C, ARP caches are restored and `tun0` is removed.

```bash
# single target, impersonation is automatic
sudo ./arp-poison -i eth0 -t 192.168.1.50 -g 192.168.1.1 --mitm

# multiple targets, pick which one to impersonate
sudo ./arp-poison -i eth0 -t 192.168.1.50,192.168.1.60 -g 192.168.1.1 --mitm --impersonate 192.168.1.50

# capture everything to pcap
sudo ./arp-poison -i eth0 -t 192.168.1.50 -g 192.168.1.1 --mitm --pcap capture.pcap
```

Route your traffic through the TUN interface:

```bash
# send all traffic via tun0 (you're now the victim to the network)
ip route add default dev tun0

# or just target specific traffic, e.g. with nmap
nmap -e tun0 192.168.1.0/24
```

---

## Disclaimer

For authorized testing and educational use only. Don't run this on networks you don't own or have explicit permission to test.
