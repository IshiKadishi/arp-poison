# arp-poison

A high-performance, cross-platform ARP spoofing and poisoning tool written in Rust.  
Designed for educational purposes and red team engagements to perform targeted Man-in-the-Middle (MITM) attacks with surgical precision.

## Features
- **Surgical Targeting**: Spoofs only specific victims (Unicast), avoiding network-wide noise.
- **Auto-Resolution**: Automatically resolves MAC addresses for Target and Gateway.
- **Continuous Poisoning**: Maintains the MITM position with configurable intervals.
- **Cross-Platform**: Runs on Linux (ELF) and Windows (PE).

---

## 🐧 Linux Setup

### 1. Enable IP Forwarding
By default, your kernel drops packets meant for other devices, causing a Denial of Service (DoS) for the victim. To act as a MITM router, you must enable forwarding.

```bash
# Enable temporarily (until reboot)
sudo sysctl -w net.ipv4.ip_forward=1
```

### 2. Running the Tool
You must run as root to open raw network sockets.

```bash
# Make executable
chmod +x arp-poison-linux-amd64

# Run
sudo ./arp-poison-linux-amd64 -i wlan0 -t 192.168.1.50 -g 192.168.1.1
```

---

## 🪟 Windows Setup

### 1. Requirements
You must install **[Npcap](https://npcap.com/)** for packet capture support.
*   **Important**: During installation, check the box **"Install Npcap in WinPcap API-compatible Mode"**.

### 2. Enable IP Forwarding
Windows calls this "IP Routing". You can enable it via PowerShell (Administrator).

1.  Find your interface name (e.g., "Wi-Fi" or "Ethernet"):
    ```powershell
    Get-NetAdapter
    ```
2.  Enable forwarding for that interface:
    ```powershell
    # Replace "Wi-Fi" with your actual interface name
    netsh interface ipv4 set interface "Wi-Fi" forwarding=enabled
    ```

### 3. Running the Tool
Open PowerShell or CMD as Administrator.

```powershell
.\arp-poison-windows-amd64.exe --interface "Wi-Fi" --target 192.168.1.50 --gateway 192.168.1.1
```

---

## arguments

| Flag | Short | Description |
|------|-------|-------------|
| `--interface` | `-i` | The network interface to use (e.g., `eth0`, `Wi-Fi`). |
| `--target` | `-t` | The victim's IP address. |
| `--gateway` | `-g` | The router/gateway IP address. |
| `--interval` | | (Optional) Spoofing interval in seconds (default: 2). |
| `--debug` | `-d` | (Optional) Enable verbose logging of sent packets. |
| `--help` | `-h` | Show the help menu. |

## Disclaimer
This tool is for educational purposes and authorized security testing only. Using this tool on networks without permission is illegal. The author is not responsible for any misuse.
