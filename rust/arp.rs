use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;

use crate::results::ScanResult;

const ARP_PACKET_SIZE: usize = 28;
const ETHERNET_HEADER_SIZE: usize = 14;
const TOTAL_FRAME_SIZE: usize = ETHERNET_HEADER_SIZE + ARP_PACKET_SIZE;

/// Find the best network interface for reaching a target IP.
fn find_interface_for_target(target: Ipv4Addr) -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();

    // Find an interface with an IPv4 address on the same subnet
    for iface in &interfaces {
        if iface.is_loopback() || !iface.is_up() || !iface.is_running() {
            continue;
        }
        if iface.mac.is_none() {
            continue;
        }
        for ip_net in &iface.ips {
            if let std::net::IpAddr::V4(iface_ip) = ip_net.ip() {
                let prefix = ip_net.prefix();
                let mask = if prefix == 0 {
                    0u32
                } else {
                    !((1u32 << (32 - prefix)) - 1)
                };
                let iface_net = u32::from(iface_ip) & mask;
                let target_net = u32::from(target) & mask;
                if iface_net == target_net {
                    return Some(iface.clone());
                }
            }
        }
    }

    // Fallback: first non-loopback interface with a MAC
    interfaces
        .into_iter()
        .find(|i| !i.is_loopback() && i.is_up() && i.mac.is_some())
}

fn get_interface_ipv4(iface: &NetworkInterface) -> Option<Ipv4Addr> {
    for ip_net in &iface.ips {
        if let std::net::IpAddr::V4(ipv4) = ip_net.ip() {
            return Some(ipv4);
        }
    }
    None
}

/// Perform ARP scan on a single host. Blocking.
fn arp_scan_host_sync(
    ip: Ipv4Addr,
    timeout: Duration,
) -> ScanResult {
    let ip_str = ip.to_string();

    let iface = match find_interface_for_target(ip) {
        Some(i) => i,
        None => return ScanResult::dead_arp(ip_str),
    };

    let source_mac = match iface.mac {
        Some(mac) => mac,
        None => return ScanResult::dead_arp(ip_str),
    };

    let source_ip = match get_interface_ipv4(&iface) {
        Some(ip) => ip,
        None => return ScanResult::dead_arp(ip_str),
    };

    // Open datalink channel
    let config = datalink::Config {
        read_timeout: Some(timeout),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(&iface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return ScanResult::dead_arp(ip_str),
    };

    // Build ARP request
    let mut eth_buf = [0u8; TOTAL_FRAME_SIZE];
    {
        let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
        eth_pkt.set_destination(MacAddr::broadcast());
        eth_pkt.set_source(source_mac);
        eth_pkt.set_ethertype(EtherTypes::Arp);

        let mut arp_buf = [0u8; ARP_PACKET_SIZE];
        {
            let mut arp_pkt = MutableArpPacket::new(&mut arp_buf).unwrap();
            arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp_pkt.set_protocol_type(EtherTypes::Ipv4);
            arp_pkt.set_hw_addr_len(6);
            arp_pkt.set_proto_addr_len(4);
            arp_pkt.set_operation(ArpOperations::Request);
            arp_pkt.set_sender_hw_addr(source_mac);
            arp_pkt.set_sender_proto_addr(source_ip);
            arp_pkt.set_target_hw_addr(MacAddr::zero());
            arp_pkt.set_target_proto_addr(ip);
        }
        eth_pkt.set_payload(&arp_buf);
    }

    let start = Instant::now();

    // Send ARP request
    if tx.send_to(&eth_buf, None).is_none() {
        return ScanResult::dead_arp(ip_str);
    }

    // Wait for reply
    while start.elapsed() < timeout {
        match rx.next() {
            Ok(data) => {
                if let Some(eth_pkt) = EthernetPacket::new(data) {
                    if eth_pkt.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp_pkt) = ArpPacket::new(eth_pkt.payload()) {
                            if arp_pkt.get_operation() == ArpOperations::Reply
                                && arp_pkt.get_sender_proto_addr() == ip
                            {
                                let rtt = start.elapsed().as_secs_f64() * 1000.0;
                                let mac = arp_pkt.get_sender_hw_addr().to_string();
                                return ScanResult::alive_arp(ip_str, rtt, mac);
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    ScanResult::dead_arp(ip_str)
}

/// Async wrapper for ARP scanning.
pub async fn arp_scan_host(ip: Ipv4Addr, timeout: Duration) -> ScanResult {
    tokio::task::spawn_blocking(move || arp_scan_host_sync(ip, timeout))
        .await
        .unwrap_or_else(|_| ScanResult::dead_arp(ip.to_string()))
}
