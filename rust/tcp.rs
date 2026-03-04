use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::{self, TransportChannelType, TransportProtocol};
use pnet_datalink as datalink;

use crate::results::ScanResult;

pub const DEFAULT_TCP_PORTS: &[u16] = &[80, 443, 22, 21, 25, 8080, 8443];

const TCP_HEADER_SIZE: usize = 20;

fn tcp_checksum_manual(src: Ipv4Addr, dst: Ipv4Addr, tcp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let src_bytes = src.octets();
    sum += ((src_bytes[0] as u32) << 8) | (src_bytes[1] as u32);
    sum += ((src_bytes[2] as u32) << 8) | (src_bytes[3] as u32);

    let dst_bytes = dst.octets();
    sum += ((dst_bytes[0] as u32) << 8) | (dst_bytes[1] as u32);
    sum += ((dst_bytes[2] as u32) << 8) | (dst_bytes[3] as u32);

    sum += 6u32; // TCP protocol number
    sum += tcp_data.len() as u32;

    let mut i = 0;
    while i + 1 < tcp_data.len() {
        sum += ((tcp_data[i] as u32) << 8) | (tcp_data[i + 1] as u32);
        i += 2;
    }
    if tcp_data.len() % 2 != 0 {
        sum += (tcp_data[tcp_data.len() - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

fn get_source_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket
        .connect(std::net::SocketAddr::from((target, 80)))
        .ok()?;
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V4(addr) => Some(*addr.ip()),
        _ => None,
    }
}

/// Find the network interface that routes to the given target IP.
fn find_interface_for_target(target: Ipv4Addr) -> Option<datalink::NetworkInterface> {
    let source_ip = get_source_ip(target)?;
    datalink::interfaces()
        .into_iter()
        .find(|iface| {
            iface.ips.iter().any(|net| match net {
                ipnetwork::IpNetwork::V4(v4net) => v4net.ip() == source_ip,
                _ => false,
            })
        })
}

fn tcp_syn_scan_sync(ip: Ipv4Addr, port: u16, timeout: Duration) -> ScanResult {
    let ip_str = ip.to_string();

    let source_ip = match get_source_ip(ip) {
        Some(ip) => ip,
        None => return ScanResult::dead_tcp(ip_str),
    };

    let src_port = 49152 + (rand::random::<u16>() % 16384);
    let seq_num = rand::random::<u32>();

    // Open transport channel for SENDING the SYN packet
    let (mut tx, _rx) = match transport::transport_channel(
        65536,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    ) {
        Ok(pair) => pair,
        Err(_) => return ScanResult::dead_tcp(ip_str),
    };

    // Open datalink channel for RECEIVING (BPF on macOS, bypasses kernel TCP stack)
    let iface = match find_interface_for_target(ip) {
        Some(i) => i,
        None => return ScanResult::dead_tcp(ip_str),
    };

    let config = datalink::Config {
        read_timeout: Some(timeout),
        ..Default::default()
    };

    let (_dl_tx, mut dl_rx) = match datalink::channel(&iface, config) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return ScanResult::dead_tcp(ip_str),
    };

    // Build the SYN packet
    let mut tcp_buf = [0u8; TCP_HEADER_SIZE];
    {
        let mut tcp_pkt = MutableTcpPacket::new(&mut tcp_buf).unwrap();
        tcp_pkt.set_source(src_port);
        tcp_pkt.set_destination(port);
        tcp_pkt.set_sequence(seq_num);
        tcp_pkt.set_flags(TcpFlags::SYN);
        tcp_pkt.set_window(64240);
        tcp_pkt.set_data_offset(5);
        tcp_pkt.set_checksum(tcp_checksum_manual(source_ip, ip, tcp_pkt.packet()));
    }

    let start = Instant::now();
    if tx
        .send_to(TcpPacket::new(&tcp_buf).unwrap(), std::net::IpAddr::V4(ip))
        .is_err()
    {
        return ScanResult::dead_tcp(ip_str);
    }

    // Listen on datalink layer -- parse Ethernet > IPv4 > TCP
    while start.elapsed() < timeout {
        match dl_rx.next() {
            Ok(frame) => {
                let eth = pnet::packet::ethernet::EthernetPacket::new(frame);
                let eth = match eth {
                    Some(e) => e,
                    None => continue,
                };

                if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
                    continue;
                }

                let ipv4 = match Ipv4Packet::new(eth.payload()) {
                    Some(p) => p,
                    None => continue,
                };

                if ipv4.get_source() != ip
                    || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
                {
                    continue;
                }

                let tcp = match TcpPacket::new(ipv4.payload()) {
                    Some(p) => p,
                    None => continue,
                };

                if tcp.get_destination() != src_port || tcp.get_source() != port {
                    continue;
                }

                let flags = tcp.get_flags();
                if (flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0)
                    || (flags & TcpFlags::RST != 0)
                {
                    return ScanResult::alive_tcp(
                        ip_str,
                        start.elapsed().as_secs_f64() * 1000.0,
                        port,
                    );
                }
            }
            Err(_) => break,
        }
    }

    ScanResult::dead_tcp(ip_str)
}

/// Scan a single host across multiple ports (stop on first alive).
pub async fn tcp_syn_scan_host(ip: Ipv4Addr, ports: Vec<u16>, timeout: Duration) -> ScanResult {
    let ip_str = ip.to_string();

    for port in ports {
        let result = tokio::task::spawn_blocking(move || tcp_syn_scan_sync(ip, port, timeout))
            .await
            .unwrap_or_else(|_| ScanResult::dead_tcp(ip.to_string()));

        if result.is_alive {
            return result;
        }
    }

    ScanResult::dead_tcp(ip_str)
}
