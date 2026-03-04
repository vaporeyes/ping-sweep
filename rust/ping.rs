use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};

use crate::results::ScanResult;

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

fn build_icmp_packet(id: u16, seq: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 8];
    packet[0] = ICMP_ECHO_REQUEST; // type
    packet[1] = 0; // code
    // checksum at [2..4], fill after
    packet[4] = (id >> 8) as u8;
    packet[5] = (id & 0xff) as u8;
    packet[6] = (seq >> 8) as u8;
    packet[7] = (seq & 0xff) as u8;

    // Calculate checksum
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;

    packet
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < data.len() - 1 {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if data.len() % 2 != 0 {
        sum += (data[data.len() - 1] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Ping a single host using raw ICMP socket. Returns RTT in ms or None.
fn ping_host_sync(ip: Ipv4Addr, timeout: Duration, id: u16) -> io::Result<Option<f64>> {
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;

    let dest = SocketAddrV4::new(ip, 0);
    let packet = build_icmp_packet(id, 1);

    let start = Instant::now();
    socket.send_to(&packet, &dest.into())?;

    let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
    loop {
        match socket.recv(&mut buf) {
            Ok(n) if n >= 28 => {
                // Safety: recv initialized the first n bytes
                let data: Vec<u8> = buf[..n]
                    .iter()
                    .map(|b| unsafe { b.assume_init() })
                    .collect();

                // IP header is typically 20 bytes, ICMP starts at variable offset
                let icmp_offset = ((data[0] & 0x0f) as usize) * 4;
                if icmp_offset + 6 > n {
                    continue;
                }
                let icmp_type = data[icmp_offset];
                let reply_id =
                    ((data[icmp_offset + 4] as u16) << 8) | (data[icmp_offset + 5] as u16);

                if icmp_type == ICMP_ECHO_REPLY && reply_id == id {
                    let rtt = start.elapsed().as_secs_f64() * 1000.0;
                    return Ok(Some(rtt));
                }
                if start.elapsed() >= timeout {
                    return Ok(None);
                }
            }
            Ok(_) => {
                if start.elapsed() >= timeout {
                    return Ok(None);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Async wrapper around sync ICMP ping. Runs in tokio blocking thread pool.
pub async fn ping_host(ip: Ipv4Addr, timeout: Duration) -> ScanResult {
    let ip_str = ip.to_string();
    // Use process ID + lower bits of IP as identifier to reduce collisions
    let id = (std::process::id() as u16) ^ (u32::from(ip) as u16);

    match tokio::task::spawn_blocking(move || ping_host_sync(ip, timeout, id)).await {
        Ok(Ok(Some(rtt_ms))) => ScanResult::alive_icmp(ip_str, rtt_ms),
        _ => ScanResult::dead(ip_str),
    }
}
