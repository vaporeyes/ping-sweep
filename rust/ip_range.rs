use std::net::Ipv4Addr;

use ipnetwork::Ipv4Network;

/// Parse an IP range specification into individual IP addresses.
///
/// Supports:
/// - Single IP: "192.168.1.1"
/// - CIDR notation: "192.168.1.0/24"
/// - Dash range: "192.168.1.1-192.168.1.10"
/// - Short dash range: "192.168.1.1-10"
pub fn parse_ip_range(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let input = input.trim();

    if input.contains('/') {
        return expand_cidr(input);
    }

    if input.contains('-') {
        return expand_dash_range(input);
    }

    // Single IP
    let addr: Ipv4Addr = input.parse().map_err(|_| format!("Invalid IP address: {input}"))?;
    Ok(vec![addr])
}

fn expand_cidr(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let network: Ipv4Network = cidr.parse().map_err(|_| format!("Invalid CIDR notation: {cidr}"))?;
    Ok(network.iter().collect())
}

fn expand_dash_range(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let parts: Vec<&str> = input.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid range format: {input}"));
    }

    let start_str = parts[0].trim();
    let end_str = parts[1].trim();

    let start: Ipv4Addr = start_str
        .parse()
        .map_err(|_| format!("Invalid start IP: {start_str}"))?;

    let end: Ipv4Addr = if let Ok(addr) = end_str.parse::<Ipv4Addr>() {
        addr
    } else {
        // Short form: "192.168.1.1-10"
        let last_octet: u8 = end_str
            .parse()
            .map_err(|_| format!("Invalid range end: {end_str}"))?;
        let octets = start.octets();
        Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet)
    };

    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);

    if start_u32 > end_u32 {
        return Err(format!("Start IP must be <= end IP: {start} > {end}"));
    }

    let mut addrs = Vec::with_capacity((end_u32 - start_u32 + 1) as usize);
    for ip_int in start_u32..=end_u32 {
        addrs.push(Ipv4Addr::from(ip_int));
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_ip() {
        let result = parse_ip_range("192.168.1.1").unwrap();
        assert_eq!(result, vec![Ipv4Addr::new(192, 168, 1, 1)]);
    }

    #[test]
    fn test_cidr() {
        let result = parse_ip_range("192.168.1.0/30").unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0], Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(result[3], Ipv4Addr::new(192, 168, 1, 3));
    }

    #[test]
    fn test_dash_range_full() {
        let result = parse_ip_range("192.168.1.1-192.168.1.5").unwrap();
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_dash_range_short() {
        let result = parse_ip_range("192.168.1.1-10").unwrap();
        assert_eq!(result.len(), 10);
        assert_eq!(result[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(result[9], Ipv4Addr::new(192, 168, 1, 10));
    }

    #[test]
    fn test_invalid_range() {
        assert!(parse_ip_range("192.168.1.10-1").is_err());
    }
}
