use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub ip: String,
    pub is_alive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Serialize)]
pub struct SweepSummary {
    pub total: usize,
    pub alive: usize,
    pub dead: usize,
}

#[derive(Debug, Serialize)]
pub struct SweepOutput {
    pub results: Vec<ScanResult>,
    pub summary: SweepSummary,
}

impl ScanResult {
    pub fn alive_icmp(ip: String, rtt_ms: f64) -> Self {
        Self {
            ip,
            is_alive: true,
            rtt_ms: Some(rtt_ms),
            method: None,
            mac_address: None,
            port: None,
        }
    }

    pub fn dead(ip: String) -> Self {
        Self {
            ip,
            is_alive: false,
            rtt_ms: None,
            method: None,
            mac_address: None,
            port: None,
        }
    }

    pub fn alive_arp(ip: String, rtt_ms: f64, mac: String) -> Self {
        Self {
            ip,
            is_alive: true,
            rtt_ms: Some(rtt_ms),
            method: Some("arp".into()),
            mac_address: Some(mac),
            port: None,
        }
    }

    pub fn dead_arp(ip: String) -> Self {
        Self {
            ip,
            is_alive: false,
            rtt_ms: None,
            method: Some("arp".into()),
            mac_address: None,
            port: None,
        }
    }

    pub fn alive_tcp(ip: String, rtt_ms: f64, port: u16) -> Self {
        Self {
            ip,
            is_alive: true,
            rtt_ms: Some(rtt_ms),
            method: Some("tcp_syn".into()),
            mac_address: None,
            port: Some(port),
        }
    }

    pub fn dead_tcp(ip: String) -> Self {
        Self {
            ip,
            is_alive: false,
            rtt_ms: None,
            method: Some("tcp_syn".into()),
            mac_address: None,
            port: None,
        }
    }

    pub fn format_human(&self) -> String {
        if self.is_alive {
            let rtt = self.rtt_ms.unwrap_or(0.0);
            let extra = if let Some(mac) = &self.mac_address {
                format!(" [MAC: {mac}]")
            } else if let Some(port) = self.port {
                format!(" [port {port}]")
            } else {
                String::new()
            };
            format!("{}: alive ({rtt:.2} ms){extra}", self.ip)
        } else {
            format!("{}: unreachable", self.ip)
        }
    }
}

pub fn build_sweep_output(results: &[ScanResult]) -> SweepOutput {
    let alive = results.iter().filter(|r| r.is_alive).count();
    SweepOutput {
        results: results.to_vec(),
        summary: SweepSummary {
            total: results.len(),
            alive,
            dead: results.len() - alive,
        },
    }
}
