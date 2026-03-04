mod arp;
mod ip_range;
mod ping;
mod results;
mod sweep;
mod tcp;

use std::fs;
use std::time::Duration;

use clap::Parser;

use results::{build_sweep_output, ScanResult};
use tcp::DEFAULT_TCP_PORTS;

#[derive(Parser)]
#[command(name = "ping-sweep")]
#[command(about = "Fast concurrent ping sweep utility for network discovery")]
struct Cli {
    /// IP range to sweep (e.g., 192.168.1.0/24, 192.168.1.1-100, or single IP)
    target: String,

    /// Scan method: icmp (default), arp (local network, fast), tcp (TCP SYN)
    #[arg(short, long, default_value = "icmp")]
    method: String,

    /// Timeout in seconds for each probe
    #[arg(short, long, default_value = "1.0")]
    timeout: f64,

    /// Maximum concurrent probes
    #[arg(short, long, default_value = "100")]
    concurrency: usize,

    /// Only show hosts that are alive
    #[arg(short, long)]
    alive_only: bool,

    /// Output results in JSON format
    #[arg(long)]
    json: bool,

    /// Export results to a JSON file
    #[arg(short, long)]
    output: Option<String>,

    /// Comma-separated ports for TCP SYN scan (default: 80,443,22,21,25,8080,8443)
    #[arg(long)]
    ports: Option<String>,
}

fn check_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn parse_ports(ports_str: &str) -> Result<Vec<u16>, String> {
    ports_str
        .split(',')
        .map(|p| {
            p.trim()
                .parse::<u16>()
                .map_err(|_| format!("Invalid port: {p}"))
        })
        .collect()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if !check_root() {
        eprintln!(
            "Error: {} scanning requires root privileges. Try running with sudo.",
            cli.method.to_uppercase()
        );
        std::process::exit(1);
    }

    let timeout = Duration::from_secs_f64(cli.timeout);

    let ips = match ip_range::parse_ip_range(&cli.target) {
        Ok(ips) => ips,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };

    let mut rx = match cli.method.as_str() {
        "icmp" => sweep::icmp_sweep(ips, timeout, cli.concurrency).await,
        "arp" => sweep::arp_sweep(ips, timeout, cli.concurrency).await,
        "tcp" => {
            let ports = match &cli.ports {
                Some(p) => match parse_ports(p) {
                    Ok(ports) => ports,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                },
                None => DEFAULT_TCP_PORTS.to_vec(),
            };
            sweep::tcp_sweep(ips, ports, timeout, cli.concurrency).await
        }
        other => {
            eprintln!("Error: Unknown method '{other}'. Use icmp, arp, or tcp.");
            std::process::exit(1);
        }
    };

    let mut all_results: Vec<ScanResult> = Vec::new();

    while let Some(result) = rx.recv().await {
        if cli.alive_only && !result.is_alive {
            continue;
        }

        if !cli.json {
            println!("{}", result.format_human());
        }
        all_results.push(result);
    }

    let alive_count = all_results.iter().filter(|r| r.is_alive).count();

    if cli.json {
        let output = build_sweep_output(&all_results);
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        println!("\nSweep complete: {}/{} hosts alive", alive_count, all_results.len());
    }

    if let Some(path) = &cli.output {
        let output = build_sweep_output(&all_results);
        let json = serde_json::to_string_pretty(&output).unwrap();
        if let Err(e) = fs::write(path, json) {
            eprintln!("Error writing to {path}: {e}");
        }
    }
}
