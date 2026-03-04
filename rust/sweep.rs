use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Semaphore};

use crate::arp;
use crate::ping;
use crate::results::ScanResult;
use crate::tcp;

/// Run ICMP sweep.
pub async fn icmp_sweep(
    ips: Vec<Ipv4Addr>,
    timeout: Duration,
    concurrency: usize,
) -> mpsc::Receiver<ScanResult> {
    let (tx, rx) = mpsc::channel(concurrency);
    let semaphore = Arc::new(Semaphore::new(concurrency));

    tokio::spawn(async move {
        let mut handles = Vec::with_capacity(ips.len());

        for ip in ips {
            let permit = semaphore.clone().acquire_owned().await;
            let tx = tx.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit;
                let result = ping::ping_host(ip, timeout).await;
                let _ = tx.send(result).await;
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.await;
        }
    });

    rx
}

/// Run ARP sweep.
pub async fn arp_sweep(
    ips: Vec<Ipv4Addr>,
    timeout: Duration,
    concurrency: usize,
) -> mpsc::Receiver<ScanResult> {
    let (tx, rx) = mpsc::channel(concurrency);
    let semaphore = Arc::new(Semaphore::new(concurrency));

    tokio::spawn(async move {
        let mut handles = Vec::with_capacity(ips.len());

        for ip in ips {
            let permit = semaphore.clone().acquire_owned().await;
            let tx = tx.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit;
                let result = arp::arp_scan_host(ip, timeout).await;
                let _ = tx.send(result).await;
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.await;
        }
    });

    rx
}

/// Run TCP SYN sweep.
pub async fn tcp_sweep(
    ips: Vec<Ipv4Addr>,
    ports: Vec<u16>,
    timeout: Duration,
    concurrency: usize,
) -> mpsc::Receiver<ScanResult> {
    let (tx, rx) = mpsc::channel(concurrency);
    let semaphore = Arc::new(Semaphore::new(concurrency));

    tokio::spawn(async move {
        let mut handles = Vec::with_capacity(ips.len());

        for ip in ips {
            let permit = semaphore.clone().acquire_owned().await;
            let tx = tx.clone();
            let ports = ports.clone();

            let handle = tokio::spawn(async move {
                let _permit = permit;
                let result = tcp::tcp_syn_scan_host(ip, ports, timeout).await;
                let _ = tx.send(result).await;
            });
            handles.push(handle);
        }

        for h in handles {
            let _ = h.await;
        }
    });

    rx
}
