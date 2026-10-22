use crate::proto::Frame;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};

static SOCKS_STREAM_ID: AtomicU64 = AtomicU64::new(1_000_000);

pub struct Socks5Server {
    bind_addr: SocketAddr,
    to_control_tx: Arc<RwLock<Option<mpsc::UnboundedSender<Frame>>>>,
    active_streams: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>>,
}

impl Socks5Server {
    pub fn new(
        bind_addr: SocketAddr,
        to_control_tx: Arc<RwLock<Option<mpsc::UnboundedSender<Frame>>>>,
        active_streams: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>>,
    ) -> Self {
        Self {
            bind_addr,
            to_control_tx,
            active_streams,
        }
    }

    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        println!("Veil SOCKS5 proxy active on {}", self.bind_addr);

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => continue,
            };

            let ctrl_tx = self.to_control_tx.clone();
            let streams = self.active_streams.clone();

            tokio::spawn(async move {
                let _ = Self::handle_socks_client(stream, ctrl_tx, streams).await;
            });
        }
    }

    async fn handle_socks_client(
        mut stream: TcpStream,
        to_control_tx: Arc<RwLock<Option<mpsc::UnboundedSender<Frame>>>>,
        active_streams: Arc<RwLock<HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>>>,
    ) -> Result<()> {
        let mut ver = [0u8; 2];
        stream.read_exact(&mut ver).await?;
        if ver[0] != 0x05 {
            return Err(anyhow!("Unsupported SOCKS version: {}", ver[0]));
        }

        let nmethods = ver[1] as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;
        stream.write_all(&[0x05, 0x00]).await?;

        let mut req_header = [0u8; 4];
        stream.read_exact(&mut req_header).await?;
        if req_header[0] != 0x05 || req_header[1] != 0x01 {
            stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(anyhow!("Only SOCKS5 CONNECT is supported"));
        }

        let target_host = match req_header[3] {
            0x01 => {
                let mut ip_bytes = [0u8; 4];
                stream.read_exact(&mut ip_bytes).await?;
                Ipv4Addr::from(ip_bytes).to_string()
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut domain_buf = vec![0u8; len[0] as usize];
                stream.read_exact(&mut domain_buf).await?;
                String::from_utf8(domain_buf)?
            }
            0x04 => {
                let mut ip_bytes = [0u8; 16];
                stream.read_exact(&mut ip_bytes).await?;
                std::net::Ipv6Addr::from(ip_bytes).to_string()
            }
            other => {
                stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                return Err(anyhow!("Unsupported address type: {}", other));
            }
        };

        let mut port_bytes = [0u8; 2];
        stream.read_exact(&mut port_bytes).await?;
        let target_port = u16::from_be_bytes(port_bytes);

        let ctrl_tx = {
            let lock = to_control_tx.read().await;
            lock.clone()
        };

        if let Some(tx) = ctrl_tx {
            let stream_id = SOCKS_STREAM_ID.fetch_add(1, Ordering::SeqCst);
            let (mut s_read, mut s_write) = stream.into_split();
            let (tx_to_client, mut rx_to_client) = mpsc::unbounded_channel::<Vec<u8>>();

            active_streams.write().await.insert(stream_id, tx_to_client);

            s_write
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await?;

            tx.send(Frame::StreamOpen {
                stream_id,
                domain: target_host,
                target_port,
            })?;

            tokio::spawn(async move {
                while let Some(chunk) = rx_to_client.recv().await {
                    if s_write.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                let _ = s_write.shutdown().await;
            });

            let tx_cleanup = tx.clone();
            let streams_cleanup = active_streams.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match s_read.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            let _ = tx_cleanup.send(Frame::StreamData {
                                stream_id,
                                payload: buf[..n].to_vec(),
                            });
                        }
                        _ => break,
                    }
                }
                let _ = tx_cleanup.send(Frame::StreamClose { stream_id });
                streams_cleanup.write().await.remove(&stream_id);
            });
        } else {
            let mut remote = match TcpStream::connect((target_host.as_str(), target_port)).await {
                Ok(c) => c,
                Err(_) => {
                    stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                    return Err(anyhow!("Failed to connect to target"));
                }
            };

            stream.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
        }

        Ok(())
    }
}
