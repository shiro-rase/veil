use crate::proto::{Frame, ObfuscatedCodec};
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

pub async fn run_expose_service(
    control_addr: &str,
    network_secret: &str,
    local_port: u16,
    domain: &str,
) -> Result<()> {
    let mut stream = TcpStream::connect(control_addr).await?;
    let codec = ObfuscatedCodec::new(network_secret.as_bytes());

    let node_id = format!("expose-{}", rand::random::<u32>());
    let register = Frame::RegisterNode {
        node_id: node_id.clone(),
        secret_token: network_secret.to_string(),
        domains: vec![domain.to_string()],
        virtual_ip: None,
    };
    stream.write_all(&codec.encode_frame(&register)?).await?;

    println!("Exposing 127.0.0.1:{} as http://{} on Veil mesh", local_port, domain);
    println!("Press Ctrl+C to stop exposing");

    let mut read_buf = BytesMut::with_capacity(65536);
    let mut streams: HashMap<u64, mpsc::UnboundedSender<Vec<u8>>> = HashMap::new();
    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<Frame>();

    loop {
        tokio::select! {
            res = stream.read_buf(&mut read_buf) => {
                let n = res?;
                if n == 0 {
                    break;
                }
                while let Some(frame) = codec.try_decode_frame(&mut read_buf)? {
                    match frame {
                        Frame::StreamOpen { stream_id, .. } => {
                            let (data_tx, mut data_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                            streams.insert(stream_id, data_tx);

                            let tx_clone = tx_out.clone();
                            tokio::spawn(async move {
                                if let Ok(local_conn) = TcpStream::connect(("127.0.0.1", local_port)).await {
                                    let (mut l_read, mut l_write) = local_conn.into_split();
                                    let mut buf = [0u8; 16384];

                                    tokio::spawn(async move {
                                        while let Some(chunk) = data_rx.recv().await {
                                            if l_write.write_all(&chunk).await.is_err() {
                                                break;
                                            }
                                        }
                                    });

                                    loop {
                                        match l_read.read(&mut buf).await {
                                            Ok(0) | Err(_) => break,
                                            Ok(n) => {
                                                let _ = tx_clone.send(Frame::StreamData {
                                                    stream_id,
                                                    payload: buf[..n].to_vec(),
                                                });
                                            }
                                        }
                                    }
                                }
                                let _ = tx_clone.send(Frame::StreamClose { stream_id });
                            });
                        }
                        Frame::StreamData { stream_id, payload } => {
                            if let Some(tx) = streams.get(&stream_id) {
                                let _ = tx.send(payload);
                            }
                        }
                        Frame::StreamClose { stream_id } => {
                            streams.remove(&stream_id);
                        }
                        _ => {}
                    }
                }
            }
            Some(outgoing) = rx_out.recv() => {
                stream.write_all(&codec.encode_frame(&outgoing)?).await?;
            }
        }
    }
    Ok(())
}

pub async fn run_file_share(
    control_addr: &str,
    network_secret: &str,
    dir_path: &str,
    domain: &str,
) -> Result<()> {
    let base_path = Arc::new(PathBuf::from(dir_path).canonicalize()?);
    if !base_path.is_dir() {
        return Err(anyhow!("Target path is not a directory"));
    }

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_port = listener.local_addr()?.port();
    let base_clone = base_path.clone();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let base = base_clone.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                if let Ok(n) = socket.read(&mut buf).await {
                    if n > 0 {
                        let req_str = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req_str.lines().next().unwrap_or("");
                        let parts: Vec<&str> = first_line.split_whitespace().collect();
                        let target_path = if parts.len() >= 2 { parts[1] } else { "/" };
                        let clean_path = target_path.trim_start_matches('/');
                        let full_path = base.join(clean_path);

                        if full_path.starts_with(&*base) && full_path.exists() {
                            if full_path.is_file() {
                                if let Ok(data) = fs::read(&full_path).await {
                                    let header = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                                        data.len()
                                    );
                                    let _ = socket.write_all(header.as_bytes()).await;
                                    let _ = socket.write_all(&data).await;
                                    return;
                                }
                            } else if full_path.is_dir() {
                                let mut html = format!("<html><body><h1>Directory: {}</h1><ul>", target_path);
                                if let Ok(mut entries) = fs::read_dir(&full_path).await {
                                    while let Ok(Some(entry)) = entries.next_entry().await {
                                        if let Ok(name) = entry.file_name().into_string() {
                                            html.push_str(&format!("<li><a href=\"{}/{}\">{}</a></li>", target_path.trim_end_matches('/'), name, name));
                                        }
                                    }
                                }
                                html.push_str("</ul></body></html>");
                                let header = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n",
                                    html.len()
                                );
                                let _ = socket.write_all(header.as_bytes()).await;
                                let _ = socket.write_all(html.as_bytes()).await;
                                return;
                            }
                        }
                    }
                }
                let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found";
                let _ = socket.write_all(not_found.as_bytes()).await;
            });
        }
    });

    run_expose_service(control_addr, network_secret, local_port, domain).await
}
