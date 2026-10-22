use crate::ingress::IngressRouter;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcRequest {
    AddRoute { domain: String, target: String },
    RemoveRoute { domain: String },
    ListRoutes,
    ListPeers,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    Success { message: String },
    Routes { routes: Vec<(String, String)> },
    Peers { peers: Vec<String> },
    Error { error: String },
}

pub struct IpcServer;

impl IpcServer {
    pub async fn start(
        socket_path: PathBuf,
        router: IngressRouter,
        dynamic_route_tx: Option<mpsc::UnboundedSender<IpcRequest>>,
    ) -> Result<()> {
        let _ = fs::remove_file(&socket_path);
        if let Some(parent) = socket_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&socket_path)?;
        let router_arc = Arc::new(router);

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let r = router_arc.clone();
                let tx = dynamic_route_tx.clone();
                tokio::spawn(async move {
                    let _ = Self::handle_ipc_client(stream, r, tx).await;
                });
            }
        });

        Ok(())
    }

    async fn handle_ipc_client(
        stream: UnixStream,
        router: Arc<IngressRouter>,
        dynamic_route_tx: Option<mpsc::UnboundedSender<IpcRequest>>,
    ) -> Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        if buf_reader.read_line(&mut line).await? > 0 {
            let req: IpcRequest = serde_json::from_str(&line)?;
            let resp = match req {
                IpcRequest::AddRoute { domain, target } => {
                    router.add_route(domain.clone(), target.clone()).await;
                    if let Some(ref tx) = dynamic_route_tx {
                        let _ = tx.send(IpcRequest::AddRoute {
                            domain: domain.clone(),
                            target: target.clone(),
                        });
                    }
                    IpcResponse::Success {
                        message: format!("Route added: {} -> {}", domain, target),
                    }
                }
                IpcRequest::RemoveRoute { domain } => {
                    router.remove_route(&domain).await;
                    if let Some(ref tx) = dynamic_route_tx {
                        let _ = tx.send(IpcRequest::RemoveRoute {
                            domain: domain.clone(),
                        });
                    }
                    IpcResponse::Success {
                        message: format!("Route removed: {}", domain),
                    }
                }
                IpcRequest::ListRoutes => {
                    let routes = router.list_routes().await;
                    IpcResponse::Routes { routes }
                }
                IpcRequest::ListPeers => IpcResponse::Peers {
                    peers: vec!["Connected to Veil mesh".to_string()],
                },
            };

            let resp_bytes = serde_json::to_vec(&resp)?;
            writer.write_all(&resp_bytes).await?;
            writer.write_all(b"\n").await?;
        }
        Ok(())
    }
}

pub async fn send_ipc_command<P: AsRef<Path>>(
    socket_path: P,
    request: IpcRequest,
) -> Result<IpcResponse> {
    let mut stream = UnixStream::connect(socket_path.as_ref())
        .await
        .map_err(|e| anyhow!("Failed to connect to Veil daemon. Is Veil running? ({e})"))?;

    let req_bytes = serde_json::to_vec(&request)?;
    stream.write_all(&req_bytes).await?;
    stream.write_all(b"\n").await?;

    let mut buf_reader = BufReader::new(stream);
    let mut line = String::new();
    buf_reader.read_line(&mut line).await?;

    let resp: IpcResponse = serde_json::from_str(&line)?;
    Ok(resp)
}
