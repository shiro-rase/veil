use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use veil::client::ClientAgent;
use veil::config::{ClientConfig, ControlConfig, NodeConfig, RouteConfig};
use veil::control::ControlServer;
use veil::node::NodeAgent;

#[tokio::test]
async fn test_end_to_end_veil_tunnel() {
    let dummy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = dummy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = dummy_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let body = "Hello from hidden VPS behind Veil!";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });

    let ctrl_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ctrl_addr = ctrl_listener.local_addr().unwrap();
    drop(ctrl_listener);

    let ctrl_cfg = ControlConfig {
        bind_addr: ctrl_addr.to_string(),
        network_secret: "secret-token-e2e".to_string(),
        virtual_subnet: "10.42.0.0/24".to_string(),
        acls: None,
        decoy_addr: None,
        web_addr: None,
    };
    let control = ControlServer::new(ctrl_cfg);
    tokio::spawn(async move {
        let _ = control.run().await;
    });

    sleep(Duration::from_millis(100)).await;

    let node_cfg = NodeConfig {
        node_id: "vps-test".to_string(),
        network_secret: "secret-token-e2e".to_string(),
        control_server: ctrl_addr.to_string(),
        ingress_bind: "127.0.0.1:0".to_string(),
        routes: vec![RouteConfig {
            domain: "hui.hui.hui".to_string(),
            proxy_to: backend_addr.to_string(),
        }],
        web_bind: None,
        web_domain: None,
        cert_dir: None,
    };
    let node = NodeAgent::new(node_cfg);
    tokio::spawn(async move {
        let _ = node.run().await;
    });

    sleep(Duration::from_millis(200)).await;

    let client_http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_http_addr: SocketAddr = client_http_listener.local_addr().unwrap();
    drop(client_http_listener);

    let client_cfg = ClientConfig {
        client_id: "client-test".to_string(),
        network_secret: "secret-token-e2e".to_string(),
        control_server: ctrl_addr.to_string(),
        dns_bind: "127.0.0.1:0".to_string(),
        upstream_dns: "1.1.1.1:53".to_string(),
        local_http_bind: client_http_addr.to_string(),
        socks5_bind: None,
        exit_node: None,
        tun_enabled: Some(false),
    };
    let client = ClientAgent::new(client_cfg).unwrap();
    tokio::spawn(async move {
        let _ = client.run().await;
    });

    sleep(Duration::from_millis(300)).await;

    let mut stream = TcpStream::connect(client_http_addr).await.unwrap();
    let req = b"GET / HTTP/1.1\r\nHost: hui.hui.hui\r\nConnection: close\r\n\r\n";
    stream.write_all(req).await.unwrap();

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let resp_str = String::from_utf8_lossy(&response);

    assert!(resp_str.contains("200 OK"));
    assert!(resp_str.contains("Hello from hidden VPS behind Veil!"));
}
