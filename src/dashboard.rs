use crate::proto::{Frame, NodeStatusItem, ObfuscatedCodec};
use anyhow::Result;
use bytes::BytesMut;
use serde_json::json;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct DashboardServer {
    bind_addr: String,
    control_addr: String,
    network_secret: String,
}

impl DashboardServer {
    pub fn new(bind_addr: impl Into<String>, control_addr: impl Into<String>, network_secret: impl Into<String>) -> Self {
        Self {
            bind_addr: bind_addr.into(),
            control_addr: control_addr.into(),
            network_secret: network_secret.into(),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = self.bind_addr.parse()?;
        let listener = TcpListener::bind(addr).await?;
        println!("Veil Web Dashboard active at http://{}", addr);

        let control_addr = self.control_addr.clone();
        let secret = self.network_secret.clone();

        loop {
            let (mut socket, _) = listener.accept().await?;
            let c_addr = control_addr.clone();
            let c_sec = secret.clone();

            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let n = match socket.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };

                let req = String::from_utf8_lossy(&buf[..n]);
                let first_line = req.lines().next().unwrap_or("");
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                if parts.len() < 2 {
                    return;
                }

                let method = parts[0];
                let path = parts[1];

                if method == "GET" && path == "/" {
                    let html = get_dashboard_html();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        html.len(),
                        html
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                } else if method == "GET" && path == "/api/status" {
                    let nodes = fetch_status(&c_addr, &c_sec).await.unwrap_or_default();
                    let body = json!({ "nodes": nodes }).to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = socket.write_all(resp.as_bytes()).await;
                } else {
                    let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = socket.write_all(not_found.as_bytes()).await;
                }
            });
        }
    }
}

async fn fetch_status(control_addr: &str, secret: &str) -> Result<Vec<NodeStatusItem>> {
    let connect_addr = if control_addr.starts_with("0.0.0.0:") {
        format!("127.0.0.1:{}", control_addr.trim_start_matches("0.0.0.0:"))
    } else {
        control_addr.to_string()
    };

    let connect_fut = async {
        let mut stream = TcpStream::connect(&connect_addr).await?;
        let codec = ObfuscatedCodec::new(secret.as_bytes());

        let reg = Frame::RegisterClient {
            client_id: format!("dash-{}", rand::random::<u32>()),
            secret_token: secret.to_string(),
        };
        stream.write_all(&codec.encode_frame(&reg)?).await?;

        let query = Frame::NodeStatusQuery;
        stream.write_all(&codec.encode_frame(&query)?).await?;

        let mut buf = BytesMut::with_capacity(32768);
        let mut tmp = [0u8; 8192];

        for _ in 0..10 {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            while let Some(frame) = codec.try_decode_frame(&mut buf)? {
                if let Frame::NodeStatusReply { nodes } = frame {
                    return Ok::<Vec<NodeStatusItem>, anyhow::Error>(nodes);
                }
            }
        }
        Ok(vec![])
    };

    match tokio::time::timeout(std::time::Duration::from_secs(2), connect_fut).await {
        Ok(res) => res,
        Err(_) => Ok(vec![]),
    }
}

fn get_dashboard_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Veil - Mesh Dashboard</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
body { background: #080c14; color: #d4e0f0; padding: 24px; }
header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1a2638; padding-bottom: 16px; margin-bottom: 24px; }
.logo { font-size: 22px; font-weight: bold; color: #00f0ff; letter-spacing: 2px; }
.badge { background: #00ff8822; color: #00ff88; border: 1px solid #00ff8866; padding: 4px 10px; border-radius: 12px; font-size: 12px; }
.grid { display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }
.card { background: #0f1726; border: 1px solid #1a2942; border-radius: 8px; padding: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }
.card h2 { font-size: 16px; color: #88a0c0; text-transform: uppercase; margin-bottom: 16px; letter-spacing: 1px; }
svg { width: 100%; height: 340px; background: #0b111c; border-radius: 6px; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { text-align: left; padding: 12px; border-bottom: 1px solid #162235; font-size: 13px; }
th { color: #5a759e; text-transform: uppercase; font-size: 11px; }
.node-id { font-weight: bold; color: #00f0ff; }
.ip-pill { background: #182844; color: #60a5fa; padding: 3px 8px; border-radius: 4px; font-family: monospace; }
.domains { color: #94a3b8; font-size: 12px; }
.stats { display: flex; gap: 16px; margin-bottom: 20px; }
.stat-box { flex: 1; background: #0b111c; border: 1px solid #162235; padding: 16px; border-radius: 6px; text-align: center; }
.stat-val { font-size: 26px; font-weight: bold; color: #00ff88; margin-top: 6px; }
.stat-lbl { font-size: 11px; color: #5a759e; text-transform: uppercase; }
.pulse-circle { animation: pulse 2s infinite ease-in-out; }
@keyframes pulse { 0% { r: 6px; opacity: 1; } 50% { r: 12px; opacity: 0.3; } 100% { r: 6px; opacity: 1; } }
</style>
</head>
<body>
<header>
  <div class="logo">VEIL - STEALTH OVERLAY</div>
  <div><span class="badge" id="mesh-status">MESH ONLINE</span></div>
</header>

<div class="stats">
  <div class="stat-box">
    <div class="stat-lbl">Active Nodes</div>
    <div class="stat-val" id="count-nodes">0</div>
  </div>
  <div class="stat-box">
    <div class="stat-lbl">Overlay Subnet</div>
    <div class="stat-val" style="color: #60a5fa;">10.42.0.0/24</div>
  </div>
  <div class="stat-box">
    <div class="stat-lbl">Transport Security</div>
    <div class="stat-val" style="color: #b537f2;">Poly1305 + Mask</div>
  </div>
</div>

<div class="grid">
  <div class="card">
    <h2>Live Mesh Topology</h2>
    <svg id="topo-svg"></svg>
  </div>
  <div class="card">
    <h2>Mesh Control Details</h2>
    <div style="font-size: 13px; line-height: 1.8; color: #94a3b8;">
      <div>Control Server: <span style="color: #00f0ff;">94.237.57.175:443</span></div>
      <div>Active Probing: <span style="color: #00ff88;">ShadowTLS Enabled</span></div>
      <div>Magic Drop P2P: <span style="color: #00ff88;">Ready</span></div>
      <div>WireGuard Gateway: <span style="color: #00ff88;">Active</span></div>
      <div style="margin-top: 16px;">
        <button onclick="refresh()" style="background: #00f0ff22; border: 1px solid #00f0ff; color: #00f0ff; padding: 8px 14px; border-radius: 4px; cursor: pointer; font-weight: bold;">Refresh Topology</button>
      </div>
    </div>
  </div>
</div>

<div class="card" style="margin-top: 24px;">
  <h2>Connected Nodes & Virtual Routes</h2>
  <table>
    <thead>
      <tr>
        <th>Node Identifier</th>
        <th>Virtual IP</th>
        <th>Domains</th>
        <th>Throughput (Rx/Tx)</th>
        <th>Direct P2P</th>
      </tr>
    </thead>
    <tbody id="nodes-table-body">
      <tr><td colspan="5" style="text-align: center; color: #5a759e;">Scanning mesh...</td></tr>
    </tbody>
  </table>
</div>

<script>
async function refresh() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    const nodes = data.nodes || [];
    document.getElementById('count-nodes').innerText = nodes.length;

    const tbody = document.getElementById('nodes-table-body');
    tbody.innerHTML = '';

    const svg = document.getElementById('topo-svg');
    svg.innerHTML = '';

    const cx = 350, cy = 170;
    const centerNode = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    centerNode.setAttribute('cx', cx);
    centerNode.setAttribute('cy', cy);
    centerNode.setAttribute('r', 12);
    centerNode.setAttribute('fill', '#00f0ff');
    svg.appendChild(centerNode);

    const centerLabel = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    centerLabel.setAttribute('x', cx);
    centerLabel.setAttribute('y', cy - 18);
    centerLabel.setAttribute('fill', '#00f0ff');
    centerLabel.setAttribute('font-size', '12');
    centerLabel.setAttribute('text-anchor', 'middle');
    centerLabel.textContent = 'Veil-Control';
    svg.appendChild(centerLabel);

    nodes.forEach((node, i) => {
      const angle = (i / nodes.length) * 2 * Math.PI;
      const r = 120;
      const nx = cx + r * Math.cos(angle);
      const ny = cy + r * Math.sin(angle);

      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', cx);
      line.setAttribute('y1', cy);
      line.setAttribute('x2', nx);
      line.setAttribute('y2', ny);
      line.setAttribute('stroke', '#00ff8888');
      line.setAttribute('stroke-width', '2');
      line.setAttribute('stroke-dasharray', '4');
      svg.appendChild(line);

      const pulse = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      pulse.setAttribute('cx', nx);
      pulse.setAttribute('cy', ny);
      pulse.setAttribute('r', 8);
      pulse.setAttribute('fill', '#00ff8844');
      pulse.setAttribute('class', 'pulse-circle');
      svg.appendChild(pulse);

      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', nx);
      circle.setAttribute('cy', ny);
      circle.setAttribute('r', 8);
      circle.setAttribute('fill', '#00ff88');
      svg.appendChild(circle);

      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('x', nx);
      text.setAttribute('y', ny + 20);
      text.setAttribute('fill', '#d4e0f0');
      text.setAttribute('font-size', '11');
      text.setAttribute('text-anchor', 'middle');
      text.textContent = node.node_id;
      svg.appendChild(text);

      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="node-id">${node.node_id}</td>
        <td><span class="ip-pill">${node.virtual_ip}</span></td>
        <td class="domains">${node.domains.join(', ')}</td>
        <td>${node.rx_bytes} B / ${node.tx_bytes} B</td>
        <td style="color: ${node.is_direct ? '#00ff88' : '#f59e0b'};">${node.is_direct ? 'DIRECT' : 'RELAY'}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Failed to load status', err);
  }
}

refresh();
setInterval(refresh, 2500);
</script>
</body>
</html>"#
}
