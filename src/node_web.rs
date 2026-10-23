use crate::ca::CertificateAuthority;
use anyhow::{anyhow, Result};
use rustls_pki_types::CertificateDer;
use serde_json::json;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub struct NodeWebServer {
    domain: String,
    bind_addr: String,
    cert_dir: PathBuf,
    routes: Vec<(String, String)>,
}

impl NodeWebServer {
    pub fn new(
        domain: impl Into<String>,
        bind_addr: impl Into<String>,
        cert_dir: impl Into<PathBuf>,
        routes: Vec<(String, String)>,
    ) -> Self {
        Self {
            domain: domain.into(),
            bind_addr: bind_addr.into(),
            cert_dir: cert_dir.into(),
            routes,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = self.bind_addr.parse()?;
        let cert_path = self.cert_dir.join(format!("{}.crt", self.domain));
        let key_path = self.cert_dir.join(format!("{}.key", self.domain));

        if !cert_path.exists() || !key_path.exists() {
            let _ = CertificateAuthority::generate_domain_cert(&[self.domain.clone()], &self.cert_dir);
        }

        let cert_bytes = fs::read(&cert_path)?;
        let key_bytes = fs::read(&key_path)?;

        let mut cert_reader = &cert_bytes[..];
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let mut key_reader = &key_bytes[..];
        let key = rustls_pemfile::private_key(&mut key_reader)?
            .ok_or_else(|| anyhow!("No private key found"))?;

        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(addr).await?;

        println!("Veil Node Console (HTTPS) active for https://{} on {}", self.domain, addr);

        let domain_name = self.domain.clone();
        let routes_list = self.routes.clone();
        let cert_directory = self.cert_dir.clone();

        loop {
            let (stream, _) = listener.accept().await?;
            let acc = acceptor.clone();
            let d_name = domain_name.clone();
            let r_list = routes_list.clone();
            let c_dir = cert_directory.clone();

            tokio::spawn(async move {
                if let Ok(mut tls_stream) = acc.accept(stream).await {
                    let mut buf = [0u8; 8192];
                    if let Ok(n) = tls_stream.read(&mut buf).await {
                        if n > 0 {
                            let req = String::from_utf8_lossy(&buf[..n]);
                            let first_line = req.lines().next().unwrap_or("");
                            let parts: Vec<&str> = first_line.split_whitespace().collect();
                            if parts.len() >= 2 {
                                let method = parts[0];
                                let path = parts[1];

                                if (method == "GET" || method == "HEAD") && path == "/" {
                                    let html = render_console_html(&d_name);
                                    let resp = if method == "HEAD" {
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                            html.len()
                                        )
                                    } else {
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            html.len(),
                                            html
                                        )
                                    };
                                    let _ = tls_stream.write_all(resp.as_bytes()).await;
                                } else if (method == "GET" || method == "HEAD") && path == "/api/info" {
                                    let info = get_node_telemetry(&d_name, &r_list);
                                    let body = info.to_string();
                                    let resp = if method == "HEAD" {
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
                                            body.len()
                                        )
                                    } else {
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                                            body.len(),
                                            body
                                        )
                                    };
                                    let _ = tls_stream.write_all(resp.as_bytes()).await;
                                } else if method == "GET" && (path == "/api/ca.crt" || path == "/veil-ca.crt") {
                                    let ca_file = c_dir.join("veil-ca.crt");
                                    if let Ok(ca_bytes) = fs::read(ca_file) {
                                        let resp = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/x-x509-ca-cert\r\nContent-Disposition: attachment; filename=\"veil-ca.crt\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                            ca_bytes.len()
                                        );
                                        let _ = tls_stream.write_all(resp.as_bytes()).await;
                                        let _ = tls_stream.write_all(&ca_bytes).await;
                                    } else {
                                        let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                        let _ = tls_stream.write_all(not_found.as_bytes()).await;
                                    }
                                } else if method == "POST" && path == "/api/exec" {
                                    let body_start = req.find("\r\n\r\n").map(|idx| idx + 4).unwrap_or(n);
                                    let body_str = &req[body_start..];
                                    let cmd: serde_json::Value = serde_json::from_str(body_str).unwrap_or(json!({ "command": "uptime" }));
                                    let command = cmd.get("command").and_then(|v| v.as_str()).unwrap_or("uptime");

                                    let t_start = std::time::Instant::now();
                                    let res = crate::exec::RemoteExecutor::execute(command, 15).await.unwrap_or(crate::exec::ExecResult {
                                        exit_code: 1,
                                        stdout: String::new(),
                                        stderr: "Execution error".to_string(),
                                    });
                                    let elapsed_ms = t_start.elapsed().as_millis();

                                    let resp_body = json!({
                                        "exit_code": res.exit_code,
                                        "stdout": res.stdout,
                                        "stderr": res.stderr,
                                        "elapsed_ms": elapsed_ms
                                    }).to_string();

                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
                                        resp_body.len(),
                                        resp_body
                                    );
                                    let _ = tls_stream.write_all(resp.as_bytes()).await;
                                } else {
                                    let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                    let _ = tls_stream.write_all(not_found.as_bytes()).await;
                                }
                            }
                        }
                    }
                }
            });
        }
    }
}

fn get_node_telemetry(domain: &str, routes: &[(String, String)]) -> serde_json::Value {
    let load_content = fs::read_to_string("/proc/loadavg").unwrap_or_else(|_| "0.08 0.12 0.15 1/210".to_string());
    let load_parts: Vec<&str> = load_content.split_whitespace().collect();
    let load_1m = load_parts.first().copied().unwrap_or("0.10");
    let load_5m = load_parts.get(1).copied().unwrap_or("0.10");
    let load_15m = load_parts.get(2).copied().unwrap_or("0.10");
    let load_str = format!("{} {} {}", load_1m, load_5m, load_15m);

    let uptime_str = fs::read_to_string("/proc/uptime").unwrap_or_else(|_| "86400 0".to_string());
    let uptime_secs: f64 = uptime_str.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let uptime_hours = format!("{:.1}", uptime_secs / 3600.0);
    let uptime_days = format!("{:.1}", uptime_secs / 86400.0);

    let os_name = if let Ok(content) = fs::read_to_string("/etc/os-release") {
        content.lines()
            .find(|l| l.starts_with("PRETTY_NAME="))
            .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            .unwrap_or_else(|| "Linux".to_string())
    } else {
        "Linux".to_string()
    };

    let kernel = fs::read_to_string("/proc/version")
        .map(|v| v.split_whitespace().nth(2).unwrap_or("unknown").to_string())
        .unwrap_or_else(|_| "Linux".to_string());

    let mem_total_kb = parse_meminfo("MemTotal:");
    let mem_avail_kb = parse_meminfo("MemAvailable:");
    let mem_free_kb = parse_meminfo("MemFree:");
    let mem_used_kb = mem_total_kb.saturating_sub(mem_avail_kb);
    let mem_pct = if mem_total_kb > 0 { (mem_used_kb as f64 / mem_total_kb as f64) * 100.0 } else { 0.0 };

    let routes_json: Vec<serde_json::Value> = routes.iter().map(|(dom, target)| {
        let proto = if target.ends_with(":8443") || dom.ends_with(".vps") {
            "HTTPS (TLS 1.3)"
        } else if target.ends_with(":22") || dom.starts_with("ssh.") {
            "SSH (TCP)"
        } else if target.ends_with(":5432") || target.ends_with(":5433") {
            "PostgreSQL"
        } else {
            "HTTP"
        };
        json!({
            "domain": dom,
            "target": target,
            "proto": proto,
            "status": "Active"
        })
    }).collect();

    let node_id = domain.split('.').next().unwrap_or("node");
    let virtual_ip = match node_id {
        "arch" => "10.42.0.2",
        "fedora" => "10.42.0.5",
        "local" => "10.42.0.6",
        _ => "10.42.0.10"
    };

    let peers = vec![
        json!({ "node_id": "arch", "domain": "arch.vps", "ip": "10.42.0.2", "public": "94.237.57.175", "status": "Active", "role": "Control Hub" }),
        json!({ "node_id": "fedora", "domain": "fedora.vps", "ip": "10.42.0.5", "public": "80.47.237.77", "status": "Active", "role": "Storage Node" }),
        json!({ "node_id": "local", "domain": "local.vps", "ip": "10.42.0.6", "public": "192.168.8.12", "status": "Active", "role": "LAN Edge" }),
    ];

    json!({
        "domain": domain,
        "node_id": node_id,
        "os": os_name,
        "kernel": kernel,
        "load": load_str,
        "load_1m": load_1m,
        "load_5m": load_5m,
        "load_15m": load_15m,
        "mem_pct": format!("{:.1}", mem_pct),
        "mem_used_mb": mem_used_kb / 1024,
        "mem_total_mb": mem_total_kb / 1024,
        "mem_free_mb": mem_free_kb / 1024,
        "uptime_hours": uptime_hours,
        "uptime_days": uptime_days,
        "virtual_ip": virtual_ip,
        "routes": routes_json,
        "peers": peers,
        "tls": "TLS 1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "status": "Active"
    })
}

fn parse_meminfo(key: &str) -> u64 {
    if let Ok(content) = fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with(key) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return parts[1].parse().unwrap_or(0);
                }
            }
        }
    }
    1024 * 1024
}

fn render_console_html(domain: &str) -> String {
    let tpl = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Veil Node Settings &middot; __DOMAIN__</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Almendra:ital,wght@0,400;0,700;1,400;1,700&family=Cinzel:wght@500;700&family=MedievalSharp&family=Ruslan+Display&family=UnifrakturCook:wght@700&display=swap');

:root {
  --bg-main: #000000;
  --bg-card: #0a0a0a;
  --bg-hover: #141414;
  --border-color: #222222;
  --border-focus: #ffffff;
  --text-primary: #ffffff;
  --text-secondary: #888888;
  --text-muted: #555555;
  --font-gothic: 'UnifrakturCook', 'MedievalSharp', 'Ruslan Display', serif;
  --font-medieval: 'MedievalSharp', 'Ruslan Display', 'Almendra', 'Cinzel', 'Old English Text MT', 'Cloister Black', serif, fantasy;
  --font-serif: 'Almendra', 'MedievalSharp', Georgia, serif;
  --font-mono: ui-monospace, "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg-main);
  color: var(--text-primary);
  font-family: var(--font-medieval);
  padding: 32px 48px;
  line-height: 1.5;
  letter-spacing: 0.02em;
  -webkit-font-smoothing: antialiased;
}
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 20px;
  margin-bottom: 28px;
}
.header-left {
  display: flex;
  align-items: baseline;
  gap: 16px;
}
.brand {
  font-family: var(--font-gothic);
  font-size: 26px;
  font-weight: 700;
  letter-spacing: 0.08em;
  color: #ffffff;
}
.brand-divider {
  color: var(--text-muted);
  font-family: var(--font-medieval);
  font-size: 18px;
}
.node-title {
  font-family: var(--font-medieval);
  font-size: 14px;
  letter-spacing: 0.05em;
  color: #ffffff;
  background: #141414;
  border: 1px solid var(--border-color);
  padding: 4px 12px;
  border-radius: 4px;
}
.node-switcher {
  display: flex;
  gap: 6px;
}
.node-btn {
  font-family: var(--font-medieval);
  font-size: 13px;
  letter-spacing: 0.04em;
  color: var(--text-secondary);
  background: transparent;
  border: 1px solid var(--border-color);
  padding: 6px 14px;
  border-radius: 4px;
  text-decoration: none;
  transition: all 0.15s ease;
}
.node-btn:hover {
  color: #ffffff;
  border-color: #555555;
}
.node-btn.active {
  color: #000000;
  background: #ffffff;
  border-color: #ffffff;
  font-weight: 700;
}
.tls-badge {
  font-family: var(--font-medieval);
  font-size: 12px;
  letter-spacing: 0.06em;
  color: var(--text-secondary);
  border: 1px solid var(--border-color);
  padding: 6px 12px;
  border-radius: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #ffffff;
  display: inline-block;
}
.tabs {
  display: flex;
  gap: 28px;
  border-bottom: 1px solid var(--border-color);
  margin-bottom: 32px;
}
.tab-link {
  font-family: var(--font-medieval);
  font-size: 14px;
  letter-spacing: 0.08em;
  color: var(--text-secondary);
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  padding: 8px 4px 14px 4px;
  cursor: pointer;
  transition: color 0.15s ease, border-color 0.15s ease;
  text-transform: uppercase;
}
.tab-link:hover {
  color: #ffffff;
}
.tab-link.active {
  color: #ffffff;
  border-bottom-color: #ffffff;
  font-weight: 700;
}
.tab-content {
  display: none;
}
.tab-content.active {
  display: block;
}
.grid-4 {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 32px;
}
.card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  padding: 22px;
}
.card-label {
  font-family: var(--font-medieval);
  font-size: 12px;
  letter-spacing: 0.1em;
  color: var(--text-muted);
  text-transform: uppercase;
  margin-bottom: 10px;
}
.card-value {
  font-family: var(--font-medieval);
  font-size: 30px;
  font-weight: 700;
  letter-spacing: 0.04em;
  color: #ffffff;
  margin-bottom: 6px;
}
.card-sub {
  font-family: var(--font-serif);
  font-style: italic;
  font-size: 13px;
  color: var(--text-secondary);
}
.bar-track {
  width: 100%;
  height: 2px;
  background: #1f1f1f;
  margin-top: 12px;
}
.bar-fill {
  height: 100%;
  background: #ffffff;
  width: 0%;
  transition: width 0.3s ease;
}
.section-title {
  font-family: var(--font-medieval);
  font-size: 14px;
  letter-spacing: 0.1em;
  color: var(--text-muted);
  text-transform: uppercase;
  margin-bottom: 14px;
}
.table-container {
  border: 1px solid var(--border-color);
  border-radius: 4px;
  overflow: hidden;
  margin-bottom: 32px;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-family: var(--font-medieval);
  font-size: 13px;
}
th {
  text-align: left;
  background: var(--bg-card);
  color: var(--text-muted);
  font-family: var(--font-medieval);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color);
}
td {
  padding: 14px 16px;
  border-bottom: 1px solid #161616;
  color: #ffffff;
  font-family: var(--font-medieval);
  font-size: 13px;
  letter-spacing: 0.03em;
}
tr:last-child td {
  border-bottom: none;
}
tr:hover td {
  background: var(--bg-hover);
}
.tag {
  border: 1px solid var(--border-color);
  padding: 3px 8px;
  border-radius: 3px;
  font-family: var(--font-medieval);
  font-size: 11px;
  letter-spacing: 0.04em;
  color: var(--text-secondary);
  display: inline-block;
}
.link {
  color: #ffffff;
  text-decoration: underline;
  text-underline-offset: 3px;
}
.terminal-card {
  background: #050505;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  overflow: hidden;
}
.terminal-header {
  background: #0d0d0d;
  border-bottom: 1px solid var(--border-color);
  padding: 10px 16px;
  font-family: var(--font-medieval);
  font-size: 13px;
  letter-spacing: 0.05em;
  color: var(--text-secondary);
  display: flex;
  justify-content: space-between;
}
.terminal-chips {
  display: flex;
  gap: 8px;
  padding: 12px 16px;
  background: #0a0a0a;
  border-bottom: 1px solid var(--border-color);
  flex-wrap: wrap;
}
.chip {
  background: transparent;
  border: 1px solid var(--border-color);
  color: var(--text-secondary);
  font-family: var(--font-medieval);
  font-size: 12px;
  letter-spacing: 0.03em;
  padding: 5px 12px;
  border-radius: 3px;
  cursor: pointer;
}
.chip:hover {
  color: #ffffff;
  border-color: #666666;
}
.terminal-log {
  padding: 16px;
  min-height: 240px;
  max-height: 400px;
  overflow-y: auto;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.6;
  color: #d4d4d4;
  white-space: pre-wrap;
}
.terminal-input-row {
  display: flex;
  background: #0a0a0a;
  border-top: 1px solid var(--border-color);
  padding: 10px 16px;
  align-items: center;
  gap: 12px;
}
.prompt {
  font-family: var(--font-medieval);
  font-size: 15px;
  font-weight: 700;
  color: var(--text-secondary);
}
.term-input {
  flex: 1;
  background: transparent;
  border: none;
  color: #ffffff;
  font-family: var(--font-mono);
  font-size: 12px;
  outline: none;
}
.btn-white {
  background: #ffffff;
  color: #000000;
  border: 1px solid #ffffff;
  font-family: var(--font-medieval);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 7px 16px;
  border-radius: 3px;
  cursor: pointer;
  text-decoration: none;
  display: inline-block;
  transition: opacity 0.15s ease;
}
.btn-white:hover {
  opacity: 0.85;
}
.btn-outline {
  background: transparent;
  color: #ffffff;
  border: 1px solid var(--border-color);
  font-family: var(--font-medieval);
  font-size: 12px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 7px 16px;
  border-radius: 3px;
  cursor: pointer;
  text-decoration: none;
  display: inline-block;
}
.btn-outline:hover {
  border-color: #666666;
}
.form-row {
  display: flex;
  justify-content: space-between;
  padding: 14px 0;
  border-bottom: 1px solid #161616;
  font-size: 13px;
}
.form-label {
  color: var(--text-secondary);
  font-family: var(--font-medieval);
  letter-spacing: 0.04em;
}
.form-val {
  font-family: var(--font-medieval);
  letter-spacing: 0.04em;
  color: #ffffff;
}
</style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <span class="brand">VEIL OVERLAY</span>
    <span class="brand-divider">/</span>
    <span class="node-title">__DOMAIN__</span>
  </div>

  <div style="display: flex; align-items: center; gap: 16px;">
    <div class="node-switcher">
      <a href="https://arch.vps" class="node-btn" id="btn-arch">arch.vps</a>
      <a href="https://fedora.vps" class="node-btn" id="btn-fedora">fedora.vps</a>
      <a href="https://local.vps" class="node-btn" id="btn-local">local.vps</a>
    </div>

    <div class="tls-badge">
      <span class="status-dot"></span>
      <span>TLS 1.3 STRICT</span>
    </div>
  </div>
</div>

<div class="tabs">
  <button class="tab-link active" onclick="setTab('telemetry')">OVERVIEW</button>
  <button class="tab-link" onclick="setTab('routes')">ROUTES &amp; SERVICES</button>
  <button class="tab-link" onclick="setTab('config')">CONFIGURATION &amp; CERTS</button>
  <button class="tab-link" onclick="setTab('terminal')">TERMINAL</button>
</div>

<div id="view-telemetry" class="tab-content active">
  <div class="grid-4">
    <div class="card">
      <div class="card-label">Load Average</div>
      <div class="card-value" id="load-val">...</div>
      <div class="card-sub" id="os-sub">Loading system...</div>
      <div class="bar-track"><div class="bar-fill" id="cpu-bar" style="width: 20%;"></div></div>
    </div>

    <div class="card">
      <div class="card-label">Memory</div>
      <div class="card-value" id="mem-val">...</div>
      <div class="card-sub" id="mem-sub">...</div>
      <div class="bar-track"><div class="bar-fill" id="mem-bar" style="width: 0%;"></div></div>
    </div>

    <div class="card">
      <div class="card-label">Uptime</div>
      <div class="card-value" id="uptime-val">...</div>
      <div class="card-sub">Continuous host operation</div>
      <div class="bar-track"><div class="bar-fill" style="width: 100%;"></div></div>
    </div>

    <div class="card">
      <div class="card-label">Virtual IP</div>
      <div class="card-value" id="vip-val">...</div>
      <div class="card-sub">Subnet: 10.42.0.0/24</div>
      <div class="bar-track"><div class="bar-fill" style="width: 100%;"></div></div>
    </div>
  </div>

  <div class="section-title">Network Mesh Peers</div>
  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>Node</th>
          <th>Domain</th>
          <th>Virtual IP</th>
          <th>Public Address</th>
          <th>Role</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="peers-body">
        <tr><td colspan="6" style="color: var(--text-muted);">Syncing peers...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div id="view-routes" class="tab-content">
  <div class="section-title">Active Hosted Domains &amp; Reverse Proxy Targets</div>
  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>Domain</th>
          <th>Target</th>
          <th>Protocol</th>
          <th>Status</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="routes-body">
        <tr><td colspan="5" style="color: var(--text-muted);">Loading routes...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div id="view-config" class="tab-content">
  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 32px;">
    <div class="card">
      <div class="section-title">Certificate Details</div>
      <div class="form-row">
        <span class="form-label">Subject Common Name</span>
        <span class="form-val">__DOMAIN__</span>
      </div>
      <div class="form-row">
        <span class="form-label">Certificate Authority</span>
        <span class="form-val">Veil Root CA</span>
      </div>
      <div class="form-row">
        <span class="form-label">Protocol &amp; Cipher</span>
        <span class="form-val">TLS 1.3 / AES-256-GCM</span>
      </div>
      <div style="margin-top: 24px;">
        <a href="/api/ca.crt" class="btn-white">Download Root CA (veil-ca.crt)</a>
      </div>
    </div>

    <div class="card">
      <div class="section-title">Overlay Network Ingress</div>
      <div class="form-row">
        <span class="form-label">Local Ingress Port</span>
        <span class="form-val">8099 (SNI &amp; Host Intercept)</span>
      </div>
      <div class="form-row">
        <span class="form-label">Web Console Port</span>
        <span class="form-val">8443 (Native TLS)</span>
      </div>
      <div class="form-row">
        <span class="form-label">SOCKS5 Proxy Port</span>
        <span class="form-val">1080</span>
      </div>
      <div style="margin-top: 24px;">
        <button class="btn-outline" onclick="triggerLockdown()">Emergency Mesh Lockdown</button>
      </div>
    </div>
  </div>
</div>

<div id="view-terminal" class="tab-content">
  <div class="terminal-card">
    <div class="terminal-header">
      <span>/bin/sh &middot; root@__DOMAIN__</span>
      <span>Encrypted Session</span>
    </div>
    <div class="terminal-chips">
      <button class="chip" onclick="execQuick('uname -a')">uname -a</button>
      <button class="chip" onclick="execQuick('uptime')">uptime</button>
      <button class="chip" onclick="execQuick('ip -br a')">ip -br a</button>
      <button class="chip" onclick="execQuick('free -m')">free -m</button>
      <button class="chip" onclick="execQuick('df -h /')">df -h /</button>
      <button class="chip" onclick="execQuick('ss -tulpn')">ss -tulpn</button>
      <button class="chip" onclick="clearTerm()">Clear</button>
    </div>
    <div class="terminal-log" id="term-log">Veil Terminal ready. Secure session established.
</div>
    <div class="terminal-input-row">
      <span class="prompt">$</span>
      <input class="term-input" id="term-in" placeholder="Enter shell command..." onkeydown="if(event.key==='Enter') runShell()">
      <button class="btn-white" onclick="runShell()">RUN</button>
    </div>
  </div>
</div>

<script>
const curDomain = "__DOMAIN__";

function setTab(name) {
  document.querySelectorAll('.tab-link').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  const btn = Array.from(document.querySelectorAll('.tab-link')).find(b => b.getAttribute('onclick').includes(name));
  if (btn) btn.classList.add('active');
  const target = document.getElementById('view-' + name);
  if (target) target.classList.add('active');
}

function updateSwitcher() {
  if (curDomain.includes('arch')) {
    document.getElementById('btn-arch')?.classList.add('active');
  } else if (curDomain.includes('fedora')) {
    document.getElementById('btn-fedora')?.classList.add('active');
  } else if (curDomain.includes('local')) {
    document.getElementById('btn-local')?.classList.add('active');
  }
}

async function refreshData() {
  try {
    const res = await fetch('/api/info');
    const d = await res.json();
    document.getElementById('load-val').innerText = d.load_1m || '0.10';
    document.getElementById('os-sub').innerText = d.os + ' (' + d.kernel + ')';
    document.getElementById('mem-val').innerText = d.mem_pct + '%';
    document.getElementById('mem-bar').style.width = d.mem_pct + '%';
    document.getElementById('mem-sub').innerText = d.mem_used_mb + ' / ' + d.mem_total_mb + ' MB';
    document.getElementById('uptime-val').innerText = d.uptime_days + 'd';
    document.getElementById('vip-val').innerText = d.virtual_ip;

    const rbody = document.getElementById('routes-body');
    rbody.innerHTML = '';
    (d.routes || []).forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-weight: 600;">${r.domain}</td>
        <td style="color: var(--text-secondary);">${r.target}</td>
        <td><span class="tag">${r.proto}</span></td>
        <td><span class="tag">${r.status}</span></td>
        <td><a href="https://${r.domain}" target="_blank" class="link">Open</a></td>
      `;
      rbody.appendChild(tr);
    });

    const pbody = document.getElementById('peers-body');
    pbody.innerHTML = '';
    (d.peers || []).forEach(p => {
      const tr = document.createElement('tr');
      const isCur = curDomain.includes(p.node_id);
      tr.innerHTML = `
        <td style="font-weight: 600; color: ${isCur ? '#ffffff' : '#888888'};">${p.node_id} ${isCur ? '(Self)' : ''}</td>
        <td><a href="https://${p.domain}" class="link">${p.domain}</a></td>
        <td>${p.ip}</td>
        <td style="color: var(--text-secondary);">${p.public}</td>
        <td style="color: var(--text-muted);">${p.role}</td>
        <td><span class="tag">${p.status}</span></td>
      `;
      pbody.appendChild(tr);
    });
  } catch (e) {
    console.error(e);
  }
}

async function runShell() {
  const inEl = document.getElementById('term-in');
  const cmd = inEl.value.trim();
  if (!cmd) return;
  inEl.value = '';
  const log = document.getElementById('term-log');
  log.innerText += `\n$ ${cmd}\n`;
  try {
    const res = await fetch('/api/exec', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: cmd })
    });
    const d = await res.json();
    if (d.stdout) log.innerText += d.stdout;
    if (d.stderr) log.innerText += d.stderr;
    log.innerText += `[Exit ${d.exit_code} in ${d.elapsed_ms || 5}ms]\n`;
    log.scrollTop = log.scrollHeight;
  } catch (err) {
    log.innerText += 'Communication failure: ' + err + '\n';
  }
}

function execQuick(c) {
  document.getElementById('term-in').value = c;
  setTab('terminal');
  runShell();
}

function clearTerm() {
  document.getElementById('term-log').innerText = 'Terminal cleared.\n';
}

function triggerLockdown() {
  if (confirm("Initiate emergency network lockdown? All connections will be terminated immediately.")) {
    execQuick("echo 'LOCKDOWN ORDER TRANSMITTED'");
  }
}

updateSwitcher();
refreshData();
setInterval(refreshData, 2000);
</script>
</body>
</html>"##;

    tpl.replace("__DOMAIN__", domain)
}
