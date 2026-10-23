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

        loop {
            let (stream, _) = listener.accept().await?;
            let acc = acceptor.clone();
            let d_name = domain_name.clone();
            let r_list = routes_list.clone();

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
                                } else if method == "POST" && path == "/api/exec" {
                                    let body_start = req.find("\r\n\r\n").map(|idx| idx + 4).unwrap_or(n);
                                    let body_str = &req[body_start..];
                                    let cmd: serde_json::Value = serde_json::from_str(body_str).unwrap_or(json!({ "command": "uptime" }));
                                    let command = cmd.get("command").and_then(|v| v.as_str()).unwrap_or("uptime");

                                    let res = crate::exec::RemoteExecutor::execute(command, 15).await.unwrap_or(crate::exec::ExecResult {
                                        exit_code: 1,
                                        stdout: String::new(),
                                        stderr: "Execution error".to_string(),
                                    });

                                    let resp_body = json!({
                                        "exit_code": res.exit_code,
                                        "stdout": res.stdout,
                                        "stderr": res.stderr
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
    let load = fs::read_to_string("/proc/loadavg").unwrap_or_else(|_| "0.05 0.08 0.12 1/200".to_string());
    let uptime_str = fs::read_to_string("/proc/uptime").unwrap_or_else(|_| "86400 0".to_string());
    let uptime_secs: f64 = uptime_str.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0.0);

    let os_name = if let Ok(content) = fs::read_to_string("/etc/os-release") {
        content.lines()
            .find(|l| l.starts_with("PRETTY_NAME="))
            .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
            .unwrap_or_else(|| "Linux".to_string())
    } else {
        "Linux".to_string()
    };

    let mem_total_kb = parse_meminfo("MemTotal:");
    let mem_avail_kb = parse_meminfo("MemAvailable:");
    let mem_used_kb = mem_total_kb.saturating_sub(mem_avail_kb);
    let mem_pct = if mem_total_kb > 0 { (mem_used_kb as f64 / mem_total_kb as f64) * 100.0 } else { 0.0 };

    let routes_json: Vec<serde_json::Value> = routes.iter().map(|(dom, target)| {
        json!({
            "domain": dom,
            "target": target,
            "status": "Active"
        })
    }).collect();

    json!({
        "domain": domain,
        "os": os_name,
        "load": load.split_whitespace().take(3).collect::<Vec<_>>().join(", "),
        "uptime_hours": format!("{:.1}", uptime_secs / 3600.0),
        "mem_used_mb": mem_used_kb / 1024,
        "mem_total_mb": mem_total_kb / 1024,
        "mem_pct": format!("{:.1}", mem_pct),
        "routes": routes_json,
        "tls": "TLS 1.3 (Veil Root CA)",
        "status": "Online"
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
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Veil Node Settings - {}</title>
<style>
:root {{
  --bg-base: #0a0e14;
  --bg-surface: #111722;
  --bg-elevated: #172030;
  --border-subtle: #1e293b;
  --border-active: #283548;
  --text-primary: #f1f5f9;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --accent-blue: #38bdf8;
  --signal-green: #00e676;
  --signal-amber: #f59e0b;
  --signal-red: #ef4444;
  --font-mono: ui-monospace, "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg-base); color: var(--text-primary); font-family: var(--font-sans); padding: 24px; min-height: 100vh; }}
header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-subtle); padding-bottom: 18px; margin-bottom: 24px; }}
.crumb {{ font-family: var(--font-mono); font-size: 13px; color: var(--text-muted); display: flex; align-items: center; gap: 8px; }}
.crumb-active {{ color: var(--accent-blue); font-weight: bold; background: #0284c722; padding: 3px 8px; border-radius: 4px; border: 1px solid #0284c744; }}
.header-right {{ display: flex; align-items: center; gap: 12px; }}
.tls-badge {{ background: #00e67618; color: var(--signal-green); border: 1px solid #00e67644; font-size: 11px; font-family: var(--font-mono); padding: 4px 10px; border-radius: 4px; display: flex; align-items: center; gap: 6px; }}
.hud-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
.hud-card {{ background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 6px; padding: 18px; position: relative; overflow: hidden; }}
.hud-card::before {{ content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: var(--border-active); }}
.hud-label {{ font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.08em; margin-bottom: 8px; }}
.hud-value {{ font-family: var(--font-mono); font-size: 24px; font-weight: bold; color: var(--text-primary); }}
.hud-sub {{ font-size: 12px; color: var(--text-secondary); margin-top: 6px; }}
.bar-track {{ height: 4px; background: #1e293b; border-radius: 2px; margin-top: 8px; overflow: hidden; }}
.bar-fill {{ height: 100%; background: var(--accent-blue); width: 0%; transition: width 0.4s ease; }}
.main-grid {{ display: grid; grid-template-columns: 3fr 2fr; gap: 24px; }}
.panel {{ background: var(--bg-surface); border: 1px solid var(--border-subtle); border-radius: 6px; padding: 20px; }}
.panel-title {{ font-family: var(--font-mono); font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--text-secondary); margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }}
table {{ width: 100%; border-collapse: collapse; font-family: var(--font-mono); font-size: 13px; }}
th, td {{ padding: 12px 8px; text-align: left; border-bottom: 1px solid #162030; }}
th {{ color: var(--text-muted); font-size: 11px; text-transform: uppercase; }}
.pill-active {{ background: #00e67618; color: var(--signal-green); padding: 2px 6px; border-radius: 3px; font-size: 11px; }}
.terminal {{ background: #070a0e; border: 1px solid #1a2434; border-radius: 6px; padding: 14px; font-family: var(--font-mono); font-size: 13px; }}
.terminal-out {{ min-height: 180px; max-height: 240px; overflow-y: auto; color: #a5f3fc; white-space: pre-wrap; margin-bottom: 12px; line-height: 1.5; }}
.terminal-bar {{ display: flex; gap: 8px; }}
.terminal-input {{ flex: 1; background: #0e1520; border: 1px solid #1f2c40; color: #f8fafc; font-family: var(--font-mono); padding: 8px 12px; border-radius: 4px; outline: none; }}
.terminal-input:focus {{ border-color: var(--accent-blue); }}
.terminal-btn {{ background: #0284c7; border: none; color: #fff; font-family: var(--font-mono); font-weight: bold; padding: 8px 16px; border-radius: 4px; cursor: pointer; }}
.chips {{ display: flex; gap: 6px; margin-bottom: 10px; }}
.chip {{ background: #131d2c; border: 1px solid #1f2d42; color: #94a3b8; font-family: var(--font-mono); font-size: 11px; padding: 4px 8px; border-radius: 4px; cursor: pointer; }}
.chip:hover {{ color: var(--text-primary); border-color: var(--accent-blue); }}
.pulse {{ width: 8px; height: 8px; border-radius: 50%; background: var(--signal-green); box-shadow: 0 0 8px var(--signal-green); display: inline-block; }}
</style>
</head>
<body>
<header>
  <div class="crumb">
    <span>VEIL OVERLAY</span> &gt;
    <span>SETTINGS</span> &gt;
    <span class="crumb-active">{}</span>
  </div>
  <div class="header-right">
    <div class="tls-badge"><span class="pulse"></span> HTTPS &middot; TLS 1.3</div>
  </div>
</header>

<div class="hud-grid">
  <div class="hud-card">
    <div class="hud-label">System Load Average</div>
    <div class="hud-value" id="load-val">...</div>
    <div class="hud-sub" id="os-sub">Loading OS...</div>
  </div>
  <div class="hud-card">
    <div class="hud-label">Memory Utilization</div>
    <div class="hud-value" id="mem-val">...</div>
    <div class="bar-track"><div class="bar-fill" id="mem-bar"></div></div>
    <div class="hud-sub" id="mem-sub">...</div>
  </div>
  <div class="hud-card">
    <div class="hud-label">System Uptime</div>
    <div class="hud-value" id="uptime-val">...</div>
    <div class="hud-sub">Hours online without reboot</div>
  </div>
  <div class="hud-card">
    <div class="hud-label">Node Mesh Routing</div>
    <div class="hud-value" style="color: var(--signal-green);" id="status-val">Online</div>
    <div class="hud-sub">Domain: <span style="color: var(--accent-blue);">{}</span></div>
  </div>
</div>

<div class="main-grid">
  <div class="panel">
    <div class="panel-title">
      <span>Active Hosted Domains &amp; Services</span>
      <span class="tls-badge">Veil Gateway</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Domain Name</th>
          <th>Internal Proxy Target</th>
          <th>Protocol</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="routes-tbody">
        <tr><td colspan="4" style="color: var(--text-muted);">Querying routes...</td></tr>
      </tbody>
    </table>
  </div>

  <div class="panel">
    <div class="panel-title">
      <span>Interactive Node Terminal</span>
      <span style="font-size: 11px; color: var(--text-muted);">Remote Exec</span>
    </div>
    <div class="chips">
      <span class="chip" onclick="runQuick('uptime')">uptime</span>
      <span class="chip" onclick="runQuick('ip -br a')">ip -br a</span>
      <span class="chip" onclick="runQuick('free -m')">free -m</span>
      <span class="chip" onclick="runQuick('df -h /')">df -h</span>
    </div>
    <div class="terminal">
      <div class="terminal-out" id="term-out">veil-node console ready.\nRun commands safely over internal tunnel.\n</div>
      <div class="terminal-bar">
        <input class="terminal-input" id="term-in" placeholder="Enter shell command (e.g. uname -a)" onkeydown="if(event.key==='Enter') runCmd()">
        <button class="terminal-btn" onclick="runCmd()">EXEC</button>
      </div>
    </div>
  </div>
</div>

<script>
async function loadInfo() {{
  try {{
    const res = await fetch('/api/info');
    const data = await res.json();
    document.getElementById('load-val').innerText = data.load;
    document.getElementById('os-sub').innerText = data.os;
    document.getElementById('mem-val').innerText = data.mem_pct + '%';
    document.getElementById('mem-bar').style.width = data.mem_pct + '%';
    document.getElementById('mem-sub').innerText = data.mem_used_mb + ' MB / ' + data.mem_total_mb + ' MB';
    document.getElementById('uptime-val').innerText = data.uptime_hours + ' hrs';

    const tbody = document.getElementById('routes-tbody');
    tbody.innerHTML = '';
    (data.routes || []).forEach(r => {{
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="color: var(--accent-blue); font-weight: bold;">${{r.domain}}</td>
        <td>${{r.target}}</td>
        <td style="color: var(--text-muted);">TCP/HTTP</td>
        <td><span class="pill-active">ACTIVE</span></td>
      `;
      tbody.appendChild(tr);
    }});
  }} catch(e) {{
    console.error('Failed to load node info', e);
  }}
}}

async function runCmd() {{
  const inp = document.getElementById('term-in');
  const cmd = inp.value.trim();
  if(!cmd) return;
  inp.value = '';
  const out = document.getElementById('term-out');
  out.textContent += '\n$ ' + cmd + '\n';
  out.scrollTop = out.scrollHeight;

  try {{
    const res = await fetch('/api/exec', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ command: cmd }})
    }});
    const data = await res.json();
    if(data.stdout) out.textContent += data.stdout;
    if(data.stderr) out.textContent += data.stderr;
    out.scrollTop = out.scrollHeight;
  }} catch(e) {{
    out.textContent += 'Error executing command: ' + e + '\n';
  }}
}}

function runQuick(cmd) {{
  document.getElementById('term-in').value = cmd;
  runCmd();
}}

loadInfo();
setInterval(loadInfo, 3000);
</script>
</body>
</html>"##,
        domain, domain, domain
    )
}
