# Veil

Stealth overlay network with custom domains, port-less L7 ingress, anti-DPI obfuscated protocol, SOCKS5 proxy, and internal TLS CA in Rust.

## Features

- **Arbitrary Internal Domains**: Map any domain (e.g. `hui.hui.hui`, `vpss2.myhost`, `*.internal`) directly to your VPS services.
- **Port-less Routing**: Transparent L7 reverse proxy (`Host` / `SNI`). Access applications without specifying ports in the URL.
- **Zero Inbound Ports on Nodes**: VPS connects outbound to the network. Keep your firewall locked (`ufw default deny incoming`), no public ports required.
- **Reinforced Obfuscated Protocol**: Anti-DPI frame masking with blake3 Pre-Shared Key entropy and variable random padding, eliminating standard WireGuard fixed packet length signatures.
- **Embedded DNS**: Internal DNS server answering local domain queries and delegating external domains to upstream resolvers.
- **RFC 1928 SOCKS5 Proxy**: Seamless routing for any tool (SSH, browsers, databases) to internal Veil domains and IPs.
- **Internal TLS CA**: Built-in Certificate Authority generator for issuing trusted HTTPS certificates for internal domains without browser warnings.
## One-Line Install

Run on any Linux machine (VPS, Client, or Control):

```bash
curl -fsSL https://raw.githubusercontent.com/shiro-rase/veil/main/install.sh | bash
```

The interactive script automatically:
1. Installs dependencies and builds the Veil binary to `/usr/local/bin/veil`
2. Configures your role (Node, Client, or Control)
3. Sets up internal domains and target local ports
4. Installs and starts the background `systemd` service

## Building from Source

```bash
cargo build --release
```

Binary will be available at `target/release/veil`.

## Quick Start

### 1. Generate Network Secret

```bash
./target/release/veil genkey
```

### 2. Start Control Plane

```bash
./target/release/veil control --bind 0.0.0.0:4242 --secret <YOUR_SECRET>
```

Or using a config file:
```bash
./target/release/veil init -t control -o veil-control.yaml
./target/release/veil control --config veil-control.yaml
```

### 3. Connect a VPS Node

Generate config:
```bash
./target/release/veil init -t node -o veil-node.yaml
```

Edit `veil-node.yaml`:
```yaml
node_id: vps-main
network_secret: <YOUR_SECRET>
control_server: <CONTROL_IP>:4242
ingress_bind: 0.0.0.0:80
routes:
  - domain: hui.hui.hui
    proxy_to: 127.0.0.1:3000
  - domain: vpss2.myhost
    proxy_to: 127.0.0.1:8080
```

Run on VPS:
```bash
./target/release/veil node --config veil-node.yaml
```

### 4. Connect Client (Your Laptop)

Generate config:
```bash
./target/release/veil init -t client -o veil-client.yaml
```

Edit `veil-client.yaml`:
```yaml
client_id: laptop-dev
network_secret: <YOUR_SECRET>
control_server: <CONTROL_IP>:4242
dns_bind: 127.0.0.1:5353
upstream_dns: 1.1.1.1:53
local_http_bind: 127.0.0.1:80
socks5_bind: 127.0.0.1:1080
```

Run on Client:
```bash
sudo ./target/release/veil client --config veil-client.yaml
```

### 5. Accessing Services

Via HTTP Interceptor:
```bash
curl http://hui.hui.hui
```

Via SOCKS5 Proxy:
```bash
curl --socks5-hostname 127.0.0.1:1080 http://hui.hui.hui
```

### 6. Internal TLS Certificates

Generate root CA and certificates for your domains:
```bash
./target/release/veil ca --out certs --domains hui.hui.hui vpss2.myhost
```

### 8. Runtime Route Management (No daemon restart)

```bash
veil route add newapp.hui 127.0.0.1:4000
veil route ls
veil route rm newapp.hui
```

### 9. Join Tokens & Enrollment

Generate an enrollment token on Control Plane:
```bash
veil token create --role node --ttl 3600 --auto-approve true
```

Join on a new VPS with a single command:
```bash
veil join <TOKEN> --control <CONTROL_IP>:4242
```

### 10. Access Control Lists (ACL)

Configure granular access in `veil-control.yaml`:
```yaml
acls:
  - client: "laptop-dev"
    allow: ["*"]
  - client: "guest-device"
    allow: ["public.vps", "*.hui.hui"]
```

## Tests

```bash
cargo test
```
