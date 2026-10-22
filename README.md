# Veil

Stealth overlay network with custom domains, port-less L7 ingress, and anti-DPI obfuscated protocol in Rust.

## Features

- **Arbitrary Internal Domains**: Map any domain (e.g. `hui.hui.hui`, `vpss2.myhost`, `*.internal`) directly to your VPS services.
- **Port-less Routing**: Transparent L7 reverse proxy (`Host` / `SNI`). Access applications without specifying ports in the URL.
- **Zero Inbound Ports on Nodes**: VPS connects outbound to the network. Keep your firewall locked (`ufw default deny incoming`), no public ports required.
- **Reinforced Obfuscated Protocol**: Anti-DPI frame masking with blake3 Pre-Shared Key entropy and variable random padding, eliminating standard WireGuard fixed packet length signatures.
- **Embedded DNS**: Internal DNS server answering local domain queries and delegating external domains to upstream resolvers.

## Building

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
```

Run on Client:
```bash
sudo ./target/release/veil client --config veil-client.yaml
```

Now you can query your custom domain directly:
```bash
curl http://hui.hui.hui
```
The request is routed over the encrypted obfuscated tunnel to `127.0.0.1:3000` on your remote VPS.

## Tests

```bash
cargo test
```
