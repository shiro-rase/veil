#!/usr/bin/env bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    CONFIG_DIR="/etc/veil"
else
    INSTALL_DIR="$HOME/.local/bin"
    CONFIG_DIR="$HOME/.config/veil"
fi

mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    export PATH="$INSTALL_DIR:$PATH"
fi

if ! command -v git >/dev/null 2>&1; then
    echo -e "${BLUE}Installing git...${NC}"
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y -qq git
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y git
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm git
    fi
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo -e "${BLUE}Installing Rust & Cargo...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
fi

echo -e "${BLUE}Building Veil binary...${NC}"
BUILD_TMP=$(mktemp -d)
git clone --depth 1 https://github.com/shiro-rase/veil.git "$BUILD_TMP"
cd "$BUILD_TMP"
cargo build --release
cp target/release/veil "$INSTALL_DIR/veil"
chmod +x "$INSTALL_DIR/veil"
cd /
rm -rf "$BUILD_TMP"

echo -e "${GREEN}${BOLD}Veil binary successfully installed to $INSTALL_DIR/veil${NC}"

ROLE="$1"
if [ -z "$ROLE" ]; then
    echo ""
    echo -e "${BOLD}Select role for this machine:${NC}"
    echo "1) VPS Node (Host services with custom domains, 0 open ports)"
    echo "2) Client (Your PC / laptop to access Veil domains)"
    echo "3) Control Plane (Network coordinator)"
    read -rp "Enter choice [1-3]: " CHOICE

    case "$CHOICE" in
        1) ROLE="node" ;;
        2) ROLE="client" ;;
        3) ROLE="control" ;;
        *) ROLE="node" ;;
    esac
fi

case "$ROLE" in
    control)
        CONF_FILE="$CONFIG_DIR/veil-control.yaml"
        read -rp "Bind address [0.0.0.0:4242]: " BIND_ADDR
        BIND_ADDR=${BIND_ADDR:-0.0.0.0:4242}

        GEN_SECRET=$(veil genkey | grep "Network Secret Token:" | awk '{print $4}')
        read -rp "Network Secret (press Enter to use generated: $GEN_SECRET): " SECRET
        SECRET=${SECRET:-$GEN_SECRET}

        cat <<EOF > "$CONF_FILE"
bind_addr: $BIND_ADDR
network_secret: $SECRET
virtual_subnet: 10.42.0.0/24
EOF
        echo -e "${GREEN}Control configuration saved to $CONF_FILE${NC}"

        if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
            veil install -t control -c "$CONF_FILE"
            systemctl daemon-reload
            systemctl enable --now veil-control
            echo -e "${GREEN}${BOLD}Veil Control is now running as a systemd service!${NC}"
        else
            echo -e "Run manually with: ${BOLD}veil control --config $CONF_FILE${NC}"
        fi
        ;;

    node)
        CONF_FILE="$CONFIG_DIR/veil-node.yaml"
        read -rp "Node ID [vps-$(hostname)]: " NODE_ID
        NODE_ID=${NODE_ID:-vps-$(hostname)}

        read -rp "Control Server address (IP:4242): " CONTROL_ADDR
        read -rp "Network Secret: " SECRET

        read -rp "Internal domain name (e.g. hui.hui.hui): " DOMAIN
        DOMAIN=${DOMAIN:-hui.hui.hui}

        read -rp "Local service target (e.g. 127.0.0.1:3000): " TARGET
        TARGET=${TARGET:-127.0.0.1:3000}

        cat <<EOF > "$CONF_FILE"
node_id: $NODE_ID
network_secret: $SECRET
control_server: $CONTROL_ADDR
ingress_bind: 0.0.0.0:80
routes:
  - domain: $DOMAIN
    proxy_to: $TARGET
EOF
        echo -e "${GREEN}Node configuration saved to $CONF_FILE${NC}"

        if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
            veil install -t node -c "$CONF_FILE"
            systemctl daemon-reload
            systemctl enable --now veil-node
            echo -e "${GREEN}${BOLD}Veil Node is now connected and running as a systemd service!${NC}"
            echo -e "Domain ${BOLD}$DOMAIN${NC} is mapped to ${BOLD}$TARGET${NC}."
        else
            echo -e "Run manually with: ${BOLD}veil node --config $CONF_FILE${NC}"
        fi
        ;;

    client)
        CONF_FILE="$CONFIG_DIR/veil-client.yaml"
        read -rp "Client ID [laptop-$(hostname)]: " CLIENT_ID
        CLIENT_ID=${CLIENT_ID:-laptop-$(hostname)}

        read -rp "Control Server address (IP:4242): " CONTROL_ADDR
        read -rp "Network Secret: " SECRET

        cat <<EOF > "$CONF_FILE"
client_id: $CLIENT_ID
network_secret: $SECRET
control_server: $CONTROL_ADDR
dns_bind: 127.0.0.1:5353
upstream_dns: 1.1.1.1:53
local_http_bind: 127.0.0.1:80
socks5_bind: 127.0.0.1:1080
EOF
        echo -e "${GREEN}Client configuration saved to $CONF_FILE${NC}"

        if [ "$(id -u)" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
            veil install -t client -c "$CONF_FILE"
            systemctl daemon-reload
            systemctl enable --now veil-client
            echo -e "${GREEN}${BOLD}Veil Client is now running as a systemd service!${NC}"
        else
            echo -e "Run manually with: ${BOLD}sudo veil client --config $CONF_FILE${NC}"
        fi
        ;;
esac

echo -e "Run veil --help for available commands."
