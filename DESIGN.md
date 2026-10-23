# Veil Node Console Design System

## Philosophy
Veil is a stealth overlay network built for security, high throughput, and zero-trust mesh routing. The interface reflects industrial cyber-engineering aesthetics:
- High information density without visual clutter
- Monospace-first data typography for exact alignment of IPs, ports, and telemetry
- Functional color signaling: Emerald (#00e676) for active mesh links, Tactical Amber (#f59e0b) for relays, Sky Blue (#38bdf8) for virtual overlay IPs
- Elimination of decorative AI-slop gradients and purples in favor of deep obsidian surfaces and crisp 1px borders

## Color Palette
- Void Base: `#0a0e14`
- Precision Surface: `#111722`
- Elevated Layer: `#172030`
- Border Subtle: `#1e293b`
- Border Active: `#283548`
- Signal Green: `#00e676`
- Tactical Amber: `#f59e0b`
- Tactical Red: `#ef4444`
- Sky Accent: `#38bdf8`

## Typography
- Primary Code & Telemetry: `ui-monospace, 'JetBrains Mono', 'SF Mono', Menlo, Consolas, monospace`
- Proportional UI Text: `-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`
- Micro-headers: 11px uppercase with `letter-spacing: 0.08em`

## Interactive Components
- Node Telemetry Gauges (CPU, RAM, Disk, Mesh RTT)
- Domain Route Mapping Table with toggle controls
- Live Interactive Command Terminal
- P2P Magic Dropzone
- Single-Packet Knock authorization toggle
