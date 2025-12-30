# Telemt - MTProxy on Rust + Tokio

**Telemt** is a fast, secure, and feature-rich server written in Rust
It fully implements the official Telegram proxy algo and adds many production-ready improvements such as connection pooling, replay protection, detailed statistics, masking from "prying" eyes

# GOTO
- [Features](#features)
- [Quick Start Guide](#quick-start-guide)
  - [Build](#build)
- [How to use?](#how-to-use)
  - [Systemd Method](#telemt-via-systemd)

## Features

- Full support for all official MTProto proxy modes:
  - Classic
  - Secure - with `dd` prefix
  - Fake TLS - with `ee` prefix + SNI fronting
- Replay attack protection
- Optional traffic masking: forward unrecognized connections to a real web server, e.g. GitHub 🤪
- Configurable keepalives + timeouts + IPv6 and "Fast Mode"
- Graceful shutdown on Ctrl+C
- Extensive logging via `trace` and `debug` with `RUST_LOG` method

## Quick Start Guide

### Build
```bash
# Cloning repo
git clone https://github.com/telemt/telemt 
# Changing Directory to telemt
cd telemt
# Starting Release Build
cargo build --release
# Allow execution
chmod +x ./target/release/telemt
# Lets go!
./target/release/telemt config.toml
```

## How to use?
### Telemt via Systemd
1. Place your config to /etc/telemt.toml
2. Create service on /etc/systemd/system/telemt.service
```bash
[Unit]
Description=Telemt
After=network.target

[Service]
Type=simple
WorkingDirectory=/bin
ExecStart=/bin/telemt /etc/telemt.toml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
3. In Shell type `systemctl start telemt` - it must start with zero exit-code
4. In Shell type `systemctl status telemt` - there you can reach info about current MTProxy status
5. In Shell type `systemctl enable telemt` - then telemt will start with system startup, after the network is up
