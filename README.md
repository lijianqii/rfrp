# rfrp

A reverse proxy tunnel tool written in Rust, enabling access to internal network services through a public server.

## How It Works

```
External User ──→ Public Server ──→ Internal Client ──→ Internal Service (SSH/HTTP/...)
```

The internal client actively connects to the public server to establish a tunnel. External traffic is forwarded through the tunnel to the internal target.

## Quick Start

### Build

```bash
cargo build --release
```

### Server

Create `server.json`:

```json
{
    "running_mode": "server",
    "server": {
        "server_ip": "0.0.0.0",
        "server_port": 11000,
        "auth_token": "your-secret-token"
    },
    "client_proxy": []
}
```

```bash
./target/release/rfrp --config server.json
```

### Client

Create `client.json`:

```json
{
    "running_mode": "client",
    "server": {
        "server_ip": "your-server-ip",
        "server_port": 11000,
        "auth_token": "your-secret-token"
    },
    "client_proxy": [
        {
            "name": "ssh",
            "bind_port": 22001,
            "proxy_ip": "127.0.0.1",
            "proxy_port": 22,
            "proxy_con_type": "tcp"
        }
    ]
}
```

```bash
./target/release/rfrp --config client.json
```

## Project Structure

| Crate | Description |
|-------|-------------|
| `rfrp` | Binary entry point |
| `rfrp-main` | CLI arguments, logging, orchestration |
| `rfrp-config` | Configuration parsing and validation |
| `rfrp-server` | Server core logic |
| `rfrp-client` | Client core logic |

## License

Apache-2.0
