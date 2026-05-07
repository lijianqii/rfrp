# rfrp

一个用 Rust 写的反向代理隧道工具，让你能通过公网服务器访问内网服务。

## 工作原理

```
外部用户 ──→ 公网 Server ──→ 内网 Client ──→ 内网服务 (SSH/HTTP/...)
```

内网客户端主动连接公网服务端建立隧道，外部流量通过隧道转发到内网目标。

## 快速开始

### 编译

```bash
cargo build --release
```

### 服务端

创建 `server.json`：

```json
{
    "running_mode": "server",
    "server": {
        "bind_ip": "0.0.0.0",
        "bind_port": 11000,
        "auth_token": "your-secret-token",
        "proxies": [
            { "name": "ssh", "bind_port": 22001, "proxy_con_type": "tcp" }
        ]
    }
}
```

```bash
./target/release/rfrp --config server.json
```

### 客户端

创建 `client.json`：

```json
{
    "running_mode": "client",
    "client": {
        "server_ip": "你的服务器IP",
        "server_port": 11000,
        "auth_token": "your-secret-token",
        "proxies": [
            { "name": "ssh", "bind_port": 22001, "proxy_ip": "127.0.0.1", "proxy_port": 22, "proxy_con_type": "tcp" }
        ]
    }
}
```

```bash
./target/release/rfrp --config client.json
```

## 项目结构

| Crate | 说明 |
|-------|------|
| `rfrp` | 二进制入口 |
| `rfrp-main` | CLI 参数、日志、编排调度 |
| `rfrp-proto` | 协议帧定义 |
| `rfrp-config` | 配置解析 |
| `rfrp-server` | 服务端核心 |
| `rfrp-client` | 客户端核心 |

## License

Apache-2.0
