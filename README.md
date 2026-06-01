### MTProxy-NodeJs

Node.js 版 MTProto Proxy，支持 Telegram 直连 DC 和 Middle Proxy 两种转发方式。

### 功能说明

* 支持 classic、secure、TLS secret，其中默认启用 TLS secret

* 支持自动生成 `tg://proxy` 分享链接

* 支持 Direct DC 模式和 Middle Proxy 模式

* 支持 IPv4 / IPv6 监听，直连模式会优先按服务器网络情况选择线路

### 文件说明

* `main.js`：主程序，包含 MTProto Proxy 服务、worker 管理、链接生成和统计页面

* `config.json`：配置文件，填写端口、用户密钥、TLS 域名、广告 tag

### 快速使用

1. 修改 `config.json`

2. 设置 `PORT`，或使用平台提供的 `PORT` / `SERVER_PORT`

3. 将 `USERS` 里的密钥改成自己的 32 位十六进制字符串

4. 执行：

```bash
node main.js
```

启动后控制台会输出 `tg://proxy` 链接。

### 配置说明

`PORT`：监听端口。平台通常会通过环境变量 `PORT` 或 `SERVER_PORT` 注入端口。

`USERS`：用户密钥表，格式为 `名称: 32位十六进制密钥`。

`MODES`：启用的 secret 类型，默认只启用 `tls`。

`TLS_DOMAIN`：TLS 模式使用的伪装域名，默认 `www.cloudflare.com`。

`AD_TAG`：从 `@MTProxybot` 获取的广告 tag。不使用广告时保持 32 个 `0`。


### 安全提醒

仓库中的默认密钥是占位值：

```text
0123456789abcdef0123456789abcdef
```

正式部署前请务必改成自己的随机 32 位十六进制密钥。
