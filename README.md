# agentfiles-mcp

远程 Agent 文件工具：本地 MCP 服务器（stdio）+ 远程文件服务端（REST/JSON）。

```
Agent ──stdio/MCP──▶ 本地 agentfiles-mcp ──HTTPS+Token+HMAC──▶ 远程 agentfiles-server ──▶ 文件系统
```

## 架构

| 组件 | 位置 | 说明 |
|---|---|---|
| `packages/shared` | 双端共享 | I/O schema、HMAC 签名算法、模型可见错误文案 |
| `packages/server` | 远程机器 | FastAPI，执行 read/write/edit/glob/grep |
| `packages/mcp` | 本地机器 | FastMCP（stdio），把工具调用转成带签名的 HTTPS 请求 |

## 安全模型

1. **TLS**：传输加密（服务端直挂证书，或由反向代理终结）
2. **Bearer Token**：`AF_TOKENS` 配置 token → secret 映射，每次请求校验
3. **HMAC-SHA256 签名**：防篡改 + 防重放

签名规范：

```
canonical = "v1\n{timestamp}\n{nonce}\n{METHOD}\n{path}\n{sha256_hex(body)}"
signature = hex(hmac_sha256(secret, canonical))

Headers:
  Authorization: Bearer <token>
  X-Timestamp:   <unix 秒>              允许偏差 ±300s
  X-Nonce:       <8-128 位 hex>         在 ±300s 窗口内不可重复
  X-Signature:   <hex hmac-sha256>
```

`X-Nonce` / `X-Signature` 必须是十六进制字符：非 hex（含非 ASCII）在比对前即被拒，
不会进到 `hmac.compare_digest`。重放缓存的保留时长是 `2 × AF_MAX_SKEW`（默认 600s），
覆盖整个 ±skew 窗口，避免客户端时钟超前时 nonce 先于时间戳窗口过期。

## 服务端

环境变量：

| 变量 | 必填 | 说明 |
|---|---|---|
| `AF_WORKSPACE` | ✔ | 允许访问的根目录 |
| `AF_TOKENS` | ✔ | JSON：`{"token": "secret"}` |
| `AF_ADDR` | | 监听地址，默认 `127.0.0.1:8443` |
| `AF_TLS_CERT` / `AF_TLS_KEY` | | PEM 证书/私钥（启用内置 TLS） |
| `AF_MAX_SKEW` | | 时间戳窗口秒数，默认 300 |

启动：

```bash
export AF_WORKSPACE=/srv/workspace
export AF_TOKENS='{"my-token":"my-secret"}'
python -m agentfiles_server
```

### API

```
GET  /healthz                        探活（免签名）
POST /v1/read    {path, offset?, limit?}
POST /v1/write   {path, content}
POST /v1/edit    {path, oldString, newString, replaceAll?}
POST /v1/glob    {pattern, path?, limit?}
POST /v1/grep    {pattern, path?, include?, limit?}
```

请求体必须是 JSON 对象，并按 `agentfiles_shared.schema` 的输入模型校验。
非 JSON、非对象、缺字段或字段越界一律返回 `error.code = invalid_input`
（`message` 会给出具体字段），而不是 500。

响应：

```json
{ "ok": true,  "result": { }, "modelText": "..." }
{ "ok": false, "error": { "code": "...", "message": "..." } }
```

## 本地 MCP

环境变量：

| 变量 | 说明 |
|---|---|
| `AF_URL` | 服务端基址，如 `https://files.example.com` |
| `AF_TOKEN` / `AF_SECRET` | 该客户端的 token 与签名密钥 |
| `AF_TIMEOUT` | 请求超时秒数，默认 30 |

注册为 MCP 服务器（stdio 命令 `agentfiles-mcp`）：

```json
{
  "mcp": {
    "agentfiles": {
      "type": "local",
      "command": ["agentfiles-mcp"],
      "environment": {
        "AF_URL": "https://files.example.com",
        "AF_TOKEN": "<token>",
        "AF_SECRET": "<secret>"
      },
      "enabled": true
    }
  }
}
```

暴露的 MCP 工具：`read`、`write`、`edit`、`glob`、`grep`。

## 开发

```bash
pip install -e packages/shared
pip install --no-deps -e packages/server -e packages/mcp
pip install pytest pytest-asyncio respx

python -m pytest tests -q
```

## 目录

```
packages/shared/agentfiles_shared/
  schema.py        工具输入/输出模型
  auth.py          HMAC 签名构造与校验
  nonce_cache.py   重放保护（内存 TTL 缓存）
  errors.py        模型可见错误文案（单一来源）
packages/server/agentfiles_server/
  app.py           FastAPI 装配
  middleware.py    认证链：token → 时间戳 → nonce → 签名
  config.py        环境变量配置
  fslayer.py       路径解析 / 逃逸校验
  tools/           read write edit glob grep
packages/mcp/agentfiles_mcp/
  server.py        FastMCP 工具定义
  client.py        带签名的 HTTP 客户端
  config.py        环境变量配置
tests/             单测 + 端到端
```
