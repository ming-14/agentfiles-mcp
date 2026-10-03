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
3. **HMAC-SHA256 签名**：防篡改 + 防重放（query string 在签名内）。签名**不承担授权**：
   它由客户端用共享密钥生成，只证明请求者身份；能读什么由服务端的 containment
   与 `AF_READ_DENY` 决定（见[文件传输](#文件传输transport)）。

签名规范：

```
canonical = "v1\n{timestamp}\n{nonce}\n{METHOD}\n{path}[?{query}]\n{sha256_hex(body)}"
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

认证失败按固定顺序报错：`missing_authorization` → `missing_signature_headers` →
`unknown_token` → 时间戳 / nonce / 签名。签名头的存在性检查排在 token 查询之前，
所以一个不带签名头的请求永远拿不到 `unknown_token`，无法据此枚举有效 token。

### 文件传输（transport）

工具响应**从不内联文件字节**——图片也不例外。`read` 到图片时返回下载描述符：

```json
{ "type": "download", "path": "/server/abs/path.png", "name": "path.png",
  "mime": "image/png", "size": 1234 }
```

MCP 客户端再用带签名的 `GET /v1/transport/download?path=<path>` 拉取原始字节
（query 在签名内，改 `path=` 会验签失败），落盘到本地 temp 目录后给模型返回：

```
Image read successfully
<本地绝对路径>
```

> **签名只证明"谁在请求"，不决定"能取什么"**。签名由客户端用共享密钥自己生成，
> 持有密钥的一方可以为任意 `path` 签名，所以防越权不靠签名，而是靠端点里逐请求
> 校验的两条服务端策略：containment（workspace + `AF_EXTERNAL_WHITELIST`）与
> `AF_READ_DENY`——与 `read` 工具完全一致，被 deny 的文件无法绕过工具处理器取到。

图片**不做缩放、不做转码**，只做结构校验（PNG IEND / JPEG SOI+EOI / GIF 终止符 /
WEBP RIFF 长度），损坏 → `Image could not be decoded: <resource>`，此时不会产生下载。
单文件传输上限 `AF_TRANSPORT_MAX`（默认 100MB）。

### 写前必读（version 回执）

write/edit 采用**严格模式**：写入必须发生在通过校验的那个文件句柄上，
不经过路径二次打开——检查与写入之间被替换的文件不可能收到数据。

```
"version": {
  "path": "/abs/canonical",
  "mtimeNs": <st_mtime_ns>, "size": <bytes>,
  "ino": <st_ino>, "dev": <st_dev>
}
```

- **read 文本成功**（含分页）→ 响应带 `version`，MCP 记入回执表；标记取自
  **读取句柄的 `fstat`（读之前）**，不是事后 stat 路径——读取到取标记之间被
  换掉的文件拿不到凭据
- **write/edit 成功** → 返回**新** `version`（关闭句柄前对该句柄 `fstat`），
  MCP 更新回执（连续修改无需重读）
- 图片 / 目录 / 读失败 → 不带 `version`（没有凭据）
- write/edit 请求由 MCP 自动附带 `expectedVersion`；服务端用 `fstat(句柄)` 比对
  `mtimeNs + size`，并在卷提供文件身份时比对 `ino/dev`（同尺寸、同 mtime 的替换
  也躲不掉）。身份由**卷**决定、不由请求方决定：标记省略 `ino/dev` 一律算不符，
  否则校验强度可以被调用方下调
- 同一路径的 write/edit 由进程内目标锁串行：并发写入要么排队，要么拿到
  `version_mismatch`，不会两边都成功而其中一个被静默覆盖
- edit 还会用**读取之前**取的基线 fstat 在解码后再校验一次（抓住读到一半被改）
- edit 的大小上限在**已校验的句柄**上判定（CAS 之后、读入内存之前，不再按路径
  二次 stat）：超过 `MAX_EDIT_BYTES`（2MiB）→ `edit_too_large`；文件与回执不符
  则先报 `version_mismatch`（更可操作）。返回的 `patch` 逐行截断到 2000 字符、
  总量超过 50KB 就截断并附省略说明
- 权限 / 目录 / 磁盘满等文件系统错误 → `unable_to_read` / `unable_to_write` /
  `unable_to_edit`，不会漏成 `internal`
- 无回执 → `version_missing`（`Read the file before editing it.`）
- 不符 → `version_mismatch`（`File changed since it was last read. ...`）
- 回执表在 MCP 进程内存（LRU 512），**不落盘**：重启即失效，fail-closed

write 的特例：文件不存在且无回执 → 直接创建（`O_EXCL`，父目录自动建）；
文件已存在且无回执 → 拒绝覆盖。

## 服务端

环境变量：

| 变量 | 必填 | 说明 |
|---|---|---|
| `AF_WORKSPACE` | ✔ | 允许访问的根目录 |
| `AF_TOKENS` | ✔ | JSON：`{"token": "secret"}` |
| `AF_ADDR` | | 监听地址，默认 `127.0.0.1:8443` |
| `AF_TLS_CERT` / `AF_TLS_KEY` | | PEM 证书/私钥（启用内置 TLS） |
| `AF_MAX_SKEW` | | 时间戳窗口秒数，默认 300 |
| `AF_EXTERNAL_WHITELIST` | | JSON 数组，workspace 之外允许访问的目录，默认 `[]`（全拒） |
| `AF_READ_DENY` | | JSON 数组，禁止**读取**的 wildcard，默认 `["*.env", "*.env.*"]` |
| `AF_WRITE_DENY` | | JSON 数组，禁止**写入/编辑**的 wildcard，默认 `["*.env", "*.env.*"]`（与读黑名单独立） |
| `AF_TRANSPORT_MAX` | | 单文件传输字节上限，默认 100MB |

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
GET  /v1/transport/download?path=<abs>   拉取文件字节（query 参与签名）
```

请求体必须是 JSON 对象，并按 `agentfiles_shared.schema` 的输入模型校验。
非 JSON、非对象、缺字段或字段越界一律返回 `error.code = invalid_input`
（`message` 会给出具体字段），而不是 500。

响应：

```json
{ "ok": true,  "result": { }, "modelText": "..." }
{ "ok": false, "error": { "code": "...", "message": "..." } }
```

`result` 用 `type` 判别（缺 `type` 即整文件内容）：

| `type` | 含义 |
|---|---|
| `text-page` | 分页文本：`content` / `offset` / `truncated` / `next` |
| `list-page` | 目录分页：`entries` / `truncated` / `next` |
| `download` | 图片等二进制，改走 `/v1/transport/download` 取字节 |
| （无） | 小文件全文：`uri` / `name` / `content` / `encoding` / `mime` |

认证失败返回 `401`，响应体形状相同；`error.code` 是稳定值
（`missing_authorization`、`unknown_token`、`bad_signature`…），客户端按它分流。

`/v1/transport/download` 的非 200 状态（响应体形状同上）：

| 状态 | 含义 |
|---|---|
| `400` | `path` 为空或不是绝对路径（`invalid_input`） |
| `403` | containment 逃逸（`path_escape`）或命中 `AF_READ_DENY`（`unable_to_read`） |
| `404` | 目标不存在或不是文件（`transport_unavailable`） |
| `413` | 超过 `AF_TRANSPORT_MAX`（`transport_too_large`） |

## 本地 MCP

环境变量：

| 变量 | 说明 |
|---|---|
| `AF_URL` | 服务端基址，如 `https://files.example.com` |
| `AF_TOKEN` / `AF_SECRET` | 该客户端的 token 与签名密钥 |
| `AF_TIMEOUT` | 请求超时秒数，默认 30 |
| `AF_TEMP_DIR` | 传输文件落地目录，默认 `<系统 temp>/agentfiles` |

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

工具参数的描述与取值约束直接取自 `agentfiles_shared.schema` 的输入模型，
MCP 输入 schema 与 REST 请求体校验是同一份定义，改一处两边同步生效。
工具失败呈现为 `Error executing tool <name>: [<code>] <message>`，方括号里的
`code` 与 REST 响应的 `error.code` 相同（FastMCP 只保留异常文本，故写进文本）。

## 开发

```bash
uv sync              # 安装三个 workspace 成员（editable）+ dev 依赖
uv run pytest -q     # 全量单测（symlink 用例在部分平台自动跳过）
```

没有 uv 也可以用 pip：

```bash
pip install -e packages/shared -e packages/server -e packages/mcp "mcp<2" \
    pytest pytest-asyncio respx
python -m pytest -q
```

依赖锁在 `uv.lock`（已提交）。默认索引是国内镜像，写在 `pyproject.toml` 的
`[[tool.uv.index]]`；换官方源删掉那三行重新 `uv lock` 即可。
`mcp` 钉在 `<2`：2.x 把 `mcp.server.fastmcp` 改名成了 `MCPServer`，迁移后可放开。

## 目录

```
packages/shared/agentfiles_shared/
  schema.py        工具输入/输出模型（含 Version 版本标记）
  auth.py          HMAC 签名构造与校验（canonical 含 query）
  nonce_cache.py   重放保护（内存 TTL 缓存）
  wildcard.py      V2 语义的通配符匹配（黑白名单复用）
  transport.py     下载描述符与传输常量
  errors.py        模型可见错误文案（单一来源）
packages/server/agentfiles_server/
  app.py           FastAPI 装配 + transport 路由
  middleware.py    认证链：bearer → 签名头 → token → 时间戳 → nonce → 签名 → 重放
  config.py        环境变量配置（白名单 / 读黑名单 / 写黑名单 / 传输上限）
  fslayer.py       路径解析 / 逃逸校验 / 外部白名单
  filemut.py       严格模式句柄读写 + version 校验 + 目标锁 + BOM
  readfs.py        read 引擎：嗅探、分页、目录列表、图片校验；文本回执在此取 fstat
  transport.py     签名下载端点（containment + read-deny + 大小校验）
  tools/           read write edit glob grep
packages/mcp/agentfiles_mcp/
  server.py        FastMCP 工具定义 + 回执记账
  receipts.py      version 回执表（LRU，进程内存）
  client.py        带签名的 HTTP 客户端（POST + 下载）
  transport.py     下载落盘（temp 目录、.part 原子改名）
  config.py        环境变量配置
tests/             单测 + 端到端
```
