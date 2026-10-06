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
3. **HMAC-SHA256 签名**：防篡改 + 防重放（query string 在签名内）

```
canonical = "v1\n{timestamp}\n{nonce}\n{METHOD}\n{path}[?{query}]\n{sha256_hex(body)}"
signature = hex(hmac_sha256(secret, canonical))

Headers:
  Authorization: Bearer <token>
  X-Timestamp:   <unix 秒>              允许偏差 ±300s
  X-Nonce:       <8-128 位 hex>         在 ±300s 窗口内不可重复
  X-Signature:   <hex hmac-sha256>
```

**签名只证明「谁在请求」，不决定「能取什么」**——能读什么完全由服务端的
containment（workspace + `AF_EXTERNAL_WHITELIST`）与 `AF_READ_DENY` 决定。

### 打开即验证（open-then-verify）

路径字符串只用来「找到」文件，不作任何安全依据；所有裁决针对**实际打开的那个
文件句柄的内核真实路径**（Windows `GetFinalPathNameByHandleW`、Linux
`/proc/self/fd`、macOS `F_GETPATH`），后续所有 IO 只用这个已验证的 fd。

因此对模型而言，「workspace 外存在」「不存在」「被 deny」三种情况呈现**同一条**
`Unable to read <path>`（原因只进服务端日志），无法借错误差异测绘文件系统。
设备、socket、管道一律不服务；被 `AF_READ_DENY` 命中的文件在读、写、搜索、
下载四条路径上都取不到。

### workspace 与 cwd

- **workspace** = 服务端配置的 `AF_WORKSPACE`，固定不变的安全边界，只在服务端内部起作用
- **cwd** = 客户端用 `set_cwd` 申请、服务端验证后返回的目录，由客户端每请求附上，
  相对路径以它为基准。服务端不存任何会话状态

启动时 cwd 为空，相对路径一律 `cwd_not_set`；**五个文件工具一视同仁**，不存在
「悄悄回落到 workspace」这回事。cwd 存在 MCP 进程内存里、不落盘、不按会话隔离
——宿主通常一个会话起一个 stdio 子进程，多会话共用一个代理进程时请自行注意。

## 服务端

环境变量：

| 变量 | 必填 | 示例值 | 说明 |
|---|---|---|---|
| `AF_WORKSPACE` | ✔ | `/srv/workspace` | 允许访问的根目录 |
| `AF_TOKENS` | ✔ | `'{"my-token":"my-secret"}'` | JSON：`{"token": "secret"}`，token 与密钥都换成自己的 |
| `AF_ADDR` | | `127.0.0.1:8443` | 监听地址，默认 `127.0.0.1:8443`；改 `0.0.0.0:8443` 即对外暴露 |
| `AF_TLS_CERT` / `AF_TLS_KEY` | | `/etc/ssl/cert.pem`、`/etc/ssl/key.pem` | PEM 证书/私钥，两个都填才启用内置 TLS |
| `AF_MAX_SKEW` | | `300` | 时间戳窗口秒数，默认 300 |
| `AF_EXTERNAL_WHITELIST` | | `'["/srv/shared", "/mnt/datasets"]'` | workspace 之外允许访问的目录，默认 `[]`（全拒） |
| `AF_READ_DENY` | | `'["*.env", "*.env.*", "*.pem", "*.key"]'` | 禁止**读取**的 wildcard，默认 `["*.env", "*.env.*"]` |
| `AF_WRITE_DENY` | | `'["*.env", "*.env.*", "*.pem", "*.key"]'` | 禁止**写入/编辑**的 wildcard，默认同上（与读黑名单独立） |
| `AF_TRANSPORT_MAX` | | `104857600` | 单文件传输字节上限，默认 100MB |
| `AF_BODY_MAX` | | `8388608` | 单次请求体字节上限，默认 8MB（超限在鉴权之前返回 `413`） |
| `AF_RIPGREP_PATH` | | `/usr/bin/rg` | rg 可执行文件路径，默认在 PATH 上查找 |
| `AF_RG_TIMEOUT` | | `30` | 单次 ripgrep 运行的整体时间上限（秒），默认 30；必须 > 0 |

JSON 类的值（`AF_TOKENS`、`AF_READ_DENY`、`AF_EXTERNAL_WHITELIST`）整体用**单引号**
包住，否则双引号会被 shell 提前展开。PowerShell 同样用单引号：

```powershell
$env:AF_TOKENS = '{"my-token":"my-secret"}'
```

启动：

```bash
export AF_WORKSPACE=/srv/workspace
export AF_TOKENS='{"my-token":"my-secret"}'
python -m agentfiles_server
```

### API

```
GET  /healthz                        探活（免签名）
POST /v1/cwd          {path}         校验并返回 cwd 规范形（签名）
POST /v1/read    {path, cwd?, offset?, limit?}
POST /v1/write   {path, cwd?, content, expectedVersion?}
POST /v1/edit    {path, cwd?, oldString, newString, replaceAll?, expectedVersion?}
POST /v1/glob    {pattern, cwd?, path?, limit?}
POST /v1/grep    {pattern, cwd?, include?, path?, limit?}
GET  /v1/transport/download?path=<abs>   拉取文件字节（query 参与签名）
```

`cwd` 是**内部字段**（MCP 客户端附带，模型不可见）：相对路径的解析基准，
每请求校验。请求体必须是 JSON 对象，字段校验失败返回
`error.code = invalid_input`，而不是 500。

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

认证失败返回 `401`，`error.code` 是稳定值（`missing_authorization`、
`unknown_token`、`bad_signature`…）。`/v1/transport/download` 的非 200 状态：

| 状态 | 含义 |
|---|---|
| `400` | `path` 为空或不是绝对路径（`invalid_input`） |
| `403` | 命中 `AF_READ_DENY`（`unable_to_read`） |
| `404` | 不存在、不是文件、**或 containment 逃逸**——三者同一文案（`transport_unavailable`） |
| `413` | 超过 `AF_TRANSPORT_MAX`（`transport_too_large`） |

### 文件传输（transport）

工具响应**从不内联文件字节**——图片也不例外。`read` 到图片时返回下载描述符：

```json
{ "type": "download", "path": "/server/abs/path.png", "name": "path.png",
  "mime": "image/png", "size": 1234 }
```

客户端再用带签名的 `GET /v1/transport/download?path=<path>` 拉取字节，落盘到本地
temp 目录后给模型返回 `Image read successfully` + 本地绝对路径。图片不做缩放与
转码，只做结构校验，损坏则返回 `Image could not be decoded: <resource>`。

### 写前必读（version 回执）

- **read 文本成功** → 响应带 `version`，MCP 记入回执表；**write/edit 必须带凭据**，
  否则 `version_missing`（`Read the file before editing it.`）
- 凭据不符 → `version_mismatch`（`File changed since it was last read.`），fail-closed
- write/edit 成功返回**新** `version`，连续修改无需重读
- 写入发生在通过校验的那个文件句柄上，不经路径二次打开；同一目标的写入串行
- 文件不存在且无回执 → 直接创建；已存在且无回执 → 拒绝覆盖
- 回执表在 MCP 进程内存（LRU 512，键为 `(cwd, path)`），不落盘，重启即失效

### 搜索（glob / grep）

两者委托给本机的 **ripgrep**（`AF_RIPGREP_PATH`，默认 PATH 查找 `rg`）：

- `AF_READ_DENY` 的每个模式都会转成 `--glob=!pattern`，**读不到的文件在搜索结果里
  也不可见**
- 正向 glob 会覆盖 ignore 逻辑：`.gitignore` 与隐藏文件规则对 glob 不生效，
  grep 则带 `--hidden`。因此默认 deny 只挡 `*.env` 这一类，`.npmrc`、
  `.aws/credentials` 等点文件需要自己加进 `AF_READ_DENY`
- deny glob 写错会让 rg 直接退 2、所有搜索返回空，启动时会探测一遍并在 stderr 告警
- 退出码 `1` → 无结果；正则错误归并成 `Unable to grep for <pattern>`；
  超时 → `rg_timeout`（`AF_RG_TIMEOUT`）
- 行预览上限 2000 字符

### 其他约定

- **路径分隔符**：输入的 `\` 一律按 `/` 处理，`sub\hello.txt` 在 Linux 服务端同样能打开
- **非 UTF-8 文件名**：不可解码的字节在响应中渲染成 `U+FFFD`（与 ripgrep 的拼写
  一致），这类名字不可回用；文件内容本身不受影响

## 本地 MCP

环境变量：

| 变量 | 示例值 | 说明 |
|---|---|---|
| `AF_URL` | `https://files.example.com` | 服务端基址，必须 `http://` 或 `https://`；本机调试填 `http://127.0.0.1:8443` |
| `AF_TOKEN` | `my-token` | 必须与服务端 `AF_TOKENS` 的 key 一致 |
| `AF_SECRET` | `my-secret` | 必须与服务端 `AF_TOKENS` 的 value 一致 |
| `AF_TIMEOUT` | `30` | 请求超时秒数，默认 30 |
| `AF_TEMP_DIR` | `D:\temp\agentfiles` | 传输文件落地目录，默认 `<系统 temp>/agentfiles` |

注册为 MCP 服务器（stdio 命令 `agentfiles-mcp`）——`AF_TOKEN` / `AF_SECRET` 要和服务端
`AF_TOKENS` 里那一组完全对上：

```json
{
  "mcp": {
    "agentfiles": {
      "type": "local",
      "command": ["agentfiles-mcp"],
      "environment": {
        "AF_URL": "https://files.example.com",
        "AF_TOKEN": "my-token",
        "AF_SECRET": "my-secret"
      },
      "enabled": true
    }
  }
}
```

本机自测（服务端不起 TLS）时对应改成：

```json
"environment": {
  "AF_URL": "http://127.0.0.1:8443",
  "AF_TOKEN": "dev-token",
  "AF_SECRET": "2485651692f5230b0c6c76f630de593e9bf9883d2046915d"
}
```

stdout 是 JSON-RPC 通道，**stderr 是这个进程唯一能写日志的地方**——宿主必须抽干
stderr，否则管道写满后代理会表现为挂死。因此代理启动时把 `mcp` 与 `httpx` 两个
logger 提到 WARNING；排障时开回 INFO 即可看到完整请求日志。

暴露 7 个 MCP 工具。五个文件工具带 `remote_` 前缀，避免与宿主自带的同名本地工具
撞名：`remote_read`、`remote_write`、`remote_edit`、`remote_glob`、`remote_grep`。
另外两个是这套服务自身的概念：

- **`workspace`** — 显示本客户端当前的 cwd
- **`set_cwd(path)`** — 让服务端验证目录（存在、是目录、在 containment 内、未被
  deny 命中），存下返回的规范形；成功后相对路径才可用。失败不改变当前 cwd，
  且四种失败同一文案 `invalid_cwd`

工具参数的描述与约束取自 `agentfiles_shared.schema`，MCP 输入 schema 与 REST
请求体校验是同一份定义。工具失败呈现为 `Error executing tool <name>: [<code>] <message>`，
方括号里的 `code` 与 REST 的 `error.code` 相同。

## 开发

```bash
uv sync              # 安装三个 workspace 成员（editable）+ dev 依赖
uv run pytest -q     # 全量单测（平台相关用例自动跳过：symlink、跨盘符、root）
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
  auth.py          HMAC 签名构造与校验
  nonce_cache.py   重放保护
  wildcard.py      通配符匹配（黑白名单复用）
  transport.py     下载描述符与传输常量
  errors.py        模型可见错误文案（单一来源）
packages/server/agentfiles_server/
  app.py           FastAPI 装配 + transport 路由
  middleware.py    认证链
  config.py        环境变量配置
  fslayer.py       定位 + 句柄级裁决 + 创建 + 显示名净化
  handlepath.py    平台层：句柄真实路径
  filemut.py       严格模式句柄读写 + version 校验 + 目标锁
  readfs.py        read 引擎：嗅探、分页、目录列表、图片校验
  rg.py            ripgrep 适配
  transport.py     签名下载端点
  tools/           read write edit glob grep
packages/mcp/agentfiles_mcp/
  server.py        FastMCP 工具定义 + 回执记账 + workspace/set_cwd
  cwd.py           每进程 cwd 状态
  receipts.py      version 回执表
  client.py        带签名的 HTTP 客户端
  transport.py     下载落盘
  config.py        环境变量配置
tests/             单测 + 端到端
```
