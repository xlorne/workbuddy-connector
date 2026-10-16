# 完整 OAuth 2.1 授权链路实现说明

> 回答「我改了授权模式让它提示需要 OAuth 授权，就能实现了吗？」
>
> **答：不够。** 仅让服务端返回 401 还差三样东西。本文记录完整实现，并已实测打通全链路。

---

## 一、为什么"只返回 401"不够

对照 WorkBuddy 官方排障文档给出的成功链路：

```
POST /mcp                                        -> 401
GET  /.well-known/oauth-protected-resource/mcp   -> 200
GET  /.well-known/oauth-authorization-server     -> 200
POST /oauth/register                             -> 201
GET  /oauth/authorize                            -> 302 登录页
POST /oauth/login                                -> 302 回调
POST /oauth/token                                -> 200
POST /mcp (Bearer Access Token)                  -> 200
```

对照本项目早期的实验，有两处关键差异：

| 项 | 早期实验（失败） | 正确做法 |
|---|---|---|
| 传输协议 | **SSE**（`/sse`） | **Streamable HTTP**（`/mcp`） |
| 元数据路径 | `/.well-known/oauth-protected-resource` | `/.well-known/oauth-protected-resource/mcp`（RFC 9728 §3.1 要求带资源路径后缀） |
| 授权服务器 | 无（只返回 401） | **必须有** register / authorize / token 端点 |
| 401 挑战 | 有 | 有（这个是对的） |

**结论：401 只是「入口」，后面还必须有真正的 OAuth 授权服务器。**

---

## 二、已实现的内容

### 1. 传输改为 Streamable HTTP

```yaml
spring:
  ai:
    mcp:
      server:
        protocol: STREAMABLE
        streamable-http:
          mcp-endpoint: /mcp
```

### 2. 401 挑战 + 元数据（RFC 9728 §3.1 路径）

```
HTTP/1.1 401
WWW-Authenticate: Bearer realm="workbuddy-connector",
                  resource_metadata="http://localhost:3100/.well-known/oauth-protected-resource/mcp"
```

元数据端点**同时支持带/不带后缀**两条路径，兼容不同客户端
（Claude Code 有只查无后缀路径的已知问题）。

### 3. 授权服务器

新增 `EmbeddedOAuthAuthorizationServer`（本地联调用）：

| 端点 | 作用 |
|---|---|
| `POST /oauth/register` | 动态客户端注册（RFC 7591），返回 `client_id` 并**回显 `redirect_uris`** |
| `GET /oauth/authorize` | 授权端点，返回登录页，支持 PKCE `S256` |
| `POST /oauth/login` | 校验账号密码，生成一次性授权码，302 回调（带 `code` + `state`） |
| `POST /oauth/token` | 校验 `code_verifier`（SHA256 比对 `code_challenge`），签发 access / refresh token |

安全细节已实现：授权码**一次性消费**、10 分钟有效期、
`redirect_uri` 与注册值**精确匹配**、`state` 原样回传。

### 4. JWT 签发与验签

- 签发：HMAC-SHA256，claims 含 `iss` / `sub` / `aud` / `exp` / `scope` 及演示用员工档案
- 验签：`NimbusJwtDecoder.withSecretKey`（embedded 模式）
- 生产环境改为对接企业 SSO（非对称密钥 + JWKS）

---

## 三、实测结果（8 步全通过）

运行 `python3 scripts/verify_oauth_flow.py`：

```
[1] POST /mcp（未带 token）        → 401 + WWW-Authenticate
[2] 发现受保护资源元数据            → 200，authorization_servers 已给出
[3] 发现授权服务器元数据            → 200，PKCE 支持 ['S256']
[4] POST /oauth/register           → 201，client_id 已颁发
[5] GET  /oauth/authorize          → 200，返回登录页 HTML
[6] POST /oauth/login (zhangsan)   → 302 回调，带 code + state（state 校验通过）
[7] POST /oauth/token (PKCE)       → 200，签发 JWT（内含 sub=zhangsan）
[8] POST /mcp (Bearer token)       → 200，服务端识别出：

    ┌─ 服务端识别到的人员档案 ─────────────────────────
    │ 登录人标识 : zhangsan
    │ 标识来源   : jwt.claim.sub
    │ 姓名       : 张三
    │ 租户       : example-corp
    │ claims验签 : True   ← 已通过 JWT 验签
    │ 邮箱      : zhangsan@example-corp.com
    │ 部门      : 平台研发部
    └──────────────────────────────────────────────────
```

**关键转变：服务端从「匿名」变成了「知道是谁」。**

---

## 四、如何使用

### 本地联调（内置授权服务器）

```yaml
workbuddy:
  oauth:
    challenge-enabled: true     # 开启资源服务器模式
    embedded: true              # 使用内置授权服务器
    resource: http://localhost:3100/mcp
    resource-path: /mcp
    demo-users:
      zhangsan: "123456"
      lisi: "123456"
```

`mcp.json`（**不配 headers**，用户 token 由 OAuth 流程注入）：

```json
{
  "mcpServers": {
    "workbuddy-connector": {
      "type": "streamableHttp",
      "url": "http://localhost:3100/mcp"
    }
  }
}
```

启动服务 → 重启 WorkBuddy（或重新信任连接器）→ 应弹出授权登录页 →
用 `zhangsan / 123456` 登录 → 调用 `whoami` 即可看到登录人。

### 生产环境（对接企业 SSO）

```yaml
workbuddy:
  oauth:
    challenge-enabled: true
    embedded: false                                    # 关闭内置授权服务器
    resource: https://mcp.your-company.com/mcp
    authorization-servers:
      - https://sso.your-company.com                   # 企业统一认证中心

spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://sso.your-company.com     # 验签企业签发的 token
```

此时你的 MCP 服务只做**资源服务器**（验证 + 解析身份），
签发与账号生命周期仍由企业 SSO 负责。

---

## 五、还需要注意的

1. **Streamable HTTP 的 `/mcp` 是同一个端点做 GET/POST/DELETE**，
   401 挑战要覆盖所有方法。
2. **metadata 建议双路径提供**（带/不带资源后缀），兼容客户端实现差异。
3. **`CallerIdentityResolver` 只应信任 `JwtAuthenticationToken`**。
   本项目修复过一个真实缺陷：过滤器写入 `UsernamePasswordAuthenticationToken` 时，
   `instanceof JwtAuthenticationToken` 判定失败，导致**验签通过但标记为未验签**。
4. **登录页面里的演示账号在生产必须删除**，并把 `embedded` 置为 `false`。
5. **OAuth 只解决「你是谁」，不解决「你能看什么」**。
   业务数据的按人过滤仍须在业务系统内完成，不能只靠 MCP 层。
