# WorkBuddy Connector

日程数据接入验证 MCP 服务（**Streamable HTTP + OAuth 2.1 身份透传**）。

这个服务的目的**不是业务**，而是回答一个具体问题：

> WorkBuddy 调用这个 MCP 服务时，到底传了什么参数？
> 尤其——企业统一认证的登录人标识，服务端能拿到吗？

因此服务内置了**全链路抓包**和**身份解析探针**，并实现了一套完整的
**OAuth 2.1 资源服务器**，让「识别到具体的人」这件事可以直接跑通。

---

## 文档索引

| 文档 | 读者 | 内容 |
|---|---|---|
| **[对接说明手册](docs/对接说明手册.md)** | 接入方、运维 | 如何接入、如何验证身份、FAQ 排查、上线清单 |
| **[技术开发说明](docs/技术开发说明.md)** | 开发者 | 架构设计、组件原理、决策权衡、扩展指南、踩坑记录 |
| [OAuth 授权链路实现说明](docs/OAuth授权链路实现说明.md) | 开发者 | 完整 OAuth 链路实现与 8 步验证 |
| [多用户身份识别方案](docs/多用户身份识别方案.md) | 架构 | 多用户场景方案对比 |
| [连接器授权机制](docs/连接器授权机制.md) | 架构 | 官方连接器 vs 自定义 MCP 的差异 |
| [多客户端身份认证对比](docs/多客户端身份认证对比.md) | 架构 | WorkBuddy / Claude / ChatGPT 横向对比 |

---

## 快速开始

```bash
# 构建
mvn clean package

# 启动（端口固定 3100）
java -jar target/workbuddy-connector-1.0.0.jar
# 或后台启动： ./scripts/start.sh -d

# 一键验证
python3 scripts/verify_oauth_flow.py   # OAuth 完整授权链路（8 步）
python3 scripts/verify_token_refresh.py # token 过期 → 401 → 静默续期
python3 scripts/verify_mcp.py          # MCP 协议握手 + 工具调用
```

在 WorkBuddy 的 MCP 配置中启用（`~/.workbuddy/mcp.json`）：

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


---

## 技术栈

| 组件 | 版本 | 说明 |
|---|---|---|
| Spring Boot | 3.5.15 | 基础框架 |
| Spring AI | 1.1.8 | MCP Server (SSE 传输) |
| MCP SDK | 0.18.3 | `io.modelcontextprotocol.sdk:mcp-spring-webmvc` |
| JDK | 17 | |

关键配置(`application.yml`):

```yaml
spring:
  ai:
    mcp:
      server:
        name: workbuddy-connector
        protocol: SSE
        sse-endpoint: /sse
        sse-message-endpoint: /mcp/message
```

---

## 核心能力

### 1. MCP 工具(WorkBuddy 可直接调用)

| 工具 | 作用 |
|---|---|
| `whoami` | **最常用**。返回服务端解析出的登录人标识、来源、展示名、租户、scope、全部 claims |
| `echo_call_context` | 回显本次调用的工具入参 + HTTP 方法/路径/全部请求头 |
| `list_captured_requests` | 列出最近捕获到的 HTTP 请求快照(握手 + 工具调用全过程) |
| `last_request_headers` | 查看最近一次请求的完整请求头与请求体全文(不截断) |
| `list_my_schedule` | 按服务端解析出的登录人隔离日程,并与客户端声称的身份做一致性校验 |
| `ping` | 最简健康检查(不触碰任何请求上下文,用于 A/B 对照排查) |

### 2. REST 观测端点(浏览器/curl 直接看)

```bash
curl http://localhost:3100/__capture/health              # 健康检查
curl http://localhost:3100/__capture/whoami              # 当前身份
curl "http://localhost:3100/__capture/requests?limit=20" # 最近请求列表
curl http://localhost:3100/__capture/requests/{id}       # 某次请求全文
curl -X DELETE http://localhost:3100/__capture/requests # 清空缓冲
```

---

## 身份解析策略(分层,可信度递减)

`CallerIdentityResolver` 按以下顺序判定登录人,并在 `userIdSource` 中**明确标注命中来源**:

| 优先级 | 来源 | `claimsVerified` | 说明 |
|---|---|---|---|
| 1 | Spring Security 已验签 JWT | `true` | 配置了 `issuer-uri` / `jwk-set-uri` 后启用 |
| 2 | 未验签 JWT(仅解码) | `false` | **仅供观测**,不可作为鉴权依据 |
| 3 | 身份 header | `false` | 网关注入,如 `X-WB-User-Id` |
| 4 | 无 | `false` | 匿名 |

登录人标识按 `workbuddy.identity.user-id-claims` 的顺序从 JWT claims 中匹配
(默认 `sub` → `user_name` → `preferred_username` → `userid` → `email` ...)。

身份 header 候选列表同样可配置,覆盖常见企业约定:

```yaml
workbuddy:
  identity:
    identity-headers:
      - x-wb-user-id
      - x-wb-corpuserid
      - x-wecom-userid
      - x-forwarded-user
      # ...
```

> **联调建议**:先用默认的宽候选列表跑一轮,从 `whoami` 返回的 `identityHeaders` 里
> 看企业实际用的是哪个字段,再把列表收敛到实际使用的头,避免线上误信任伪造头。

---

## 多用户场景:如何识别「当前访问人」

**结论:WorkBuddy 直连自定义 MCP(裸 `mcp.json`)时不会传递任何用户身份。**
多用户身份识别必须走「连接器(Connector)」渠道的 OAuth / Token 认证模式。

实测证据(WorkBuddy 5.8.2):

```
POST /mcp/message × 110, GET /sse × 78
携带 Authorization 的请求数 : 0
携带任何身份 header 的请求数 : 0
```

本服务已内置官方 MCP OAuth 2.1 资源服务器能力(`oauth/` 包),
配置 `workbuddy.oauth.challenge-enabled=true` 并指向企业统一认证中心即可启用。

**完整分析、官方机制说明与三种落地方案对比,见
[`docs/多用户身份识别方案.md`](docs/多用户身份识别方案.md)。**

---

## 接入企业真实认证中心

取消 `application.yml` 中注释并填入实际地址:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://your-company.com/oauth2
          jwk-set-uri: https://your-company.com/oauth2/jwks
```

配置后 `JwtDecoder` 自动生效,`whoami` 返回的 `claimsVerified` 会变为 `true`。

### 关于安全策略的说明

当前 `SecurityConfig` 采用**宽松策略**(全端点 `permitAll` + 自定义 `PermissiveJwtAuthenticationFilter`),
这是**刻意的联调设计**:

- 本地尚未拿到企业真实 JWT / JWKS 时,若强制鉴权会导致服务根本连不上,无法联调;
- 带了可验签 token → 写入 `JwtAuthenticationToken`,`whoami` 返回已认证身份;
- 带了无效 token → 不拦截,但身份解析退化为未验签,并**明确标注可信度**;
- 完全不带 token → 匿名,可用于确认"不带身份时服务端看到什么"。

**生产环境必须收紧**:把 `authorizeHttpRequests` 改为 `anyRequest().authenticated()`,
并按业务需要加 `@PreAuthorize` 做工具级权限控制。当前宽松模式不可直接上线。

---

## 踩坑记录(实测)

### 1. 端口被 IDE 环境变量劫持 ⚠️

WorkBuddy IDE 会向子进程注入 `SERVER__PORT`(其自身服务端口,如 50430)。
Spring Boot 的 relaxed binding 会把它映射为 `server.port`,而**环境变量优先级高于 `application.yml`**,
导致服务静默监听错误端口,客户端按 3100 配置自然连不上。

**解决**:启动类以「命令行参数」方式注入端口(命令行参数优先级高于环境变量),
同时保留 `--server.port=` 显式覆盖能力。见 `WorkbuddyConnectorApplication#withPortDefaults`。

### 2. SSE 长连接不能包 `ContentCachingRequestWrapper`

抓包过滤器最初在 `finally` 中记录请求。SSE 是长连接,`finally` 要等客户端断开才执行,
导致「握手请求迟迟抓不到」,联调时误判为没抓到包。

**解决**:改为**请求进入时立即记录**(此时请求头已完整),body 留待普通请求结束后补记;
并对 `Accept: text/event-stream` 的请求跳过 body 缓存包装,避免破坏流式输出。

### 3. SSE 长连接占用线程,需调大 Tomcat 线程池

一个 SSE 连接独占一个线程,客户端可能同时保持多个连接,
线程数不足会导致 `POST /mcp/message` 拿不到线程而无响应。已配置 `server.tomcat.threads.max: 200`。

### 4. MCP 协议必须先 `initialize`

跳过 `initialize` 直接调 `tools/list`,请求会在 `session.handle().block()` 处挂起,
表现为 POST 一直无响应。完整顺序:
`GET /sse` → `initialize` → `notifications/initialized` → 业务调用。

### 5. 类名不要与 Spring 内置 bean 冲突

自定义 `RequestContextFilter` 会与 Spring MVC 内置的 `requestContextFilter` bean 名冲突,
导致启动失败。本项目已改名为 `CallerContextFilter`。

---

## 目录结构

```
src/main/java/com/workbuddy/connector/
├── WorkbuddyConnectorApplication.java   # 启动类 + 端口保护
├── capture/
│   ├── CapturedRequest.java             # 请求快照模型
│   ├── RequestCaptureFilter.java        # 抓包过滤器(最高优先级)
│   └── RequestCaptureStore.java         # 环形缓冲存储
├── config/
│   ├── CaptureProperties.java           # 抓包配置
│   ├── IdentityProperties.java          # 身份候选配置
│   ├── SecurityConfig.java              # 宽松安全链
│   ├── PermissiveJwtAuthenticationFilter.java
│   └── ToolProviderConfig.java          # 工具注册
├── identity/
│   ├── CallerIdentity.java              # 身份解析结果
│   ├── CallerIdentityResolver.java      # 分层身份解析(核心)
│   └── CallerContextFilter.java         # 请求上下文绑定
├── tools/
│   ├── IdentityInspectorTools.java      # whoami / echo / 抓包查询
│   ├── ScheduleTools.java               # 日程示例
│   └── PingTools.java                   # 最小对照工具
└── web/CaptureController.java           # 观测 REST 端点

scripts/verify_mcp.py                    # 端到端验证脚本
```

---

## 验证结果示例

```
[2] MCP initialize 握手    → workbuddy-connector v1.0.0, 协议版本 2024-11-05
[4] tools/list            → 6 个工具
[5] whoami
      登录人标识  : wd_10086
      标识来源    : jwt.claim.sub
      展示名      : 李四
      租户        : t_8899
      claims 验签 : False   (本地无企业 JWKS → 未验签观测模式)
      身份头命中  : {'x-wb-user-id': 'lisi', 'x-wb-corpuserid': 'corp_lisi'}
```