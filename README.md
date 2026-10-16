# WorkBuddy Connector

WorkBuddy MCP 服务参考实现：**Streamable HTTP + OAuth 2.1 用户身份识别**。

面向企业场景，解决一个核心问题：

> WorkBuddy 调用远程 MCP 服务时，服务端如何知道「当前访问人是谁」？

本服务给出可直接复用的答案：**作为 OAuth 2.1 资源服务器**，
由 WorkBuddy 内置 OAuth 管理器完成授权，服务端验签后即可拿到用户身份。

---

## 快速开始

```bash
mvn clean package
java -jar target/workbuddy-connector-1.0.0.jar      # 端口 3100
```

`~/.workbuddy/mcp.json`：

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

> `type` 必须是 `streamableHttp`；**不要配置 `headers`**，用户 token 由 OAuth 流程注入。
> 修改配置后需**重启 WorkBuddy** 才生效。

### 验证

```bash
python3 scripts/verify_oauth_flow.py      # OAuth 授权全链路（8 步）
python3 scripts/verify_token_refresh.py   # access_token 过期与静默续期（7 步）
python3 scripts/verify_refresh_expiry.py  # refresh_token 超期 → 需重新授权（6 步）
python3 scripts/verify_mcp.py             # MCP 协议握手与工具调用
```

> 两个续期脚本需服务端以秒级 TTL 启动，命令见脚本头部注释。

---

## 能力一览

| 能力 | 说明 |
|---|---|
| **OAuth 2.1 资源服务器** | 401 挑战 + RFC 9728/8414 发现端点，接入企业 SSO 即识别用户 |
| **内置授权服务器** | 联调用，含注册/授权/登录/令牌端点，可脱离企业 SSO 跑通全流程 |
| **7 个 MCP 工具** | `whoami`、`echo_call_context`、`list_my_schedule` 等 |
| **分层身份解析** | 已验签 JWT > 未验签解码 > 身份 header > 匿名，并标注可信度 |
| **全链路抓包** | 请求进入即记录，无须翻日志即可排查 |
| **令牌静默续期** | access_token 短期 + refresh_token 轮换续期 |

---

## 文档

| 文档 | 读者 | 内容 |
|---|---|---|
| [对接说明手册](docs/对接说明手册.md) | 接入方、运维 | 接入步骤、配置、工具清单、Token 生命周期、FAQ、上线清单 |
| [技术开发说明](docs/技术开发说明.md) | 开发者 | 架构设计、组件原理、扩展指南、验证与测试、生产化改造 |

---

## 目录结构

```
├── docs/                    文档
├── scripts/                 验证脚本与启动脚本
│   ├── verify_oauth_flow.py        OAuth 授权链路验证
│   ├── verify_token_refresh.py     access_token 过期与续期验证
│   ├── verify_refresh_expiry.py    refresh_token 超期验证
│   ├── verify_mcp.py               MCP 协议验证
│   └── start.sh                    启动脚本
└── src/main/java/com/workbuddy/connector/
    ├── config/              配置与安全（OAuth、验签、双模式安全链）
    ├── identity/            身份解析（核心）
    ├── oauth/               OAuth 2.1（发现端点、401 挑战、内置授权服务器）
    ├── tools/               MCP 工具
    ├── capture/             抓包
    └── web/                 观测 REST 端点
```
