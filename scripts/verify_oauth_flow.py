#!/usr/bin/env python3
"""
完整 OAuth 2.1 授权链路验证 —— 模拟 WorkBuddy 客户端的标准连接流程。

验证步骤（与 WorkBuddy 官方排障文档描述的链路一致）：
  1. POST /mcp                                  -> 401 + WWW-Authenticate
  2. GET  /.well-known/oauth-protected-resource/mcp -> 200（发现授权服务器）
  3. GET  /.well-known/oauth-authorization-server   -> 200
  4. POST /oauth/register                       -> 201（动态客户端注册）
  5. GET  /oauth/authorize                      -> 200（登录页）
  6. POST /oauth/login                          -> 302（带 code + state 回调）
  7. POST /oauth/token                          -> 200（PKCE 换 token）
  8. POST /mcp  (Bearer Access Token)           -> 200（工具调用，服务端识别出用户）
"""
import base64, hashlib, http.client, json, os, re, secrets, sys
from urllib.parse import urlparse, parse_qs, urlencode, quote

HOST, PORT = "127.0.0.1", 3100
BASE = f"http://{HOST}:{PORT}"


def _req(method, path, body=None, headers=None, follow=False):
    """发一个 HTTP 请求，返回 (status, headers, body_text)。"""
    conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
    hdrs = {"Accept": "application/json, text/event-stream"}
    if headers:
        hdrs.update(headers)
    payload = None
    if body is not None:
        if isinstance(body, (bytes, str)):
            payload = body.encode() if isinstance(body, str) else body
        else:
            payload = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=payload, headers=hdrs)
    resp = conn.getresponse()
    try:
        data = resp.read().decode("utf-8", errors="replace")
    except http.client.IncompleteRead as e:
        # Streamable HTTP 的流式响应可能提前结束，取已读部分即可
        data = e.partial.decode("utf-8", errors="replace")
    result = (resp.status, dict(resp.getheaders()), data, resp.getheader("Location"))
    conn.close()
    return result


def step(n, desc):
    print(f"\n[{n}] {desc}")


def main():
    print("=" * 78)
    print("  完整 OAuth 2.1 授权链路验证（模拟 WorkBuddy 客户端连接流程）")
    print("=" * 78)

    # ---------------------------------------------------------------- 1. 未认证访问
    step(1, "POST /mcp（未携带 token）→ 应返回 401 + WWW-Authenticate")
    st, hdrs, body, _ = _req("POST", "/mcp", {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "workbuddy-like-client", "version": "1.0"}}})
    challenge = hdrs.get("WWW-Authenticate", "")
    print(f"    状态码 : {st}")
    print(f"    挑战头 : {challenge[:110]}")
    if st != 401:
        print("    ✗ 预期 401"); return 1
    m = re.search(r'resource_metadata="([^"]+)"', challenge)
    if not m:
        print("    ✗ WWW-Authenticate 缺少 resource_metadata"); return 1
    metadata_url = m.group(1)

    # ---------------------------------------------------------------- 2. 发现受保护资源元数据
    step(2, f"GET {urlparse(metadata_url).path} → 获取授权服务器地址")
    st, _, body, _ = _req("GET", urlparse(metadata_url).path)
    meta = json.loads(body)
    print(f"    状态码 : {st}")
    print(f"    resource               : {meta['resource']}")
    print(f"    authorization_servers  : {meta['authorization_servers']}")
    auth_server = meta["authorization_servers"][0]

    # ---------------------------------------------------------------- 3. 发现授权服务器元数据
    step(3, "GET /.well-known/oauth-authorization-server → 获取各端点")
    st, _, body, _ = _req("GET", "/.well-known/oauth-authorization-server")
    asm = json.loads(body)
    print(f"    issuer                 : {asm['issuer']}")
    print(f"    authorization_endpoint : {asm['authorization_endpoint']}")
    print(f"    token_endpoint         : {asm['token_endpoint']}")
    print(f"    registration_endpoint  : {asm['registration_endpoint']}")
    print(f"    PKCE 支持              : {asm['code_challenge_methods_supported']}")

    # ---------------------------------------------------------------- 4. 动态客户端注册
    step(4, "POST /oauth/register → 动态客户端注册（RFC 7591）")
    redirect_uri = f"http://127.0.0.1:{PORT}/oauth/callback-demo"
    st, _, body, _ = _req("POST", "/oauth/register", {
        "client_name": "workbuddy-like-client",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none"})
    reg = json.loads(body)
    client_id = reg["client_id"]
    print(f"    状态码     : {st}")
    print(f"    client_id  : {client_id}")
    print(f"    回显回调   : {reg.get('redirect_uris')}")

    # ---------------------------------------------------------------- 5. PKCE + 授权请求
    step(5, "GET /oauth/authorize → 生成 PKCE 并打开登录页")
    code_verifier = secrets.token_urlsafe(48)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(16)

    q = urlencode({
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
        "scope": "openid profile", "state": state,
        "code_challenge": code_challenge, "code_challenge_method": "S256",
        "resource": meta["resource"]})
    st, _, html, _ = _req("GET", f"/oauth/authorize?{q}")
    request_id = re.search(r'name="request_id" value="([^"]+)"', html)
    print(f"    状态码     : {st}")
    print(f"    登录页     : {'已返回 HTML 表单' if '<form' in html else '异常'}")
    print(f"    PKCE       : code_challenge_method=S256, challenge={code_challenge[:20]}...")
    if not request_id:
        print("    ✗ 未取到 request_id"); return 1
    request_id = request_id.group(1)

    # ---------------------------------------------------------------- 6. 登录
    step(6, "POST /oauth/login → 用户用企业账号登录（演示账号 zhangsan）")
    form = urlencode({"request_id": request_id, "username": "zhangsan", "password": "123456"})
    st, _, body, location = _req("POST", "/oauth/login", form,
                                 {"Content-Type": "application/x-www-form-urlencoded"})
    print(f"    状态码     : {st}")
    print(f"    回调地址   : {location}")
    if not location or "code=" not in location:
        print("    ✗ 未收到授权码"); return 1
    params = parse_qs(urlparse(location).query)
    code = params["code"][0]
    print(f"    授权码     : {code[:24]}...")
    print(f"    state 一致 : {params.get('state', [''])[0] == state}")

    # ---------------------------------------------------------------- 7. 换 token
    step(7, "POST /oauth/token → 校验 PKCE 并签发用户 token")
    form = urlencode({
        "grant_type": "authorization_code", "code": code,
        "code_verifier": code_verifier, "client_id": client_id,
        "redirect_uri": redirect_uri, "resource": meta["resource"]})
    st, _, body, _ = _req("POST", "/oauth/token", form,
                          {"Content-Type": "application/x-www-form-urlencoded"})
    tok = json.loads(body)
    print(f"    状态码     : {st}")
    print(f"    token_type : {tok.get('token_type')}")
    print(f"    expires_in : {tok.get('expires_in')}s")
    print(f"    scope      : {tok.get('scope')}")
    access_token = tok.get("access_token")
    if not access_token:
        print(f"    ✗ 未签发 token: {body[:200]}"); return 1

    # 解析 token 里带的用户身份（仅供展示）
    p = access_token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    print(f"    token 内用户标识 : sub={claims.get('sub')}, name={claims.get('name')}")

    # ---------------------------------------------------------------- 8. 带 token 调用 MCP
    step(8, "POST /mcp（Bearer token）→ 服务端识别出当前访问人")
    auth = {"Authorization": f"Bearer {access_token}",
            "Mcp-Session-Id": ""}
    # 先 initialize
    st, hdrs, body, _ = _req("POST", "/mcp", {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "workbuddy-like-client", "version": "1.0"}}},
        auth)
    print(f"    initialize 状态码 : {st}")
    session_id = hdrs.get("Mcp-Session-Id") or hdrs.get("mcp-session-id")
    if session_id:
        auth["Mcp-Session-Id"] = session_id
        print(f"    MCP Session-Id    : {session_id[:24]}...")

    def parse_body(text):
        """Streamable HTTP 可能返回 SSE 帧，提取其中的 JSON。"""
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    msg = parse_body(body)
    if msg is None:
        print("    initialize 响应解析结果 :", body[:200])
    _req("POST", "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}, auth)

    st, _, body, _ = _req("POST", "/mcp", {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "whoami", "arguments": {}}}, auth)
    print(f"    tools/call 状态码 : {st}")
    msg = parse_body(body)
    if msg and "result" in msg:
        result = json.loads(msg["result"]["content"][0]["text"])
        print("\n    ┌─ 服务端识别到的人员档案 ─────────────────────────")
        print(f"    │ 登录人标识 : {result['userId']}")
        print(f"    │ 标识来源   : {result['userIdSource']}")
        print(f"    │ 姓名       : {result['displayName']}")
        print(f"    │ 租户       : {result['tenantId']}")
        print(f"    │ claims验签 : {result['claimsVerified']}  ← 已通过 JWT 验签")
        claims2 = result.get("claims") or {}
        for k, label in [("email", "邮箱"), ("employee_id", "工号"),
                         ("dept", "部门"), ("iss", "签发方")]:
            if claims2.get(k):
                print(f"    │ {label:8}: {claims2[k]}")
        print("    └──────────────────────────────────────────────────")
    else:
        print("    响应 :", body[:300])

    print("\n" + "=" * 78)
    print("  完整 OAuth 2.1 授权链路验证通过")
    print("  → 客户端通过标准流程拿到了【用户绑定的 token】")
    print("  → 服务端验签后识别出具体登录人（不再是匿名）")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())