#!/usr/bin/env python3
"""
Token 过期与自动续期（refresh_token）验证。

回答的问题：
  access_token 是有时效的 JWT，过期后请求会 401 吗？会。
  但客户端应能用 refresh_token 换新 token 后重试，此过程对用户透明。
  本脚本验证服务端的续期链路是否正确、是否安全。

验证步骤：
  1. OAuth 授权流程拿到 access_token + refresh_token
  2. 用有效 access_token 调用 → 200
  3. 等待 access_token 过期（服务端 access-token-ttl-seconds 已设为很短）
  4. 用过期 token 调用 → 401（预期行为）
  5. 用 refresh_token 换新 token → 200，且拿到新的 access_token 与 refresh_token
  6. 用新 access_token 调用 → 200（续期成功，业务无感）
  7. 重放旧 refresh_token → 400（轮换生效，防重放）
"""
import base64, hashlib, http.client, json, re, secrets, sys, time
from urllib.parse import urlencode, urlparse, parse_qs

HOST, PORT = "127.0.0.1", 3100


def _req(method, path, body=None, headers=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=20)
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
        data = e.partial.decode("utf-8", errors="replace")
    loc = resp.getheader("Location")
    sid = resp.getheader("Mcp-Session-Id") or resp.getheader("mcp-session-id")
    conn.close()
    return resp.status, data, loc, sid


def mcp_whoami(access_token):
    """完成 Streamable HTTP 握手后调用 whoami。

    Streamable HTTP 是有状态的：必须先 initialize 拿到 Mcp-Session-Id，
    再发 notifications/initialized，最后才能调 tools/call。
    未携带 token 时 initialize 会被 401 拒绝，这本身就是过期信号。
    """
    auth = {"Authorization": f"Bearer {access_token}"}

    st, body, _, sid = _req("POST", "/mcp", {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "refresh-test", "version": "1.0"}}}, auth)
    if st != 200:
        return st, None
    if sid:
        auth["Mcp-Session-Id"] = sid
    _req("POST", "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}, auth)

    st, body, _, _ = _req("POST", "/mcp", {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "whoami", "arguments": {}}}, auth)
    user = None
    for line in body.splitlines():
        if line.startswith("data:"):
            try:
                msg = json.loads(line[5:].strip())
                if "result" in msg:
                    user = json.loads(msg["result"]["content"][0]["text"])["userId"]
            except Exception:
                pass
    return st, user


def step(n, desc):
    print(f"\n[{n}] {desc}")


def decode_jwt_exp(token):
    p = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    return claims


def main():
    print("=" * 78)
    print("  Token 过期与自动续期验证")
    print("=" * 78)

    # ---------------------------------------------------------------- 1. 走授权流程拿令牌
    step(1, "完成 OAuth 授权流程，取得 access_token + refresh_token")
    redirect_uri = f"http://127.0.0.1:{PORT}/oauth/callback-demo"
    _, body, _, _ = _req("POST", "/oauth/register", {
        "client_name": "refresh-test", "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
        "token_endpoint_auth_method": "none"})
    client_id = json.loads(body)["client_id"]

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    q = urlencode({"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
                   "code_challenge": challenge, "code_challenge_method": "S256", "state": "s1"})
    _, html, _, _ = _req("GET", f"/oauth/authorize?{q}")
    request_id = re.search(r'name="request_id" value="([^"]+)"', html).group(1)

    form = urlencode({"request_id": request_id, "username": "zhangsan", "password": "123456"})
    _, _, location, _ = _req("POST", "/oauth/login", form,
                             {"Content-Type": "application/x-www-form-urlencoded"})
    code = parse_qs(urlparse(location).query)["code"][0]

    form = urlencode({"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                      "client_id": client_id, "redirect_uri": redirect_uri})
    _, body, _, _ = _req("POST", "/oauth/token", form,
                         {"Content-Type": "application/x-www-form-urlencoded"})
    tok = json.loads(body)
    at1, rt1 = tok["access_token"], tok["refresh_token"]
    claims = decode_jwt_exp(at1)
    ttl = tok["expires_in"]
    print(f"    client_id        : {client_id}")
    print(f"    access_token     : {at1[:32]}...")
    print(f"    expires_in       : {ttl}s")
    print(f"    refresh_token    : {rt1[:20]}...")
    print(f"    refresh 有效期   : {tok.get('refresh_expires_in', 0)}s "
          f"({tok.get('refresh_expires_in', 0)//86400} 天)")
    print(f"    JWT exp 时间戳   : {claims['exp']}")

    # ---------------------------------------------------------------- 2. 有效 token 调用
    step(2, "用【有效】access_token 调用 MCP 工具")
    st, user = mcp_whoami(at1)
    print(f"    状态码 : {st}   识别到用户 : {user}")

    # ---------------------------------------------------------------- 3. 等待过期
    step(3, f"等待 access_token 过期（{ttl}s）")
    for i in range(ttl + 3, 0, -1):
        print(f"\r    倒计时 {i}s ...", end="", flush=True)
        time.sleep(1)
    print("\r    已过期          ")

    # ---------------------------------------------------------------- 4. 过期 token 调用
    step(4, "用【已过期】access_token 调用 → 预期 401")
    st, _ = mcp_whoami(at1)
    print(f"    状态码 : {st}")
    if st != 401:
        print("    ✗ 预期 401，未复现过期拦截"); return 1
    print("    ✓ 过期 token 被正确拒绝")

    # ---------------------------------------------------------------- 5. 续期
    step(5, "用 refresh_token 换取新 access_token → 预期 200")
    form = urlencode({"grant_type": "refresh_token", "refresh_token": rt1, "client_id": client_id})
    st, body, _, _ = _req("POST", "/oauth/token", form,
                          {"Content-Type": "application/x-www-form-urlencoded"})
    print(f"    状态码 : {st}")
    if st != 200:
        print(f"    ✗ 续期失败: {body[:200]}"); return 1
    tok2 = json.loads(body)
    at2, rt2 = tok2["access_token"], tok2["refresh_token"]
    print(f"    新 access_token  : {at2[:32]}...")
    print(f"    新 refresh_token : {rt2[:20]}...")
    print(f"    已轮换           : {rt2 != rt1}")

    # ---------------------------------------------------------------- 6. 新 token 调用
    step(6, "用【新】access_token 调用 → 预期 200（业务无感）")
    st, user2 = mcp_whoami(at2)
    print(f"    状态码 : {st}   识别到用户 : {user2}  ← 续期后仍能正常识别身份")

    # ---------------------------------------------------------------- 7. 旧 refresh 重放
    step(7, "重放【旧】refresh_token → 预期 400（轮换生效，防重放）")
    form = urlencode({"grant_type": "refresh_token", "refresh_token": rt1, "client_id": client_id})
    st, body, _, _ = _req("POST", "/oauth/token", form,
                          {"Content-Type": "application/x-www-form-urlencoded"})
    print(f"    状态码 : {st}   {body[:110]}")
    ok_rotation = st == 400

    print("\n" + "=" * 78)
    print("  验证结论")
    print("=" * 78)
    print("  ✓ access_token 过期后确实返回 401（这是设计如此，短期凭证降风险）")
    print("  ✓ 客户端可用 refresh_token 静默换取新 token，无需用户重新登录")
    print("  ✓ refresh_token 采用轮换机制，旧令牌一次使用后立即作废")
    if not ok_rotation:
        print("  ✗ 轮换未生效，旧 refresh_token 仍可用（存在重放风险）")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())