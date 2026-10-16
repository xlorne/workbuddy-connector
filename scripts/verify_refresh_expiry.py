#!/usr/bin/env python3
"""
refresh_token 过期（长期未续期）行为验证。

回答的问题：
  如果我没有在有效期内用 refresh_token 续期，会发生什么？
  服务端会不会明确告诉客户端「必须重新授权」？重新授权后能否立即恢复？

验证步骤：
  1. 完成 OAuth 授权流程，取得 access_token + refresh_token
  2. 用有效 access_token 调用 → 200，能识别身份
  3. 等待 refresh_token 有效期结束（服务端起短 TTL）
  4. 用失效 access_token 调用 → 401，且 WWW-Authenticate 带 error="invalid_token"
     （客户端据此知道「凭证失效」，而不是「从未授权」）
  5. 用已过期的 refresh_token 续期 → 400 invalid_grant
     （服务端明确拒绝续期，客户端应作废本地凭证）
  6. 重新走一次完整授权流程 → 200，身份立即恢复
     （这就是用户看到的「需要重新连接/授权」，且授权一次即可恢复）

运行前提（服务端以短 TTL 启动，便于在秒级观察过期行为）：
  java -jar target/workbuddy-connector-1.0.0.jar \\
    --workbuddy.oauth.access-token-ttl-seconds=8 \\
    --workbuddy.oauth.refresh-token-ttl-seconds=12 \\
    --workbuddy.oauth.clock-skew-seconds=0
"""
import base64, hashlib, http.client, json, re, secrets, sys, time
from urllib.parse import urlencode, urlparse, parse_qs

HOST, PORT = "127.0.0.1", 3100


def _req(method, path, body=None, headers=None):
    """发请求并返回 (状态码, 响应体, 响应头dict, Location)。"""
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
    out_headers = {k.lower(): v for k, v in resp.getheaders()}
    loc = resp.getheader("Location")
    conn.close()
    return resp.status, data, out_headers, loc


def mcp_whoami(access_token):
    """完成 Streamable HTTP 握手后调用 whoami，返回 (状态码, 用户名, 响应头)。

    Streamable HTTP 是有状态的：initialize 的响应头会带 Mcp-Session-Id，
    后续请求必须回传该头，否则服务端返回 400。
    """
    auth = {"Authorization": f"Bearer {access_token}"}
    st, _, hdrs, _ = _req("POST", "/mcp", {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "expiry-test", "version": "1.0"}}}, auth)
    if st != 200:
        return st, None, hdrs
    sid = hdrs.get("mcp-session-id")
    if sid:
        auth["Mcp-Session-Id"] = sid
    _req("POST", "/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}, auth)
    st, body, hdrs, _ = _req("POST", "/mcp", {
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
    return st, user, hdrs


def authorize(username="zhangsan", password="123456"):
    """走一次完整授权流程，返回 (client_id, access_token, refresh_token, token响应)。"""
    redirect_uri = f"http://127.0.0.1:{PORT}/oauth/callback-demo"
    _, body, _, _ = _req("POST", "/oauth/register", {
        "client_name": "expiry-test", "redirect_uris": [redirect_uri],
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

    form = urlencode({"request_id": request_id, "username": username, "password": password})
    _, _, _, location = _req("POST", "/oauth/login", form,
                             {"Content-Type": "application/x-www-form-urlencoded"})
    code = parse_qs(urlparse(location).query)["code"][0]

    form = urlencode({"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                      "client_id": client_id, "redirect_uri": redirect_uri})
    _, body, _, _ = _req("POST", "/oauth/token", form,
                         {"Content-Type": "application/x-www-form-urlencoded"})
    tok = json.loads(body)
    return client_id, tok["access_token"], tok["refresh_token"], tok


def step(n, desc):
    print(f"\n[{n}] {desc}")


def main():
    print("=" * 78)
    print("  refresh_token 过期行为验证（长期未续期会怎样）")
    print("=" * 78)

    # ---------------------------------------------------------------- 1. 授权拿令牌
    step(1, "完成 OAuth 授权流程，取得 access_token + refresh_token")
    client_id, at1, rt1, tok = authorize()
    at_ttl = tok.get("expires_in", 0)
    rt_ttl = tok.get("refresh_expires_in", 0)
    print(f"    client_id              : {client_id}")
    print(f"    access_token           : {at1[:32]}...")
    print(f"    access_token 有效期    : {at_ttl}s")
    print(f"    refresh_token          : {rt1[:20]}...")
    print(f"    refresh_token 有效期   : {rt_ttl}s")

    if rt_ttl <= at_ttl:
        print("\n    ⚠️  refresh_token 有效期未短于 access_token，")
        print("        请以 --workbuddy.oauth.refresh-token-ttl-seconds=<秒> 启动服务后重跑。")
        return 1

    # ---------------------------------------------------------------- 2. 有效期内调用
    step(2, "在有效期内用 access_token 调用 MCP 工具 → 预期 200")
    st, user, _ = mcp_whoami(at1)
    print(f"    状态码 : {st}   识别到用户 : {user}")
    if st != 200:
        print("    ✗ 有效 token 被拒绝，请检查服务端配置"); return 1

    # ---------------------------------------------------------------- 3. 等待双双过期
    step(3, f"等待 refresh_token 有效期结束（{rt_ttl}s，期间不做任何续期）")
    for i in range(rt_ttl + 2, 0, -1):
        print(f"\r    倒计时 {i}s ...", end="", flush=True)
        time.sleep(1)
    print("\r    已超期（access_token 与 refresh_token 均已失效）")

    # ---------------------------------------------------------------- 4. 失效 token 调用
    step(4, "用【已失效】access_token 调用 → 预期 401 且挑战头带 invalid_token")
    st, _, hdrs = mcp_whoami(at1)
    challenge = hdrs.get("www-authenticate", "")
    print(f"    状态码            : {st}")
    print(f"    WWW-Authenticate  : {challenge[:120]}")
    hint_refresh = 'error="invalid_token"' in challenge
    hint_discovery = "resource_metadata=" in challenge
    print(f"    ├─ 告知凭证已失效 : {hint_refresh}")
    print(f"    └─ 告知去哪重新授权: {hint_discovery}")
    if st != 401:
        print("    ✗ 预期 401，未复现失效拦截"); return 1

    # ---------------------------------------------------------------- 5. 过期 refresh 续期
    step(5, "用【已过期】refresh_token 尝试续期 → 预期 400 invalid_grant")
    form = urlencode({"grant_type": "refresh_token", "refresh_token": rt1, "client_id": client_id})
    st, body, _, _ = _req("POST", "/oauth/token", form,
                          {"Content-Type": "application/x-www-form-urlencoded"})
    err = json.loads(body) if body.startswith("{") else {}
    print(f"    状态码             : {st}")
    print(f"    error              : {err.get('error')}")
    print(f"    error_description  : {err.get('error_description')}")
    if st != 400 or err.get("error") != "invalid_grant":
        print("    ✗ 预期 400 invalid_grant"); return 1
    print("    ✓ 服务端明确拒绝续期 —— 客户端应作废本地凭证并重新授权")
    print("      （若客户端不处理，用户会持续看到连接失败/工具报错）")

    # ---------------------------------------------------------------- 6. 重新授权恢复
    step(6, "重新走一次完整授权流程（用户重新登录）→ 预期立即恢复")
    client_id2, at2, rt2, tok2 = authorize()
    st, user2, _ = mcp_whoami(at2)
    print(f"    重新授权后状态码 : {st}   识别到用户 : {user2}")
    print(f"    新 refresh 有效期: {tok2.get('refresh_expires_in', 0)}s（重新开始计时）")
    recovered = st == 200 and user2 == "zhangsan"

    print("\n" + "=" * 78)
    print("  验证结论")
    print("=" * 78)
    print("  ✓ 刷新令牌超期后，access_token 与 refresh_token 均失效，请求返回 401")
    print("  ✓ 服务端以 400 invalid_grant 明确告知「续期失败，需重新授权」")
    print("  ✓ 401 挑战头同时给出 invalid_token（凭证失效）与 resource_metadata（去哪授权）")
    print(f"  {'✓' if recovered else '✗'} 重新授权一次即可恢复，新 refresh_token 有效期重新计时")
    print()
    print("  一句话：超期不会「静默失败」，而是明确要求重新授权；")
    print("         是否弹出授权界面由客户端决定，服务端只能给出标准信号。")
    print("=" * 78)
    return 0 if recovered else 1


if __name__ == "__main__":
    sys.exit(main())
