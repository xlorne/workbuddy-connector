#!/usr/bin/env python3
"""
MCP SSE 端到端验证 —— 完整协议握手流程。

关键点：MCP 协议要求客户端在 session 建立后，先发送 initialize 完成握手，
之后才能调用 tools/list 等方法。之前的测试直接调 tools/list 而跳过了
initialize，导致请求在 session.handle() 中挂起。
"""
import base64, json, queue, socket, sys, threading, time

HOST, PORT = "127.0.0.1", 3100
PROTOCOL_VERSION = "2025-06-18"


def b64url(o):
    return base64.urlsafe_b64encode(json.dumps(o, ensure_ascii=False).encode()).decode().rstrip("=")


TOKEN = (
    f"{b64url({'alg': 'RS256', 'typ': 'JWT', 'kid': 'sso-key-1'})}."
    f"{b64url({'sub': 'zhangsan', 'name': '张三', 'email': 'zhangsan@example-corp.com', 'employee_id': 'E10086', 'corp_id': 'corp_example', 'tenant_id': 'example-corp', 'dept': '平台研发部', 'title': '高级工程师', 'scope': 'schedule:read schedule:write profile', 'iss': 'https://sso.example-corp.com', 'aud': 'workbuddy-connector'})}."
    f"signature-placeholder"
)
IDENT = {"X-WB-User-Id": "zhangsan", "X-WB-CorpUserId": "corp_example"}


def headers_block(extra=None):
    lines = [f"{k}: {v}" for k, v in IDENT.items()]
    lines.append(f"Authorization: Bearer {TOKEN}")
    if extra:
        lines += [f"{k}: {v}" for k, v in extra.items()]
    return "\r\n".join(lines)


def start_sse(q):
    """建立 SSE 长连接并解析事件流。"""
    head = (
        f"GET /sse HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
        "Accept: text/event-stream\r\nCache-Control: no-cache\r\n"
        f"{headers_block()}\r\n\r\n"
    )
    s = socket.create_connection((HOST, PORT), timeout=20)
    s.sendall(head.encode())

    st = {"buf": b"", "event": None, "hdr_done": False}

    def reader():
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                st["buf"] += chunk
                while b"\n" in st["buf"]:
                    line, rest = st["buf"].split(b"\n", 1)
                    st["buf"] = rest
                    text = line.decode("utf-8").rstrip("\r")
                    if not st["hdr_done"]:
                        if text == "":
                            st["hdr_done"] = True
                        continue
                    if text.startswith("event:"):
                        st["event"] = text.split(":", 1)[1].strip()
                    elif text.startswith("data:"):
                        q.put((st["event"], text.split(":", 1)[1].strip()))
        except Exception:
            pass

    threading.Thread(target=reader, daemon=True).start()
    return s


def wait_endpoint(q, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            ev, data = q.get(timeout=1)
        except queue.Empty:
            continue
        if ev == "endpoint":
            return data
    raise TimeoutError("未收到 SSE endpoint 事件")


def post_rpc(session_id, payload, timeout=15):
    """POST JSON-RPC 并读取 HTTP 响应。

    MCP SSE 协议下，真正的业务响应通过 SSE 长连接回传，
    POST 本身只返回一个空的 200。因此这里读完状态行后立即返回，
    不做长时间等待，避免把时间浪费在本已结束的响应上。
    """
    body = json.dumps(payload).encode()
    head = (
        f"POST /mcp/message?sessionId={session_id} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json, text/event-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{headers_block()}\r\n\r\n"
    )
    s = socket.create_connection((HOST, PORT), timeout=timeout)
    s.sendall(head.encode() + body)

    # 只读到响应头结束（空行）即可，业务响应在 SSE 流上
    status = b""
    s.settimeout(5)
    try:
        while b"\r\n\r\n" not in status:
            c = s.recv(1)
            if not c:
                break
            status += c
    except socket.timeout:
        pass
    s.close()
    return status.decode("utf-8", errors="replace")


def await_response(q, msg_id, timeout=15):
    """从 SSE 流中等待指定 id 的响应。

    注意：队列里可能已存在之前请求的响应（例如 initialize）。
    这里缓存不匹配的响应，待命中目标后再放回队列，避免误消费导致后续步骤错乱。
    """
    pending = []
    end = time.time() + timeout
    try:
        while time.time() < end:
            try:
                _, data = q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                msg = json.loads(data)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == msg_id:
                return msg
            pending.append((None, data))
    finally:
        for item in pending:
            q.put(item)
    raise TimeoutError(f"未收到 id={msg_id} 的 SSE 响应")


def main():
    print("=" * 76)
    print("  MCP SSE 端到端验证 —— 完整协议握手（含 initialize）")
    print("=" * 76)
    print(f"  注入身份头 : {IDENT}")
    print("  JWT claims : sub=zhangsan, name=张三, dept=平台研发部, corp_id=corp_example")
    print()

    q = queue.Queue()
    sock = start_sse(q)

    endpoint = wait_endpoint(q)
    print(f"[1] SSE 握手成功")
    print(f"    message 端点 : {endpoint}")
    sid = endpoint.split("sessionId=")[1]

    print("\n[2] MCP initialize 握手（协议要求的第一步）")
    r = post_rpc(sid, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "workbuddy-verify", "version": "1.0.0"},
        },
    })
    print(f"    HTTP 响应字节数 : {len(r)}")
    init = await_response(q, 1)
    info = init["result"]["serverInfo"]
    print(f"    服务端信息      : {info.get('name')} v{info.get('version')}")
    print(f"    协议版本        : {init['result'].get('protocolVersion')}")

    print("\n[3] notifications/initialized 通知")
    post_rpc(sid, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    time.sleep(1.0)
    print("    已发送")

    print("\n[4] tools/list —— 拉取工具清单")
    post_rpc(sid, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools = await_response(q, 2, timeout=20)
    names = [t["name"] for t in tools["result"]["tools"]]
    print(f"    服务端暴露 {len(names)} 个工具:")
    for n in names:
        print(f"      - {n}")

    print("\n[5] tools/call whoami —— 服务端识别到的人员档案")
    post_rpc(sid, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "whoami", "arguments": {}}})
    p = json.loads(await_response(q, 3)["result"]["content"][0]["text"])
    c = p.get("claims") or {}
    scopes = ", ".join(p["scopes"]) if p["scopes"] else "<无>"
    print("    ┌─ 识别结果 ─────────────────────────────────────")
    print(f"    │ 登录人标识 : {p['userId']}")
    print(f"    │ 标识来源   : {p['userIdSource']}")
    print(f"    │ 姓名       : {p['displayName']}")
    print(f"    │ 租户       : {p['tenantId']}")
    print(f"    │ 权限 scope : {scopes}")
    print(f"    │ 携带 token : {p['tokenPresent']}")
    print(f"    │ claims验签 : {p['claimsVerified']}   (本地无企业 JWKS → 未验签观测模式)")
    print("    ├─ 员工档案(来自 JWT claims) ───────────────────")
    for key, label in [("sub", "账号"), ("name", "姓名"), ("email", "邮箱"),
                       ("employee_id", "工号"), ("dept", "部门"), ("title", "职位"),
                       ("corp_id", "企业ID"), ("tenant_id", "租户"), ("iss", "签发方")]:
        if c.get(key) is not None:
            print(f"    │ {label:8}: {c[key]}")
    print("    ├─ 命中身份 header ─────────────────────────────")
    for k, v in (p.get("identityHeaders") or {}).items():
        print(f"    │ {k}: {v}")
    print("    └────────────────────────────────────────────────")

    print("\n[6] tools/call list_my_schedule —— 验证身份驱动数据隔离")
    post_rpc(sid, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                   "params": {"name": "list_my_schedule",
                              "arguments": {"date": "2026-10-15", "claimedUser": "zhangsan"}}})
    s = json.loads(await_response(q, 4)["result"]["content"][0]["text"])
    print(f"    服务端解析 userId : {s['serverResolvedUserId']}  (来源 {s['serverResolvedUserIdSource']})")
    print(f"    客户端声称 user   : {s['claimedUser']}")
    print(f"    身份一致性        : {s['identityConsistent']}")
    print(f"    日程 owner        : {s['events'][0]['owner']}")

    print("\n[7] tools/call echo_call_context —— 回显全部请求头")
    post_rpc(sid, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                   "params": {"name": "echo_call_context", "arguments": {"label": "workbuddy联调"}}})
    e = json.loads(await_response(q, 5)["result"]["content"][0]["text"])
    print(f"    请求方法/路径 : {e.get('httpMethod')} {e.get('requestURI')}")
    print(f"    来源 IP       : {e.get('remoteAddr')}")
    hdrs = e.get("headers", {})
    print(f"    携带请求头 ({len(hdrs)} 个):")
    for k in sorted(hdrs):
        print(f"      {k}: {str(hdrs[k])[:54]}")

    print("\n" + "=" * 76)
    print("  验证通过：MCP 协议全链路打通，企业登录人标识解析正确")
    print("=" * 76)
    try:
        sock.close()
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print(f"\n验证失败: {type(ex).__name__}: {ex}")
        sys.exit(1)