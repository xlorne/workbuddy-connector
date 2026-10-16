package com.workbuddy.connector.tools;

import com.workbuddy.connector.capture.CapturedRequest;
import com.workbuddy.connector.capture.RequestCaptureStore;
import com.workbuddy.connector.identity.CallerIdentity;
import com.workbuddy.connector.identity.CallerIdentityResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * MCP 工具集 —— WorkBuddy 侧实际可以调用的能力。
 *
 * <p>工具命名刻意直白（whoami / echo_call_context / list_captured_requests），
 * 让模型在「我不确定对方传了什么」时能主动调用并把真实内容回显给用户，
 * 从而形成一条自动化的联调链路，而不必人工翻服务端日志。
 */
@Component
public class IdentityInspectorTools {

    private static final Logger log = LoggerFactory.getLogger(IdentityInspectorTools.class);

    private final CallerIdentityResolver resolver;
    private final RequestCaptureStore store;

    public IdentityInspectorTools(CallerIdentityResolver resolver, RequestCaptureStore store) {
        this.resolver = resolver;
        this.store = store;
    }

    /**
     * 返回当前调用者的企业统一认证登录人标识。
     *
     * <p>这是验证身份透传最直接的探针：WorkBuddy 调用本工具返回的内容，
     * 就是服务端从请求头 / JWT 中实际解析出的登录人。
     */
    @Tool(name = "whoami", description = """
            返回当前 MCP 调用者的身份信息，包含企业统一认证的登录人标识(userId)、
            标识来源(来自 JWT claim 还是身份 header)、展示名、租户、scope 以及全部 claims。
            当需要确认『我调用这个服务时，服务端识别到我是谁』时使用此工具。""")
    public Map<String, Object> whoami() {
        CallerIdentity identity = resolver.resolve();
        log.info("[WHOAMI] userId={} source={} authenticated={}",
                identity.userId(), identity.userIdSource(), identity.authenticated());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("authenticated", identity.authenticated());
        out.put("userId", identity.userId());
        out.put("userIdSource", identity.userIdSource());
        out.put("displayName", identity.displayName());
        out.put("tenantId", identity.tenantId());
        out.put("scopes", identity.scopes());
        out.put("tokenPresent", identity.tokenPresent());
        out.put("claimsVerified", identity.claimsVerified());
        out.put("claims", identity.claims());
        out.put("identityHeaders", identity.identityHeaders());
        out.put("summary", identity.describe());
        return out;
    }

    /**
     * 原样回显本次调用的完整上下文：工具入参 + HTTP 方法/URI/query/全部请求头。
     *
     * <p>用于回答『WorkBuddy 调用这个 MCP 服务时到底传了什么参数』。
     */
    @Tool(name = "echo_call_context", description = """
            回显本次调用携带的完整上下文：传入的参数、HTTP 请求方法与路径、查询字符串、
            以及全部请求头(含 Authorization)。用于诊断客户端实际传递了哪些参数与身份信息。""")
    public Map<String, Object> echoCallContext(
            @ToolParam(description = "回显用的标签，便于区分多次调用", required = false) String label) {

        CallerIdentity identity = resolver.resolve();
        var request = CallerIdentityResolver.RequestContextHolder.get();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("label", label == null ? "(未提供)" : label);
        out.put("identity", identity.describe());

        if (request != null) {
            out.put("httpMethod", request.getMethod());
            out.put("requestURI", request.getRequestURI());
            out.put("queryString", request.getQueryString());
            out.put("remoteAddr", request.getRemoteAddr());

            Map<String, List<String>> headers = new LinkedHashMap<>();
            java.util.Enumeration<String> names = request.getHeaderNames();
            while (names != null && names.hasMoreElements()) {
                String n = names.nextElement();
                headers.put(n, headerValues(request, n));
            }
            out.put("headers", headers);
        } else {
            out.put("httpMethod", "(非HTTP线程上下文，STDIO/本地调用)");
        }

        log.info("[ECHO] label={} uri={}", label, request == null ? "n/a" : request.getRequestURI());
        return out;
    }

    /**
     * 列出服务启动以来捕获到的最近若干次 HTTP 请求，用于回溯握手与调用过程。
     */
    /** Enumeration&lt;String&gt; 转 List，便于以 JSON 结构回显。 */
    private List<String> headerValues(HttpServletRequest request, String name) {
        List<String> values = new ArrayList<>();
        java.util.Enumeration<String> raw = request.getHeaders(name);
        while (raw != null && raw.hasMoreElements()) {
            values.add(raw.nextElement());
        }
        return values;
    }

    @Tool(name = "list_captured_requests", description = """
            列出服务端最近捕获到的 HTTP 请求快照(方法/路径/关键请求头/请求体长度)，
            包含建立 MCP SSE 连接与工具调用的全过程，用于排查握手或参数传递问题。""")
    public Map<String, Object> listCapturedRequests(
            @ToolParam(description = "返回最近多少条，默认 20", required = false) Integer limit) {

        int n = (limit == null || limit <= 0) ? 20 : Math.min(limit, 100);
        List<CapturedRequest> recent = store.recent(n);

        List<Map<String, Object>> items = new ArrayList<>();
        for (CapturedRequest r : recent) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", r.id());
            m.put("timestamp", r.timestamp().toString());
            m.put("method", r.method());
            m.put("uri", r.uri());
            m.put("query", r.queryString());
            m.put("authorization", r.header("Authorization"));
            m.put("userAgent", r.header("User-Agent"));
            m.put("bodyPreview", r.body() == null ? "" :
                    (r.body().length() > 400 ? r.body().substring(0, 400) + "..." : r.body()));
            m.put("bodyLength", r.body() == null ? 0 : r.body().length());
            items.add(m);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total", store.size());
        out.put("returned", items.size());
        out.put("requests", items);
        return out;
    }

    /**
     * 查看最近一次请求的完整请求头（未截断），用于排查自定义身份头。
     */
    @Tool(name = "last_request_headers", description = """
            查看最近一次进入本服务的 HTTP 请求的完整请求头(不截断)与请求体全文，
            用于确认客户端传递的自定义身份字段。""")
    public Map<String, Object> lastRequestHeaders() {
        return store.latest().map(r -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", r.id());
            m.put("timestamp", r.timestamp().toString());
            m.put("method", r.method());
            m.put("uri", r.uri());
            m.put("query", r.queryString());
            m.put("headers", r.headers());
            m.put("body", r.body());
            m.put("remoteAddr", r.remoteAddr());
            return m;
        }).orElseGet(() -> Map.of("error", "尚未捕获到任何请求"));
    }
}