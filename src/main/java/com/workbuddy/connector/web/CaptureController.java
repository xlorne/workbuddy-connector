package com.workbuddy.connector.web;

import com.workbuddy.connector.capture.CapturedRequest;
import com.workbuddy.connector.capture.RequestCaptureStore;
import com.workbuddy.connector.identity.CallerIdentity;
import com.workbuddy.connector.identity.CallerIdentityResolver;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 观测用的 REST 端点。
 *
 * <p>提供不经过 MCP 协议的快捷排查入口：在浏览器或 curl 中直接查看
 * 「最近请求到了什么、服务端认定的登录人是谁」，比翻控制台日志高效得多。
 */
@RestController
@RequestMapping("/__capture")
public class CaptureController {

    private final RequestCaptureStore store;
    private final CallerIdentityResolver resolver;
    private final com.workbuddy.connector.config.OAuthProperties oauthProperties;

    public CaptureController(RequestCaptureStore store, CallerIdentityResolver resolver,
                             com.workbuddy.connector.config.OAuthProperties oauthProperties) {
        this.store = store;
        this.resolver = resolver;
        this.oauthProperties = oauthProperties;
    }

    /** 健康检查 + 基本信息（含当前传输协议与 OAuth 模式）。 */
    @GetMapping(value = "/health", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> health() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "UP");
        out.put("protocol", "STREAMABLE");
        out.put("mcpEndpoint", "/mcp");
        out.put("oauthChallengeEnabled", oauthProperties.isChallengeEnabled());
        out.put("embeddedAuthorizationServer", oauthProperties.isEmbedded());
        out.put("capturedRequests", store.size());
        return out;
    }

    /** 当前这次 HTTP 请求在服务端解析出的身份（不走 MCP 协议，直观验证 header/token）。 */
    @GetMapping(value = "/whoami", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> whoami() {
        CallerIdentity identity = resolver.resolve();
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

    /** 最近捕获到的请求列表。 */
    @GetMapping(value = "/requests", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> requests(
            @RequestParam(required = false, defaultValue = "20") int limit) {
        List<CapturedRequest> recent = store.recent(limit);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total", store.size());
        out.put("requests", recent);
        return ResponseEntity.ok(out);
    }

    /** 某次请求的完整细节（含全部请求头与请求体全文）。 */
    @GetMapping(value = "/requests/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> requestDetail(@org.springframework.web.bind.annotation.PathVariable String id) {
        return store.recent(store.size()).stream()
                .filter(r -> r.id().equals(id))
                .findFirst()
                .map(r -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", r.id());
                    m.put("timestamp", r.timestamp().toString());
                    m.put("method", r.method());
                    m.put("uri", r.uri());
                    m.put("query", r.queryString());
                    m.put("headers", r.headers());
                    m.put("body", r.body());
                    m.put("remoteAddr", r.remoteAddr());
                    return ResponseEntity.ok(m);
                })
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** 清空缓冲，便于开始一轮新的联调。 */
    @DeleteMapping(value = "/requests", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> clear() {
        int before = store.size();
        store.clear();
        return Map.of("cleared", before, "message", "抓包缓冲已清空");
    }
}