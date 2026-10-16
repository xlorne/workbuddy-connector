package com.workbuddy.connector.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.workbuddy.connector.config.OAuthProperties;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内置 OAuth 2.1 授权服务器（仅用于本地联调）。
 *
 * <p><b>为什么内置一个授权服务器？</b>因为 MCP 的 OAuth 流程需要「授权服务器」这一环，
 * 而企业 SSO 通常需要走申请流程才能接入。为了让完整授权链路可以立刻验证，
 * 这里提供一个最小可用实现：注册 → 授权 → 登录 → 换 token。
 *
 * <p><b>生产环境请勿使用本实现</b>，应改为对接企业统一认证中心
 * （把 {@code workbuddy.oauth.embedded} 置为 false，并配置 {@code authorization-servers}）。
 *
 * <p>实现的端点（与官方文档要求一致）：
 * <ul>
 *   <li>{@code POST /oauth/register} 动态客户端注册（RFC 7591，公共客户端，回显 redirect_uris）</li>
 *   <li>{@code GET  /oauth/authorize} 授权端点，返回登录页，支持 PKCE S256</li>
 *   <li>{@code POST /oauth/login}    处理登录，302 回调并携带 code + state</li>
 *   <li>{@code POST /oauth/token}    校验 code_verifier，签发 access_token / refresh_token</li>
 * </ul>
 */
@RestController
@RequestMapping("/oauth")
public class EmbeddedOAuthAuthorizationServer {

    private static final Logger log = LoggerFactory.getLogger(EmbeddedOAuthAuthorizationServer.class);

    private final OAuthProperties properties;
    private final ObjectMapper objectMapper;

    /** 已注册的公共客户端：client_id → redirect_uris */
    private final Map<String, java.util.List<String>> clients = new ConcurrentHashMap<>();
    /** 待用户登录的授权请求：request_id → 授权请求上下文 */
    private final Map<String, PendingAuth> pending = new ConcurrentHashMap<>();
    /** 已签发的授权码：code → 授权码上下文 */
    private final Map<String, AuthCode> codes = new ConcurrentHashMap<>();
    /** 刷新令牌：token → (用户, 绑定客户端, 过期时间)。 */
    private final Map<String, RefreshToken> refreshTokens = new ConcurrentHashMap<>();

    public EmbeddedOAuthAuthorizationServer(OAuthProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    // ------------------------------------------------------------------ 动态客户端注册

    @PostMapping(value = "/register", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, Object> body) {
        String clientId = "wb-" + UUID.randomUUID().toString().substring(0, 12);
        @SuppressWarnings("unchecked")
        java.util.List<String> redirectUris = (java.util.List<String>) body.getOrDefault("redirect_uris", java.util.List.of());
        clients.put(clientId, redirectUris);

        log.info("[OAUTH-AS] 动态客户端注册 client_id={} redirect_uris={}", clientId, redirectUris);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("client_id", clientId);
        // 必须回显 redirect_uris，否则后续流程无法继续
        resp.put("redirect_uris", redirectUris);
        // 桌面客户端是公共客户端，PKCE，不持有 secret
        resp.put("token_endpoint_auth_method", "none");
        resp.put("grant_types", java.util.List.of("authorization_code", "refresh_token"));
        resp.put("response_types", java.util.List.of("code"));
        resp.put("client_id_issued_at", Instant.now().getEpochSecond());
        return ResponseEntity.status(201).body(resp);
    }

    // ------------------------------------------------------------------ 授权端点（登录页）

    @GetMapping("/authorize")
    public void authorize(@RequestParam Map<String, String> params, HttpServletResponse response) throws Exception {
        String redirectUri = params.get("redirect_uri");
        String codeChallenge = params.get("code_challenge");
        String codeChallengeMethod = params.getOrDefault("code_challenge_method", "S256");
        String clientId = params.get("client_id");
        String state = params.get("state");

        if (redirectUri == null || codeChallenge == null) {
            response.setStatus(400);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("缺少 redirect_uri 或 code_challenge");
            return;
        }

        // 回调必须与注册值精确匹配（安全要求）
        java.util.List<String> registered = clients.getOrDefault(clientId, java.util.List.of());
        if (!registered.isEmpty() && !registered.contains(redirectUri)) {
            log.warn("[OAUTH-AS] 回调地址不匹配！注册={} 本次={}", registered, redirectUri);
            response.setStatus(400);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("redirect_uri 与注册值不匹配");
            return;
        }

        String requestId = UUID.randomUUID().toString().substring(0, 8);
        pending.put(requestId, new PendingAuth(clientId, redirectUri, codeChallenge, codeChallengeMethod, state));

        log.info("[OAUTH-AS] 收到授权请求 request_id={} client_id={} redirect_uri={}", requestId, clientId, redirectUri);

        response.setContentType("text/html;charset=UTF-8");
        response.getWriter().write(renderLoginPage(requestId, clientId));
    }

    // ------------------------------------------------------------------ 登录处理

    @PostMapping(value = "/login")
    public void login(@RequestParam String request_id,
                      @RequestParam String username,
                      @RequestParam String password,
                      HttpServletResponse response) throws Exception {
        PendingAuth pa = pending.get(request_id);
        if (pa == null) {
            writeError(response, "授权请求已失效，请重新发起");
            return;
        }

        String expected = properties.getDemoUsers().get(username);
        if (expected == null || !expected.equals(password)) {
            log.warn("[OAUTH-AS] 登录失败 request_id={} username={}", request_id, username);
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write(renderLoginPage(request_id, pa.clientId(), "账号或密码错误"));
            return;
        }

        // 登录成功：生成一次性授权码
        String code = UUID.randomUUID().toString().replace("-", "");
        codes.put(code, new AuthCode(username, pa.clientId(), pa.redirectUri(), pa.codeChallenge(),
                pa.codeChallengeMethod(), Instant.now().plusSeconds(600)));
        pending.remove(request_id);

        StringBuilder loc = new StringBuilder(pa.redirectUri());
        loc.append(pa.redirectUri().contains("?") ? "&" : "?").append("code=").append(code);
        if (pa.state() != null) {
            loc.append("&state=").append(pa.state());
        }

        log.info("[OAUTH-AS] 登录成功 user={} → 302 回调 {}", username, pa.redirectUri());
        response.sendRedirect(loc.toString());
    }

    // ------------------------------------------------------------------ 令牌端点

    @PostMapping(value = "/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> token(@RequestParam Map<String, String> form) {
        String grantType = form.get("grant_type");

        if ("refresh_token".equals(grantType)) {
            String rt = form.get("refresh_token");
            String clientId = form.get("client_id");

            // 轮换：refresh_token 一次性使用，消费后立即作废，并签发新的一对
            RefreshToken stored = refreshTokens.remove(rt);
            if (stored == null) {
                log.warn("[OAUTH-AS] refresh_token 无效或已被使用（可能被重放）");
                return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant",
                        "error_description", "refresh token invalid or already used"));
            }
            if (stored.expiresAt().isBefore(Instant.now())) {
                log.warn("[OAUTH-AS] refresh_token 已过期 user={}", stored.userId());
                return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant",
                        "error_description", "refresh token expired, re-authorization required"));
            }
            // 刷新令牌绑定客户端，防止被其他客户端盗用
            if (clientId != null && !clientId.equals(stored.clientId())) {
                log.warn("[OAUTH-AS] refresh_token 的 client_id 不匹配");
                return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant",
                        "error_description", "client_id mismatch"));
            }

            log.info("[OAUTH-AS] 刷新令牌成功 user={}（access_token 已续期）", stored.userId());
            return ResponseEntity.ok(issueTokens(stored.userId(), stored.clientId()));
        }

        String code = form.get("code");
        String codeVerifier = form.get("code_verifier");
        String redirectUri = form.get("redirect_uri");
        String clientId = form.get("client_id");

        AuthCode ac = codes.remove(code);   // 一次性消费
        if (ac == null) {
            log.warn("[OAUTH-AS] 授权码无效或已被消费");
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant",
                    "error_description", "authorization code invalid or already used"));
        }
        if (ac.expiresAt().isBefore(Instant.now())) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant",
                    "error_description", "authorization code expired"));
        }
        if (clientId != null && !clientId.equals(ac.clientId())) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant",
                    "error_description", "client_id mismatch"));
        }
        if (redirectUri != null && !redirectUri.equals(ac.redirectUri())) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant",
                    "error_description", "redirect_uri mismatch"));
        }
        // PKCE 校验：SHA256(code_verifier) 的 base64url 必须等于 code_challenge
        if (codeVerifier == null || !verifyPkce(codeVerifier, ac.codeChallenge())) {
            log.warn("[OAUTH-AS] PKCE 校验失败");
            return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant",
                    "error_description", "PKCE verification failed"));
        }

        log.info("[OAUTH-AS] 令牌交换成功 user={}", ac.userId());
        return ResponseEntity.ok(issueTokens(ac.userId(), ac.clientId()));
    }

    // ------------------------------------------------------------------ 内部工具

    private Map<String, Object> issueTokens(String userId, String clientId) {
        long ttl = properties.getAccessTokenTtlSeconds();
        String accessToken = signJwt(userId, ttl);

        // refresh_token 是长期凭证：access_token 过期后靠它续期，
        // 因此它的有效期必须明显长于 access_token，否则用户会被频繁要求重新授权。
        String refreshToken = UUID.randomUUID().toString().replace("-", "");
        Instant refreshExpiry = Instant.now().plus(Duration.ofDays(properties.getRefreshTokenTtlDays()));
        purgeExpiredRefreshTokens();
        refreshTokens.put(refreshToken, new RefreshToken(userId, clientId, refreshExpiry));

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token", accessToken);
        resp.put("token_type", "Bearer");
        resp.put("expires_in", ttl);
        resp.put("refresh_token", refreshToken);
        resp.put("refresh_expires_in", Duration.ofDays(properties.getRefreshTokenTtlDays()).toSeconds());
        resp.put("scope", String.join(" ", properties.getScopesSupported()));
        return resp;
    }

    /** 清理过期令牌；若仍超上限则淘汰最早过期的，防止内存无界增长。 */
    private void purgeExpiredRefreshTokens() {
        Instant now = Instant.now();
        refreshTokens.entrySet().removeIf(e -> e.getValue().expiresAt().isBefore(now));

        int max = properties.getMaxRefreshTokens();
        while (refreshTokens.size() >= max) {
            refreshTokens.entrySet().stream()
                    .min(java.util.Comparator.comparing(e -> e.getValue().expiresAt()))
                    .map(Map.Entry::getKey)
                    .ifPresent(refreshTokens::remove);
        }
    }

    /** 用 HMAC-SHA256 签发 JWT（仅本地联调；生产由企业 SSO 用非对称密钥签发）。 */
    private String signJwt(String userId, long ttlSeconds) {
        try {
            String header = b64url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", properties.getEmbeddedIssuer());
            claims.put("sub", userId);
            claims.put("aud", properties.getResource());
            claims.put("iat", Instant.now().getEpochSecond());
            claims.put("exp", Instant.now().getEpochSecond() + ttlSeconds);
            claims.put("scope", String.join(" ", properties.getScopesSupported()));
            // 演示用的业务字段，模拟企业 SSO 下发的员工档案
            claims.put("name", demoName(userId));
            claims.put("email", userId + "@example-corp.com");
            claims.put("employee_id", "E" + Math.abs(userId.hashCode() % 100000));
            claims.put("dept", "平台研发部");
            claims.put("tenant_id", "example-corp");
            claims.put("corp_id", "corp_example");

            String payload = b64url(objectMapper.writeValueAsBytes(claims));
            String signingInput = header + "." + payload;

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(properties.getSigningSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String sig = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));
            return signingInput + "." + sig;
        } catch (Exception e) {
            throw new IllegalStateException("签发 JWT 失败", e);
        }
    }

    private boolean verifyPkce(String codeVerifier, String codeChallenge) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return computed.equals(codeChallenge);
        } catch (Exception e) {
            return false;
        }
    }

    private String demoName(String userId) {
        return switch (userId) {
            case "zhangsan" -> "张三";
            case "lisi" -> "李四";
            case "wangwu" -> "王五";
            default -> userId;
        };
    }

    private String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private void writeError(HttpServletResponse response, String msg) throws Exception {
        response.setStatus(400);
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().write(msg);
    }

    private String renderLoginPage(String requestId, String clientId) {
        return renderLoginPage(requestId, clientId, null);
    }

    private String renderLoginPage(String requestId, String clientId, String error) {
        StringBuilder users = new StringBuilder();
        properties.getDemoUsers().forEach((u, p) ->
                users.append("<li><code>").append(u).append("</code> / <code>").append(p).append("</code></li>"));

        String err = error == null ? "" : "<p style='color:#c00'>" + error + "</p>";
        return """
                <!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
                <title>授权登录 - WorkBuddy Connector</title>
                <style>
                  body{font-family:-apple-system,'PingFang SC',sans-serif;background:#f5f6f8;
                       display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
                  .card{background:#fff;padding:36px 40px;border-radius:12px;width:380px;
                        box-shadow:0 4px 24px rgba(0,0,0,.08)}
                  h1{font-size:19px;margin:0 0 6px}
                  p.sub{color:#666;font-size:13px;margin:0 0 22px}
                  label{display:block;font-size:13px;color:#333;margin-bottom:6px}
                  input{width:100%%;padding:10px 12px;border:1px solid #d9d9d9;border-radius:6px;
                        font-size:14px;box-sizing:border-box;margin-bottom:16px}
                  button{width:100%%;padding:11px;background:#07c160;color:#fff;border:0;
                         border-radius:6px;font-size:15px;cursor:pointer}
                  button:hover{background:#06ad56}
                  .hint{margin-top:22px;padding-top:16px;border-top:1px solid #eee;
                        font-size:12px;color:#888}
                  .hint ul{margin:8px 0 0;padding-left:18px}
                  code{background:#f0f0f0;padding:1px 5px;border-radius:3px}
                </style></head><body>
                <div class="card">
                  <h1>授权登录</h1>
                  <p class="sub">应用 <code>%s</code> 请求访问你的日程数据</p>
                  %s
                  <form method="post" action="/oauth/login">
                    <input type="hidden" name="request_id" value="%s">
                    <label>账号</label>
                    <input name="username" autocomplete="username" autofocus>
                    <label>密码</label>
                    <input name="password" type="password" autocomplete="current-password">
                    <button type="submit">登录并授权</button>
                  </form>
                  <div class="hint">
                    内置授权服务器（仅本地联调）。可用测试账号：
                    <ul>%s</ul>
                  </div>
                </div></body></html>
                """.formatted(clientId, err, requestId, users);
    }

    // ------------------------------------------------------------------ 数据结构

    private record PendingAuth(String clientId, String redirectUri, String codeChallenge,
                               String codeChallengeMethod, String state) {
    }

    private record AuthCode(String userId, String clientId, String redirectUri, String codeChallenge,
                            String codeChallengeMethod, Instant expiresAt) {
    }

    /** 刷新令牌记录：绑定用户与客户端，并记录过期时间。 */
    private record RefreshToken(String userId, String clientId, Instant expiresAt) {
    }
}