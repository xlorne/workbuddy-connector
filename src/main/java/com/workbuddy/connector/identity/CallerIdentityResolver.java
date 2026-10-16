package com.workbuddy.connector.identity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.workbuddy.connector.config.IdentityProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 登录人标识解析器 —— 本服务最核心的组件。
 *
 * <p>分层策略（按信任度从高到低）：
 * <ol>
 *   <li><b>已验签 JWT</b>：Spring Security 已完成验签，claims 可直接信任；</li>
 *   <li><b>未验签 JWT</b>：本地拿不到企业 JWKS 时，仅做 Base64 解码以「看清里面有什么」，
 *       明确标记 claimsVerified=false，<b>仅供观测，绝不可作为鉴权依据</b>；</li>
 *   <li><b>身份 header</b>：网关前置注入的用户标识头（X-WB-User-Id 等）；</li>
 *   <li><b>均无</b>：判定为匿名。</li>
 * </ol>
 * 每一种来源都会记录在 {@code userIdSource} 中，这样联调时能立刻确认企业到底走的是哪条链路。
 */
@Component
public class CallerIdentityResolver {

    private static final Logger log = LoggerFactory.getLogger(CallerIdentityResolver.class);

    private final IdentityProperties properties;
    private final ObjectMapper objectMapper;

    public CallerIdentityResolver(IdentityProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    /**
     * 基于当前线程绑定的 HTTP 请求解析身份。
     * MCP 的 tool 调用发生在 POST /mcp/message 的请求线程内，因此这里能拿到当次调用的原始请求头。
     */
    public CallerIdentity resolve() {
        return resolve(RequestContextHolder.get());
    }

    public CallerIdentity resolve(HttpServletRequest request) {
        Map<String, String> identityHeaders = extractIdentityHeaders(request);
        String token = extractBearerToken(request);

        // 1) 优先使用 Spring Security 已验签的结果
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auth instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            CallerIdentity fromJwt = fromVerifiedJwt(jwt, identityHeaders, true);
            // SecurityContext 里没有可用 userId 时，再补上 header 线索
            if (fromJwt.userId() == null && !identityHeaders.isEmpty()) {
                Map.Entry<String, String> first = identityHeaders.entrySet().iterator().next();
                return new CallerIdentity(true, first.getValue(), "header." + first.getKey(),
                        fromJwt.displayName(), fromJwt.tenantId(), fromJwt.scopes(),
                        fromJwt.claims(), true, identityHeaders, token != null);
            }
            return fromJwt;
        }

        // 2) 退化为未验签解码——目的是「看清企业传了什么」，不是安全校验
        if (token != null) {
            Map<String, Object> claims = decodeJwtPayloadUnverified(token);
            if (!claims.isEmpty()) {
                CallerIdentity unverified = buildFromClaims(claims, identityHeaders);
                return new CallerIdentity(unverified.authenticated(), unverified.userId(),
                        unverified.userIdSource(), unverified.displayName(), unverified.tenantId(),
                        unverified.scopes(), claims, false, identityHeaders, true);
            }
            log.debug("Authorization 存在但不是可解析的 JWT，转由 header 判定");
        }

        // 3) 仅剩 header
        if (!identityHeaders.isEmpty()) {
            Map.Entry<String, String> first = identityHeaders.entrySet().iterator().next();
            return new CallerIdentity(false, first.getValue(), "header." + first.getKey(),
                    null, null, List.of(), new LinkedHashMap<>(), false, identityHeaders, token != null);
        }

        return new CallerIdentity(false, null, "none", null, null,
                List.of(), new LinkedHashMap<>(), false, identityHeaders, token != null);
    }

    private CallerIdentity fromVerifiedJwt(Jwt jwt, Map<String, String> identityHeaders, boolean verified) {
        Map<String, Object> claims = new LinkedHashMap<>(jwt.getClaims());
        CallerIdentity built = buildFromClaims(claims, identityHeaders);
        // 关键：来自 Spring Security 已验签的 JWT，必须把可信度标记为 true
        return new CallerIdentity(true, built.userId(), built.userIdSource(), built.displayName(),
                built.tenantId(), built.scopes(), claims, true, identityHeaders, true);
    }

    private CallerIdentity buildFromClaims(Map<String, Object> claims, Map<String, String> identityHeaders) {
        String userId = null;
        String source = null;
        for (String claimName : properties.getUserIdClaims()) {
            Object v = claims.get(claimName);
            if (v != null && !String.valueOf(v).isBlank()) {
                userId = String.valueOf(v);
                source = "jwt.claim." + claimName;
                break;
            }
        }
        String displayName = firstNonBlank(
                str(claims.get("name")),
                str(claims.get("real_name")),
                str(claims.get("nickname")),
                str(claims.get("display_name")),
                userId);
        String tenantId = firstNonBlank(
                str(claims.get("tenant_id")),
                str(claims.get("corp_id")),
                str(claims.get("corpid")),
                str(claims.get("tenant_id")),
                str(claims.get("org_id")));

        List<String> scopes = new ArrayList<>();
        Object scopeClaim = claims.get("scope");
        if (scopeClaim instanceof String s) {
            for (String part : s.split("[ ,]+")) {
                if (!part.isBlank()) {
                    scopes.add(part);
                }
            }
        } else if (scopeClaim instanceof Collection<?> c) {
            c.forEach(o -> scopes.add(String.valueOf(o)));
        }
        if (scopes.isEmpty() && claims.get("scp") instanceof Collection<?> c2) {
            c2.forEach(o -> scopes.add(String.valueOf(o)));
        }

        boolean authenticated = true;
        return new CallerIdentity(authenticated, userId, source, displayName, tenantId,
                scopes, claims, false, identityHeaders, true);
    }

    /**
     * 不验签地解析 JWT payload。仅用于观测：让开发者看清企业统一认证下发的身份信息长什么样。
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> decodeJwtPayloadUnverified(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                return Map.of();
            }
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            return objectMapper.readValue(payload, Map.class);
        } catch (Exception ex) {
            log.debug("JWT payload 解析失败: {}", ex.getMessage());
            return Map.of();
        }
    }

    private Map<String, String> extractIdentityHeaders(HttpServletRequest request) {
        Map<String, String> found = new LinkedHashMap<>();
        if (request == null) {
            return found;
        }
        for (String candidate : properties.getIdentityHeaders()) {
            String value = request.getHeader(candidate);
            if (value != null && !value.isBlank()) {
                found.put(candidate, value.trim());
            }
        }
        return found;
    }

    private String extractBearerToken(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return auth.substring(7).trim();
        }
        return null;
    }

    private String firstNonBlank(String... vals) {
        for (String v : vals) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    private String str(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    /** 极简请求上下文持有者，避免工具类层层传 request。 */
    public static final class RequestContextHolder {
        private static final ThreadLocal<HttpServletRequest> CTX = new ThreadLocal<>();

        private RequestContextHolder() {
        }

        public static void set(HttpServletRequest request) {
            CTX.set(request);
        }

        public static HttpServletRequest get() {
            return CTX.get();
        }

        public static void clear() {
            CTX.remove();
        }
    }
}