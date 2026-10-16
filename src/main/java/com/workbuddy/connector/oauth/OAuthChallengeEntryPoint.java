package com.workbuddy.connector.oauth;

import com.workbuddy.connector.config.OAuthProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

/**
 * OAuth 挑战入口点 —— 触发 WorkBuddy 内置 OAuth 管理器的关键。
 *
 * <p>按 MCP 规范（2025-06-18 授权章节），资源服务器在收到未认证请求时
 * 必须返回 <b>401</b> 并附带 {@code WWW-Authenticate} 头，其中
 * {@code resource_metadata} 指向受保护资源元数据地址。客户端据此自动发现授权服务器，
 * 无需任何预配置。
 *
 * <p>这个 401 是整个多用户身份识别链路的<b>起点</b>：
 * 服务端只要不返回它，WorkBuddy 就认为「该服务无需认证」，
 * 也就永远不会带上「当前用户是谁」的凭证。
 */
public class OAuthChallengeEntryPoint implements AuthenticationEntryPoint {

    private static final Logger log = LoggerFactory.getLogger(OAuthChallengeEntryPoint.class);

    private final OAuthProperties properties;

    public OAuthChallengeEntryPoint(OAuthProperties properties) {
        this.properties = properties;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // RFC 9728 §3.1：资源标识符含路径时，受保护资源元数据地址为
        // {origin}/.well-known/oauth-protected-resource{资源路径}
        // 例：resource=http://host/mcp → http://host/.well-known/oauth-protected-resource/mcp
        java.net.URI u = java.net.URI.create(properties.getResource());
        String origin = u.getScheme() + "://" + u.getAuthority();
        String metadataUrl = origin + "/.well-known/oauth-protected-resource" + properties.getResourcePath();
        // RFC 6750 §3：若请求带了 token 但被拒绝（如已过期），挑战中应带 error="invalid_token"。
        // 客户端据此区分「从未授权」与「凭证已失效」，前者发起完整授权、后者先尝试续期。
        boolean tokenPresented = request.getHeader(HttpHeaders.AUTHORIZATION) != null;
        StringBuilder challenge = new StringBuilder("Bearer realm=\"").append(properties.getRealm()).append("\"");
        if (tokenPresented) {
            challenge.append(", error=\"invalid_token\", error_description=\"The access token expired or is invalid\"");
        }
        challenge.append(", resource_metadata=\"").append(metadataUrl).append("\"");

        log.info("[OAUTH-CHALLENGE] 未认证请求 {} {}（{}）→ 返回 401，提示客户端去 {} 发现授权服务器",
                request.getMethod(), request.getRequestURI(),
                tokenPresented ? "携带的 token 已失效" : "未携带 token", metadataUrl);

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, challenge.toString());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("""
                {"error":"invalid_token","error_description":"Authentication required. \
                Discover the authorization server at the resource_metadata URL \
                advertised in the WWW-Authenticate header."}""");
    }
}