package com.workbuddy.connector.oauth;

import com.workbuddy.connector.config.OAuthProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * OAuth 2.1 发现端点。
 *
 * <p>这是「让 WorkBuddy 知道该去哪里认人」的入口。链路如下：
 * <ol>
 *   <li>WorkBuddy 访问 {@code /sse}，本服务返回 <b>401</b>，
 *       并在 {@code WWW-Authenticate} 头里给出 {@code resource_metadata} 地址；</li>
 *   <li>WorkBuddy 请求 {@code /.well-known/oauth-protected-resource}（RFC 9728），
 *       拿到本资源标识与<b>授权服务器列表</b>；</li>
 *   <li>WorkBuddy 去该授权服务器（企业统一认证中心）做动态注册 + PKCE 授权，
 *       用户用<b>自己的企业账号</b>登录；</li>
 *   <li>WorkBuddy 带着该用户的 access_token 重新调用本服务，本服务验签后
 *       即可解析出「当前访问人是谁」。</li>
 * </ol>
 *
 * <p>注意本服务只做<b>资源服务器</b>：token 由企业统一认证中心签发，本服务只验证不签发。
 * 这样身份治理（开户、销户、权限复核）继续由企业既有体系负责。
 */
@RestController
public class OAuthDiscoveryController {

    private static final Logger log = LoggerFactory.getLogger(OAuthDiscoveryController.class);

    private final OAuthProperties properties;

    public OAuthDiscoveryController(OAuthProperties properties) {
        this.properties = properties;
    }

    /**
     * RFC 9728 受保护资源元数据 —— WorkBuddy 发现授权服务器的第一步。
     */
    @GetMapping(value = {
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp"
    }, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> protectedResourceMetadata() {
        java.util.List<String> authServers = properties.effectiveAuthorizationServers();

        log.info("[OAUTH-DISCOVERY] 客户端请求了 oauth-protected-resource，授权服务器将指向: {}", authServers);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("resource", properties.getResource());
        body.put("authorization_servers", authServers);
        body.put("scopes_supported", properties.getScopesSupported());
        body.put("bearer_methods_supported", java.util.List.of("header"));
        // 便于联调时确认服务端确实读到了配置
        body.put("_note", authServers.isEmpty()
                ? "尚未配置授权服务器：请设置 workbuddy.oauth.embedded=true（内置联调）"
                  + " 或填入 workbuddy.oauth.authorization-servers（企业统一认证中心）"
                : (properties.isEmbedded()
                    ? "使用内置授权服务器（仅联调）"
                    : "授权服务器已配置为企业统一认证中心"));
        return ResponseEntity.ok(body);
    }

    /**
     * RFC 8414 授权服务器元数据。
     *
     * <p>正式部署时该端点由<b>企业统一认证中心</b>提供，WorkBuddy 会直接访问它，
     * 不会问本服务。这里保留一个本地实现，仅用于在没有企业 SSO 的联调环境里
     * 把完整流程跑通（可指向一个本地/测试用的 OAuth 服务器）。
     */
    @GetMapping(value = "/.well-known/oauth-authorization-server", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> authorizationServerMetadata() {
        java.util.List<String> authServers = properties.effectiveAuthorizationServers();
        if (authServers.isEmpty()) {
            return ResponseEntity.ok(Map.of(
                    "error", "authorization_server_not_configured",
                    "message", "本服务是资源服务器，授权服务器元数据应由企业统一认证中心提供。"
                            + "请配置 workbuddy.oauth.authorization-servers 指向企业 SSO，"
                            + "或设置 workbuddy.oauth.embedded=true 使用内置授权服务器（仅联调）。"));
        }
        String issuer = authServers.get(0);
        log.info("[OAUTH-DISCOVERY] 返回授权服务器元数据，issuer={}", issuer);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("issuer", issuer);
        body.put("authorization_endpoint", issuer + "/oauth/authorize");
        body.put("token_endpoint", issuer + "/oauth/token");
        body.put("registration_endpoint", issuer + "/oauth/register");
        body.put("scopes_supported", properties.getScopesSupported());
        body.put("response_types_supported", java.util.List.of("code"));
        body.put("grant_types_supported", java.util.List.of("authorization_code", "refresh_token"));
        body.put("code_challenge_methods_supported", java.util.List.of("S256"));
        body.put("token_endpoint_auth_methods_supported", java.util.List.of("none"));
        return ResponseEntity.ok(body);
    }
}