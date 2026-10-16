package com.workbuddy.connector.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * MCP OAuth 2.1 配置。
 *
 * <p>「多用户环境下如何识别访问人」的官方解法是 MCP OAuth 2.1 流程。
 * 本服务作为 <b>OAuth 资源服务器</b>，生产环境不自己签发 token，
 * 而是把授权服务器指向企业统一认证中心。
 *
 * <p>为便于本地联调，提供 {@link #embedded} 开关：
 * 开启后内置一个最小可用的 OAuth 授权服务器（注册 / 授权 / 登录 / 令牌 + 演示用户），
 * 可在不依赖企业 SSO 的情况下走通完整授权链路。
 */
@ConfigurationProperties(prefix = "workbuddy.oauth")
public class OAuthProperties {

    /**
     * 是否启用 OAuth 资源服务器模式（未认证请求返回 401 挑战）。
     * 默认 false：观测模式，任何请求都能连上。要做身份识别时置为 true。
     */
    private boolean challengeEnabled = false;

    /** 本资源服务器对外标识（RFC 8707 resource），须与 MCP 端点一致。 */
    private String resource = "http://localhost:3100/mcp";

    /**
     * MCP 资源路径。RFC 9728 §3.1：资源标识符含路径时，受保护资源元数据地址为
     * {@code /.well-known/oauth-protected-resource<资源路径>}。
     * 例：resource=http://host/mcp → 元数据在 /.well-known/oauth-protected-resource/mcp
     */
    private String resourcePath = "/mcp";

    /** 企业统一认证中心地址（OAuth 授权服务器）。embedded=true 时可为空。 */
    private List<String> authorizationServers = new ArrayList<>();

    /** 本服务声明支持的 scope。 */
    private List<String> scopesSupported = new ArrayList<>(List.of("openid", "profile"));

    /** 无 token 时 WWW-Authenticate 的 realm。 */
    private String realm = "workbuddy-connector";

    /**
     * 是否启用内置授权服务器（仅本地联调）。
     * <b>生产环境必须为 false</b>，改为对接企业统一认证中心。
     */
    private boolean embedded = false;

    /** 内置授权服务器的 issuer 标识。 */
    private String embeddedIssuer = "http://localhost:3100";

    /** 内置授权服务器的演示用户目录（用户名 → 密码）。生产环境绝不使用。 */
    private Map<String, String> demoUsers = new HashMap<>(Map.of("zhangsan", "123456"));

    /** 签发的 access_token 有效期（秒）。短期以降低泄露风险，靠 refresh_token 续期。 */
    private long accessTokenTtlSeconds = 3600;

    /** refresh_token 有效期（天）。过期后必须重新授权。 */
    private long refreshTokenTtlDays = 30;

    /**
     * refresh_token 有效期（秒），<b>仅供联调验证过期行为</b>：
     * 大于 0 时覆盖 {@link #refreshTokenTtlDays}（天级粒度无法在联调中观察）。
     */
    private long refreshTokenTtlSeconds = 0;

    /** refresh_token 最大保存数量，防止内存无界增长。 */
    private int maxRefreshTokens = 1000;

    /**
     * JWT 时间戳校验的时钟容差（秒）。
     *
     * <p>用于容忍客户端与服务端的时钟漂移 —— 若不设容差，
     * 客户端稍快几秒就会把「刚签发」的 token 判为未生效。
     * 默认 60 秒（Spring Security 默认值）。联调验证 token 过期时可设为 0。
     */
    private long clockSkewSeconds = 60;

    /** 内置授权服务器的对称签名密钥（仅联调）。 */
    private String signingSecret = "workbuddy-connector-local-dev-only-secret-key-32b";

    /** 实际生效的授权服务器列表。 */
    public List<String> effectiveAuthorizationServers() {
        if (embedded) {
            return List.of(embeddedIssuer);
        }
        return authorizationServers;
    }

    public boolean isChallengeEnabled() {
        return challengeEnabled;
    }

    public void setChallengeEnabled(boolean challengeEnabled) {
        this.challengeEnabled = challengeEnabled;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getResourcePath() {
        return resourcePath;
    }

    public void setResourcePath(String resourcePath) {
        this.resourcePath = resourcePath;
    }

    public List<String> getAuthorizationServers() {
        return authorizationServers;
    }

    public void setAuthorizationServers(List<String> authorizationServers) {
        this.authorizationServers = authorizationServers;
    }

    public List<String> getScopesSupported() {
        return scopesSupported;
    }

    public void setScopesSupported(List<String> scopesSupported) {
        this.scopesSupported = scopesSupported;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public boolean isEmbedded() {
        return embedded;
    }

    public void setEmbedded(boolean embedded) {
        this.embedded = embedded;
    }

    public String getEmbeddedIssuer() {
        return embeddedIssuer;
    }

    public void setEmbeddedIssuer(String embeddedIssuer) {
        this.embeddedIssuer = embeddedIssuer;
    }

    public Map<String, String> getDemoUsers() {
        return demoUsers;
    }

    public void setDemoUsers(Map<String, String> demoUsers) {
        this.demoUsers = demoUsers;
    }

    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public void setAccessTokenTtlSeconds(long accessTokenTtlSeconds) {
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    }

    public long getRefreshTokenTtlDays() {
        return refreshTokenTtlDays;
    }

    public void setRefreshTokenTtlDays(long refreshTokenTtlDays) {
        this.refreshTokenTtlDays = refreshTokenTtlDays;
    }

    public long getRefreshTokenTtlSeconds() {
        return refreshTokenTtlSeconds;
    }

    public void setRefreshTokenTtlSeconds(long refreshTokenTtlSeconds) {
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    /** 实际生效的 refresh_token 有效期。 */
    public Duration effectiveRefreshTokenTtl() {
        return refreshTokenTtlSeconds > 0
                ? Duration.ofSeconds(refreshTokenTtlSeconds)
                : Duration.ofDays(refreshTokenTtlDays);
    }

    public int getMaxRefreshTokens() {
        return maxRefreshTokens;
    }

    public void setMaxRefreshTokens(int maxRefreshTokens) {
        this.maxRefreshTokens = maxRefreshTokens;
    }

    public long getClockSkewSeconds() {
        return clockSkewSeconds;
    }

    public void setClockSkewSeconds(long clockSkewSeconds) {
        this.clockSkewSeconds = clockSkewSeconds;
    }

    public String getSigningSecret() {
        return signingSecret;
    }

    public void setSigningSecret(String signingSecret) {
        this.signingSecret = signingSecret;
    }
}