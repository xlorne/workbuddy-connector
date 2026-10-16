package com.workbuddy.connector.identity;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 一次调用中的「登录人标识」解析结果。
 *
 * @param authenticated  是否已通过 OAuth2 验签认证
 * @param userId         最终认定的登录人标识（最核心的字段）
 * @param userIdSource   该标识的来源，例如 {@code jwt.claim.sub} / {@code header.X-WB-User-Id} / {@code SecurityContext}
 * @param displayName    展示名（姓名/昵称），可能为空
 * @param tenantId       租户/企业标识，可能为空
 * @param scopes         授予的 scope
 * @param claims         全部 JWT claims（可能是未验签解析所得）
 * @param claimsVerified claims 是否来自已验签的 Authentication
 * @param identityHeaders 命中的身份类header
 * @param tokenPresent   是否携带了 Bearer token
 */
public record CallerIdentity(
        boolean authenticated,
        String userId,
        String userIdSource,
        String displayName,
        String tenantId,
        java.util.List<String> scopes,
        Map<String, Object> claims,
        boolean claimsVerified,
        Map<String, String> identityHeaders,
        boolean tokenPresent) {

    public static CallerIdentity anonymous() {
        return new CallerIdentity(false, null, "none", null, null,
                java.util.List.of(), new LinkedHashMap<>(), false, new LinkedHashMap<>(), false);
    }

    /** 以自然语言解释当前身份判定，便于直接作为 MCP 工具返回值给模型阅读。 */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("认证状态: ").append(authenticated ? "已认证" : "未认证(匿名)").append('\n');
        sb.append("登录人标识: ").append(userId == null ? "<未识别到>" : userId).append('\n');
        sb.append("标识来源: ").append(userIdSource == null ? "<无>" : userIdSource).append('\n');
        sb.append("展示名: ").append(displayName == null ? "<无>" : displayName).append('\n');
        sb.append("租户: ").append(tenantId == null ? "<无>" : tenantId).append('\n');
        sb.append("scope: ").append(scopes == null || scopes.isEmpty() ? "<无>" : String.join(",", scopes)).append('\n');
        sb.append("claims 可信度: ").append(claimsVerified
                ? "已验签(Spring Security 认证)"
                : (claims == null || claims.isEmpty() ? "无claims" : "未验签解析(仅供观测，不应作为鉴权依据)")).append('\n');
        sb.append("携带 token: ").append(tokenPresent ? "是" : "否").append('\n');
        sb.append("身份类 header: ").append(identityHeaders == null || identityHeaders.isEmpty()
                ? "<无>" : identityHeaders.toString());
        return sb.toString();
    }
}