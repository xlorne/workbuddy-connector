package com.workbuddy.connector.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * 身份识别相关的可调参数。
 *
 * <p>企业统一认证（OAuth 2.1）的登录人标识具体落在哪个 header / JWT claim 上，
 * 不同企业实现差异很大。与其猜一个写死，不如全部做成可配置列表：
 * 服务会按顺序尝试匹配，并在观测输出中明确标注「命中来源」，
 * 这样联调一次就能确定企业真实使用的字段，后续再收紧配置。
 */
@ConfigurationProperties(prefix = "workbuddy.identity")
public class IdentityProperties {

    /**
     * 候选身份 header（小写比较）。命中任一即视为携带登录人标识。
     * 覆盖常见的企微/内部网关约定。
     */
    private List<String> identityHeaders = new ArrayList<>(List.of(
            "x-wb-user-id",
            "x-wb-username",
            "x-wb-corpuserid",
            "x-wecom-userid",
            "x-wx-userid",
            "x-user-id",
            "x-userid",
            "x-employee-id",
            "x-staff-id",
            "x-login-user",
            "x-authenticated-user",
            "x-forwarded-user",
            "x-forwarded-user-email",
            "x-forwarded-email",
            "x-forwarded-for",
            "x-real-ip",
            "remote-user"));

    /** JWT 中被视为「登录人标识」的 claim，按优先级排列。 */
    private List<String> userIdClaims = new ArrayList<>(List.of(
            "sub", "user_name", "username", "preferred_username", "userid",
            "user_id", "corp_userid", "staff_id", "employee_id", "login_name", "email"));

    /** 是否在观测输出中对 token 只展示摘要（false = 展示完整 token，便于核对）。 */
    private boolean maskToken = false;

    public List<String> getIdentityHeaders() {
        return identityHeaders;
    }

    public void setIdentityHeaders(List<String> identityHeaders) {
        this.identityHeaders = identityHeaders;
    }

    public List<String> getUserIdClaims() {
        return userIdClaims;
    }

    public void setUserIdClaims(List<String> userIdClaims) {
        this.userIdClaims = userIdClaims;
    }

    public boolean isMaskToken() {
        return maskToken;
    }

    public void setMaskToken(boolean maskToken) {
        this.maskToken = maskToken;
    }
}