package com.workbuddy.connector.capture;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * 一次被捕获的 HTTP/MCP 请求快照。
 *
 * <p>本项目的核心目的不是业务，而是「看清楚 WorkBuddy 调用本MCP 服务时到底传了什么」，
 * 因此这里刻意保留原始请求的全部要素：方法、URI、查询参数、所有请求头、以及请求体原文。
 * Authorization 等敏感头同样保留（可用 mask 配置决定是否打码），因为验证身份透传必须看到原值。
 */
public record CapturedRequest(
        String id,
        Instant timestamp,
        String method,
        String uri,
        String queryString,
        Map<String, List<String>> headers,
        String body,
        String remoteAddr,
        String sessionId,
        boolean bodyTruncated) {

    /** 请求头大小写不敏感地取第一个值。 */
    public String header(String name) {
        if (headers == null) {
            return null;
        }
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (e.getKey() != null && e.getKey().equalsIgnoreCase(name)) {
                List<String> v = e.getValue();
                return (v == null || v.isEmpty()) ? null : v.get(0);
            }
        }
        return null;
    }
}