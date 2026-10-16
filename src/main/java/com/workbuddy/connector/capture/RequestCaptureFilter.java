package com.workbuddy.connector.capture;

import com.workbuddy.connector.config.CaptureProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 抓包过滤器：在链路最前端记录每一个进入本服务的 HTTP 请求。
 *
 * <p>顺序被刻意设为 {@link Ordered#HIGHEST_PRECEDENCE}，确保在 Spring Security 之前执行，
 * 这样即便后续因为 token 无效被 401 拒绝，请求内容（含 Authorization 头）依然已经留痕，
 * 从而能够回答「WorkBuddy 到底发了什么」这个核心问题。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestCaptureFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestCaptureFilter.class);

    private final RequestCaptureStore store;
    private final CaptureProperties properties;

    public RequestCaptureFilter(RequestCaptureStore store, CaptureProperties properties) {
        this.store = store;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // /__capture 自身是观测接口，不记录，避免自噪声
        if (!properties.isEnabled() || request.getRequestURI().startsWith("/__capture")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 关键：请求进入时立即记录，而不是放在 finally 里。
        // SSE 是长连接，若放在 finally 中记录，必须等客户端断开才会落库，
        // 会导致「握手请求迟迟看不到记录」，联调时误判为没抓到包。
        recordOnEntry(request);

        if (isStreamingRequest(request)) {
            // SSE / 流式响应不能包裹 ContentCachingRequestWrapper：
            // 包装器会尝试缓存响应体，破坏长连接的流式输出。
            filterChain.doFilter(request, response);
            return;
        }

        // 普通请求：包裹后可在调用结束时读取 body
        ContentCachingRequestWrapper wrapped = new ContentCachingRequestWrapper(request);
        filterChain.doFilter(wrapped, response);
        recordBody(wrapped);
    }

    /** SSE 这类长连接流式请求不做 body 缓存。 */
    private boolean isStreamingRequest(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        return accept != null && accept.contains("text/event-stream");
    }

    /** 请求进入时记录：此时请求头、query 已完整可用。 */
    private void recordOnEntry(HttpServletRequest request) {
        try {
            Map<String, List<String>> headers = new LinkedHashMap<>();
            EnumerationNames(request, headers);

            store.record(new CapturedRequest(
                    UUID.randomUUID().toString().substring(0, 8),
                    java.time.Instant.now(),
                    request.getMethod(),
                    request.getRequestURI(),
                    request.getQueryString(),
                    headers,
                    "",
                    request.getRemoteAddr(),
                    null,
                    false));

            logRequest(request);
        } catch (Exception ex) {
            log.warn("请求抓包失败，但不影响主流程: {}", ex.getMessage());
        }
    }

    /** 请求结束后补记 body（仅普通请求）。 */
    private void recordBody(ContentCachingRequestWrapper request) {
        try {
            String body = new String(request.getContentAsByteArray(), StandardCharsets.UTF_8);
            if (body.isEmpty()) {
                return;
            }
            boolean truncated = body.length() > properties.getMaxBodyChars();

            Map<String, List<String>> headers = new LinkedHashMap<>();
            EnumerationNames(request, headers);

            store.record(new CapturedRequest(
                    UUID.randomUUID().toString().substring(0, 8),
                    java.time.Instant.now(),
                    request.getMethod(),
                    request.getRequestURI(),
                    request.getQueryString(),
                    headers,
                    truncated ? body.substring(0, properties.getMaxBodyChars()) + "...[truncated]" : body,
                    request.getRemoteAddr(),
                    null,
                    truncated));
        } catch (Exception ex) {
            log.debug("记录请求体失败: {}", ex.getMessage());
        }
    }

    private void logRequest(HttpServletRequest request) {
        if (!log.isInfoEnabled()) {
            return;
        }
        log.info("[CAPTURE] {} {} auth={} ua={}",
                request.getMethod(), request.getRequestURI(),
                abbreviate(request.getHeader("Authorization")),
                abbreviate(request.getHeader("User-Agent")));
    }

    private void EnumerationNames(HttpServletRequest request, Map<String, List<String>> headers) {
        java.util.Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            headers.put(name, headerValues(request, name));
        }
    }

    /** Enumeration&lt;String&gt; 不能直接喂给 List.of，这里做一次安全转换。 */
    private List<String> headerValues(HttpServletRequest request, String name) {
        List<String> values = new java.util.ArrayList<>();
        java.util.Enumeration<String> raw = request.getHeaders(name);
        while (raw != null && raw.hasMoreElements()) {
            values.add(raw.nextElement());
        }
        return values;
    }

    private String abbreviate(String s) {
        if (s == null) {
            return "<none>";
        }
        return s.length() <= 60 ? s : s.substring(0, 60) + "...";
    }
}