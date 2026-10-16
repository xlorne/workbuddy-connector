package com.workbuddy.connector.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * 宽容的 JWT 认证过滤器。
 *
 * <p>为什么不直接用 {@code oauth2ResourceServer().jwt()}：那条链路在没有配置
 * {@code issuer-uri}/{@code jwk-set-uri} 时无法创建 JwtDecoder，且一旦开启就会对
 * 无 token 请求直接 401 —— 而本地联调的第一阶段恰恰是「还没有企业 token，先看看服务端看到什么」。
 *
 * <p>本过滤器的行为：
 * <ul>
 *   <li>没有 Bearer token → 直接放行，不设置任何认证（匿名）；</li>
 *   <li>有 token 且 {@link JwtDecoder} 可用且验签通过 → 写入 JwtAuthenticationToken；</li>
 *   <li>有 token 但验签失败/无 decoder → 仅记录日志并放行，
 *       身份解析器会退化为「未验签解码」，用于观测企业到底下发了什么。</li>
 * </ul>
 */
public class PermissiveJwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(PermissiveJwtAuthenticationFilter.class);

    private final ObjectProvider<JwtDecoder> jwtDecoderProvider;

    public PermissiveJwtAuthenticationFilter(ObjectProvider<JwtDecoder> jwtDecoderProvider) {
        this.jwtDecoderProvider = jwtDecoderProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            filterChain.doFilter(request, response);
            return;
        }
        String token = header.substring(7).trim();

        JwtDecoder decoder = jwtDecoderProvider.getIfAvailable();
        if (decoder == null) {
            log.info("收到 Bearer token，但未配置 issuer-uri/jwk-set-uri，跳过验签（仅观测模式）");
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Jwt jwt = decoder.decode(token);
            // 必须写入 JwtAuthenticationToken：CallerIdentityResolver 以此判定
            // 「claims 是否来自已验签的 token」，用其他 Authentication 类型会导致
            // 身份被误判为「未验签」。
            JwtAuthenticationToken auth = new JwtAuthenticationToken(jwt, AuthorityUtils.NO_AUTHORITIES);
            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
            log.info("JWT 验签通过, subject={}", jwt.getSubject());
        } catch (BadJwtException ex) {
            log.warn("JWT 验签失败({})，按观测模式继续放行", ex.getMessage());
        } catch (Exception ex) {
            log.warn("JWT 处理异常({})，按观测模式继续放行", ex.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}