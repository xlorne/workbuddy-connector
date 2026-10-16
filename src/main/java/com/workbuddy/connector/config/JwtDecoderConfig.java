package com.workbuddy.connector.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * JWT 验签配置。
 *
 * <p>两种来源互斥：
 * <ul>
 *   <li><b>内置授权服务器模式</b>（{@code workbuddy.oauth.embedded=true}）：
 *       用对称密钥验签，供本地联调走通全流程；</li>
 *   <li><b>企业 SSO 模式</b>：由 Spring Boot 依据
 *       {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}
 *       自动配置（非对称密钥 + JWKS 轮换），本类不介入。</li>
 * </ul>
 * 注意 {@link org.springframework.security.oauth2.jwt.JwtDecoder} 是 MCP 服务
 * 识别「当前访问人」的关键：验签通过后才能信任 token 中的用户标识。
 */
@Configuration
public class JwtDecoderConfig {

    private static final Logger log = LoggerFactory.getLogger(JwtDecoderConfig.class);

    @Bean
    @ConditionalOnProperty(prefix = "workbuddy.oauth", name = "embedded", havingValue = "true")
    public JwtDecoder embeddedJwtDecoder(OAuthProperties properties) {
        log.info("""
                \n========================================================
                 使用内置授权服务器（仅本地联调）
                   issuer : {}
                   resource: {}
                 生产环境请设置 workbuddy.oauth.embedded=false 并接入企业 SSO
                =========================================================""",
                properties.getEmbeddedIssuer(), properties.getResource());

        SecretKeySpec key = new SecretKeySpec(
                properties.getSigningSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(key).build();
    }
}