package com.workbuddy.connector.config;

import com.workbuddy.connector.oauth.OAuthChallengeEntryPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * 安全配置，支持两种互斥运行模式。
 *
 * <h3>模式一：观测模式（默认，{@code workbuddy.oauth.challenge-enabled=false}）</h3>
 * 全端点放通。用于联调第一步——在还没有企业 token 时先看清客户端传了什么。
 * 此时 WorkBuddy 不会走 OAuth 流程，服务端也就拿不到用户身份。
 *
 * <h3>模式二：OAuth 资源服务器模式（{@code challenge-enabled=true}）</h3>
 * 未认证请求返回 401 + {@code WWW-Authenticate}，触发 WorkBuddy 内置的 OAuth 管理器：
 * 发现元数据 → 动态注册 → 打开浏览器让用户用<b>企业账号</b>登录 → 携带用户 token 重试。
 * 这是多用户场景下识别「当前访问人」的官方标准做法。
 *
 * <p>两种模式都保留 {@link PermissiveJwtAuthenticationFilter} 负责验签，
 * 区别只在于「验签失败/无 token 时是放行还是挑战」。
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   ObjectProvider<JwtDecoder> jwtDecoderProvider,
                                                   OAuthProperties oauthProperties) throws Exception {

        boolean challengeEnabled = oauthProperties.isChallengeEnabled();
        OAuthChallengeEntryPoint entryPoint = new OAuthChallengeEntryPoint(oauthProperties);

        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(new PermissiveJwtAuthenticationFilter(jwtDecoderProvider),
                        UsernamePasswordAuthenticationFilter.class);

        if (challengeEnabled) {
            // OAuth 资源服务器模式：MCP 端点要求认证，未认证返回 401 触发授权流程
            http.authorizeHttpRequests(auth -> auth
                            // 发现端点是公开的：客户端必须能不带 token 访问它
                            .requestMatchers("/.well-known/**").permitAll()
                            // 授权服务器端点必须公开（注册/授权/登录/令牌）
                            .requestMatchers("/oauth/**").permitAll()
                            // 观测端点保持公开，便于排查（生产环境应关闭）
                            .requestMatchers("/__capture/**").permitAll()
                            // MCP 协议端点要求认证 —— 这是拿到用户身份的关键
                            .requestMatchers("/mcp", "/mcp/**", "/sse", "/mcp/message").authenticated()
                            .anyRequest().permitAll())
                    .exceptionHandling(ex -> ex.authenticationEntryPoint(entryPoint));

            log.info("""
                    \n========================================================
                     OAuth 资源服务器模式已启用
                       resource            : {}
                       authorization_servers: {}
                     WorkBuddy 将按标准 MCP OAuth 2.1 流程获取用户 token。
                    ========================================================""",
                    oauthProperties.getResource(), oauthProperties.getAuthorizationServers());

            if (oauthProperties.getAuthorizationServers().isEmpty()) {
                log.warn("未配置 workbuddy.oauth.authorization-servers，"
                        + "客户端将无法完成授权。请填入企业统一认证中心地址。");
            }
        }
        else {
            // 观测模式：全放通，保证任何情况下都能连上并观察原始请求
            http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
            log.info("观测模式（permitAll）：WorkBuddy 不会触发 OAuth，服务端无法获知用户身份。"
                    + "需要识别访问人时请设置 workbuddy.oauth.challenge-enabled=true");
        }

        return http.build();
    }
}