package com.workbuddy.connector.tools;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * 最小化的对照工具：不触碰任何 ThreadLocal / SecurityContext / Servlet API。
 *
 * <p>用途：与 {@link IdentityInspectorTools} 做 A/B 对照。
 * 若本工具能正常返回、而依赖请求上下文的工具挂起，
 * 即可确认阻塞源自请求上下文（ThreadLocal / SecurityContext）在异步链路上不可用，
 * 而不是 MCP 传输层本身的问题。
 */
@Component
public class PingTools {

    @Tool(name = "ping", description = "最简单的健康检查工具，返回 pong，不读取任何请求上下文。")
    public Map<String, String> ping() {
        return Map.of("result", "pong");
    }
}