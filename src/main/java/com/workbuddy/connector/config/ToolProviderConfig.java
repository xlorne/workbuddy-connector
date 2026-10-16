package com.workbuddy.connector.tools;

import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 把带 {@code @Tool} 的 Bean 注册为 MCP 工具。
 */
@Configuration
public class ToolProviderConfig {

    @Bean
    public ToolCallbackProvider identityTools(IdentityInspectorTools identityInspectorTools,
                                              ScheduleTools scheduleTools,
                                              PingTools pingTools) {
        return MethodToolCallbackProvider.builder()
                .toolObjects(identityInspectorTools, scheduleTools, pingTools)
                .build();
    }
}