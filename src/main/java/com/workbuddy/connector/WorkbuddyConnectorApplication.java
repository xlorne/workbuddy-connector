package com.workbuddy.connector;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@SpringBootApplication
@ConfigurationPropertiesScan
public class WorkbuddyConnectorApplication {

    /**
     * 端口保护：防止 IDE 注入的环境变量劫持本服务端口。
     *
     * <p>背景：WorkBuddy IDE 会向子进程注入 {@code SERVER__PORT} / {@code SERVER__HOST} 环境变量
     * （其自身服务端口，例如 50430）。Spring Boot 的 relaxed binding 会把 {@code SERVER__PORT}
     * 映射为 {@code server.port}，而环境变量的属性源优先级<b>高于 application.yml</b>，
     * 于是本服务会静默监听 IDE 的端口，MCP 客户端按 3100 配置自然连不上。
     *
     * <p>解决方式：Spring Boot 属性源优先级中，<b>命令行参数高于环境变量</b>。
     * 因此这里把端口/地址作为「默认命令行参数」注入 —— 既能压过环境变量，
     * 又保留了用户通过 {@code --server.port=xxxx} 显式覆盖的能力。
     */
    private static String[] withPortDefaults(String[] args) {
        List<String> merged = new ArrayList<>(Arrays.asList(args));
        boolean hasPort = merged.stream().anyMatch(a -> a.startsWith("--server.port"));
        boolean hasAddress = merged.stream().anyMatch(a -> a.startsWith("--server.address"));

        if (!hasPort) {
            String fromEnv = System.getenv("WORKBUDDY_CONNECTOR_PORT");
            merged.add("--server.port=" + (fromEnv != null && !fromEnv.isBlank() ? fromEnv : "3100"));
        }
        if (!hasAddress) {
            merged.add("--server.address=127.0.0.1");
        }
        return merged.toArray(new String[0]);
    }

    public static void main(String[] args) {
        new SpringApplicationBuilder(WorkbuddyConnectorApplication.class)
                .run(withPortDefaults(args));
    }
}