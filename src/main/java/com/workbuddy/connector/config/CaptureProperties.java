package com.workbuddy.connector.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "workbuddy.capture")
public class CaptureProperties {

    /**
     * 是否启用抓包过滤器。
     *
     * <p>联调排查时若怀疑过滤器干扰 MCP 长连接，可用 {@code --workbuddy.capture.enabled=false}
     * 快速关闭做对照实验。
     */
    private boolean enabled = true;

    /** 环形缓冲保留的最大请求快照数。 */
    private int maxRecords = 200;

    /** 单个请求体最大保留字符数，超出截断。 */
    private int maxBodyChars = 8000;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public int getMaxRecords() {
        return maxRecords;
    }

    public void setMaxRecords(int maxRecords) {
        this.maxRecords = maxRecords;
    }

    public int getMaxBodyChars() {
        return maxBodyChars;
    }

    public void setMaxBodyChars(int maxBodyChars) {
        this.maxBodyChars = maxBodyChars;
    }
}