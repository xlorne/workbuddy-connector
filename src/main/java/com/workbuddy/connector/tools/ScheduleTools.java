package com.workbuddy.connector.tools;

import com.workbuddy.connector.identity.CallerIdentity;
import com.workbuddy.connector.identity.CallerIdentityResolver;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 日程相关的示例工具。
 *
 * <p>这些方法刻意把「当前登录人」写进返回值/过滤条件里：
 * 这样既贴合「日程数据接入验证」的定位，也能实际验证企业统一认证的登录人标识
 * 能否正确驱动业务逻辑（例如只能看自己的日程），而不仅仅是打印出来。
 */
@Component
public class ScheduleTools {

    private final CallerIdentityResolver resolver;

    public ScheduleTools(CallerIdentityResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * 查询「当前登录人」的日程，演示按身份隔离数据。
     *
     * <p>注意：这里的 user 参数是用于对照的期望值，真实过滤依据始终来自服务端解析出的
     * 登录人标识，以此演示「客户端声称的身份」与「服务端认定的身份」是否一致。
     */
    @Tool(name = "list_my_schedule", description = """
            查询当前登录人(企业统一认证身份)在指定日期的日程。
            数据按服务端解析出的登录人标识进行隔离，不接受客户端自行指定身份。""")
    public Map<String, Object> listMySchedule(
            @ToolParam(description = "查询日期，格式 yyyy-MM-dd；为空则返回今天", required = false) String date,
            @ToolParam(description = "客户端声称的当前用户，仅用于对照校验，可为空", required = false) String claimedUser) {

        CallerIdentity identity = resolver.resolve();
        String target = (date == null || date.isBlank()) ? LocalDate.now().toString() : date;

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("queryDate", target);
        out.put("serverResolvedUserId", identity.userId());
        out.put("serverResolvedUserIdSource", identity.userIdSource());
        out.put("authenticated", identity.authenticated());
        out.put("identitySummary", identity.describe());

        if (claimedUser != null && !claimedUser.isBlank()) {
            boolean match = claimedUser.equals(identity.userId());
            out.put("claimedUser", claimedUser);
            out.put("identityConsistent", match);
            out.put("consistencyNote", match
                    ? "客户端声称身份与服务端解析结果一致"
                    : "警告：客户端声称身份与服务端解析结果不一致，可能存在身份透传问题");
        }

        out.put("events", List.of(
                Map.of("id", "evt-1001", "title", "企业日程同步验证会议",
                        "start", target + " 10:00:00", "end", target + " 11:00:00",
                        "owner", identity.userId() == null ? "<未识别到登录人>" : identity.userId()),
                Map.of("id", "evt-1002", "title", "MCP 联调 - 身份透传确认",
                        "start", target + " 14:00:00", "end", target + " 15:00:00",
                        "owner", identity.userId() == null ? "<未识别到登录人>" : identity.userId())));
        return out;
    }
}