package com.workbuddy.connector.capture;

import com.workbuddy.connector.config.CaptureProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * 请求快照的内存存储（环形缓冲，容量上限由配置控制，避免长时间运行把内存打满）。
 *
 * <p>这是一个纯验证/观测用途的组件，所以选择内存存储而非数据库：重启即清空，
 * 正好符合「每次联调看当次传参」的使用方式。
 */
@Component
public class RequestCaptureStore {

    private final CaptureProperties properties;
    private final List<CapturedRequest> buffer;

    public RequestCaptureStore(CaptureProperties properties) {
        this.properties = properties;
        this.buffer = Collections.synchronizedList(new ArrayList<>());
    }

    public void record(CapturedRequest request) {
        synchronized (buffer) {
            buffer.add(request);
            int max = properties.getMaxRecords();
            while (buffer.size() > max) {
                buffer.remove(0);
            }
        }
    }

    /** 最新在前。 */
    public List<CapturedRequest> recent(int limit) {
        synchronized (buffer) {
            List<CapturedRequest> copy = new ArrayList<>(buffer);
            Collections.reverse(copy);
            if (limit > 0 && copy.size() > limit) {
                return new ArrayList<>(copy.subList(0, limit));
            }
            return copy;
        }
    }

    public Optional<CapturedRequest> latest() {
        synchronized (buffer) {
            return buffer.isEmpty() ? Optional.empty() : Optional.of(buffer.get(buffer.size() - 1));
        }
    }

    public int size() {
        return buffer.size();
    }

    public void clear() {
        synchronized (buffer) {
            buffer.clear();
        }
    }
}