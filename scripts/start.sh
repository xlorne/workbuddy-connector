#!/usr/bin/env bash
#
# 启动 WorkBuddy Connector MCP 服务（OAuth 2.1 用户身份透传）
#
# 用法：
#   ./scripts/start.sh          # 前台启动（Ctrl+C 停止）
#   ./scripts/start.sh -d       # 后台启动（日志写入 /tmp/workbuddy-connector.log）
#
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAR="$PROJECT_DIR/target/workbuddy-connector-1.0.0.jar"
LOG="/tmp/workbuddy-connector.log"

if [ ! -f "$JAR" ]; then
  echo "未找到 $JAR，先执行构建：mvn clean package"
  exit 1
fi

# 端口 3100 若被占用，先停掉旧实例，避免连不上
if lsof -nP -iTCP:3100 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "端口 3100 已被占用，停止旧实例..."
  pkill -f "workbuddy-connector-1.0.0.jar" || true
  sleep 2
fi

if [ "${1:-}" = "-d" ]; then
  nohup java -jar "$JAR" > "$LOG" 2>&1 &
  echo "已在后台启动 (PID $!)，日志：$LOG"
  echo "等待就绪..."
  for _ in $(seq 1 40); do
    if curl -s --noproxy '*' -m 2 http://127.0.0.1:3100/__capture/health 2>/dev/null | grep -q '"status"'; then
      echo "服务已就绪：http://localhost:3100/mcp"
      echo
      echo "  调试端点：curl http://localhost:3100/__capture/whoami"
      echo "  OAuth 登录页：http://localhost:3100/oauth/authorize?client_id=x&redirect_uri=http://127.0.0.1:3100/cb&code_challenge=abc"
      exit 0
    fi
    sleep 1
  done
  echo "启动超时，请查看日志：$LOG"
  exit 1
else
  echo "前台启动中（Ctrl+C 停止）..."
  exec java -jar "$JAR"
fi