#!/usr/bin/env bash
# Laptop-hosted engine for owlx: control service + mitmproxy, talking to
# frida-server on the rooted tablet over the LAN.
#
# Configuration is entirely through the environment (see also engine.env):
#   TABLET_IP, FRIDA_PORT, OWLX_HOST, OWLX_PORT, OWLX_MITM, OWLX_MITM_PORT,
#   OWLX_FRIDA_TIMEOUT, OWLX_HEALTH_TIMEOUT, OWLX_STOP_TIMEOUT, OWLX_ROOT,
#   OWLX_TOKEN_FILE, OWLX_TOKEN, OWLX_RUN_DIR
set -euo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="${OWLX_ROOT:-$(cd -- "$HERE/.." && pwd -P)}"
SERVICE="$ROOT/phone/owlx_service.py"
CLI="$ROOT/nixos/owlx.py"

RUN_DIR="${OWLX_RUN_DIR:-$HOME/.local/state/owlx}"
TOKEN_FILE="${OWLX_TOKEN_FILE:-$HOME/.config/owlx/token}"
TABLET_IP="${TABLET_IP:-10.10.10.119}"
FRIDA_PORT="${FRIDA_PORT:-27042}"
OWLX_HOST="${OWLX_HOST:-0.0.0.0}"
OWLX_PORT="${OWLX_PORT:-8787}"
MITM_PORT="${OWLX_MITM_PORT:-${MITM_PORT:-8080}}"
START_MITM="${OWLX_MITM:-1}"
FRIDA_TIMEOUT="${OWLX_FRIDA_TIMEOUT:-10}"
HEALTH_TIMEOUT="${OWLX_HEALTH_TIMEOUT:-30}"
STOP_TIMEOUT="${OWLX_STOP_TIMEOUT:-10}"
DEVICE="remote:${TABLET_IP}:${FRIDA_PORT}"
PID_FILE="$RUN_DIR/service.pid"
LOG_FILE="$RUN_DIR/service.log"
PID_MARKER="owlx-service"

mkdir -p "$RUN_DIR"

die() { echo "owlx: $*" >&2; exit 2; }

valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_int() { [[ "$1" =~ ^[0-9]+$ ]]; }
valid_number() { [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ ]]; }

validate_config() {
  [[ -f "$SERVICE" ]] || die "missing $SERVICE (set OWLX_ROOT to the checkout)"
  [[ -f "$CLI" ]] || die "missing $CLI (set OWLX_ROOT to the checkout)"
  command -v python3 >/dev/null || die "python3 is required"
  command -v curl >/dev/null || die "curl is required"
  valid_port "$FRIDA_PORT" || die "FRIDA_PORT must be 1..65535"
  valid_port "$OWLX_PORT" || die "OWLX_PORT must be 1..65535"
  valid_port "$MITM_PORT" || die "OWLX_MITM_PORT must be 1..65535"
  valid_number "$FRIDA_TIMEOUT" || die "OWLX_FRIDA_TIMEOUT must be a number"
  valid_int "$HEALTH_TIMEOUT" || die "OWLX_HEALTH_TIMEOUT must be whole seconds"
  valid_int "$STOP_TIMEOUT" || die "OWLX_STOP_TIMEOUT must be whole seconds"
}

load_token() {
  if [[ -z "${OWLX_TOKEN:-}" && -r "$TOKEN_FILE" ]]; then
    OWLX_TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
    local mode
    mode="$(stat -c '%a' "$TOKEN_FILE" 2>/dev/null || true)"
    if [[ "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 077) != 0 )); then
      echo "owlx: warning: $TOKEN_FILE is mode $mode; chmod 600 it" >&2
    fi
  fi
  [[ -n "${OWLX_TOKEN:-}" ]] || die "set OWLX_TOKEN or write a token to $TOKEN_FILE (chmod 600)"
  export OWLX_TOKEN OWLX_TOKEN_FILE="$TOKEN_FILE" OWLX_FRIDA_TIMEOUT="$FRIDA_TIMEOUT"
}

cli() { python3 "$CLI" --url "http://127.0.0.1:$OWLX_PORT" "$@"; }

# A pid file is only trusted if it has our marker, the process is alive and
# /proc says it is still the owlx service (PIDs get recycled).
running_pid() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid marker
  { read -r pid marker; } < "$PID_FILE" || { rm -f "$PID_FILE"; return 1; }
  if [[ ! "$pid" =~ ^[0-9]+$ || "$marker" != "$PID_MARKER" ]] || (( pid <= 1 )); then
    echo "owlx: ignoring stale pid file $PID_FILE" >&2
    rm -f "$PID_FILE"
    return 1
  fi
  kill -0 "$pid" 2>/dev/null || { rm -f "$PID_FILE"; return 1; }
  if [[ -r "/proc/$pid/cmdline" ]]; then
    if ! tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q 'owlx_service.py'; then
      echo "owlx: pid $pid is not an owlx service; clearing stale pid file" >&2
      rm -f "$PID_FILE"
      return 1
    fi
  fi
  printf '%s\n' "$pid"
}

write_pid() { printf '%s %s\n' "$1" "$PID_MARKER" > "$PID_FILE"; }

lan_ip() {
  local ip=""
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); if (a[1] != "" && a[1] != "127.0.0.1") {print a[1]; exit}}')"
  fi
  if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i != "127.0.0.1") {print $i; exit}}')"
  fi
  printf '%s\n' "$ip"
}

dashboard_url() {
  local ip
  ip="$(lan_ip)"
  printf 'http://%s:%s' "${ip:-<laptop-ip>}" "$OWLX_PORT"
}

wait_health() {
  local pid="$1" i=0 max=$(( HEALTH_TIMEOUT * 5 ))
  while (( i < max )); do
    if curl -fsS "http://127.0.0.1:$OWLX_PORT/healthz" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "owlx: service exited during startup; see $LOG_FILE" >&2
      tail -n 20 "$LOG_FILE" >&2 2>/dev/null || true
      return 1
    fi
    i=$((i + 1))
    sleep 0.2
  done
  echo "owlx: no /healthz after ${HEALTH_TIMEOUT}s; see $LOG_FILE" >&2
  tail -n 20 "$LOG_FILE" >&2 2>/dev/null || true
  return 1
}

start() {
  load_token
  local pid
  if pid="$(running_pid)"; then
    echo "engine already running (pid $pid); device $DEVICE"
    status || true
    return 0
  fi
  echo "starting engine: device $DEVICE, listen ${OWLX_HOST}:${OWLX_PORT}, dashboard $(dashboard_url)"
  nohup python3 "$SERVICE" --host "$OWLX_HOST" --port "$OWLX_PORT" \
    --device "$DEVICE" --frida-timeout "$FRIDA_TIMEOUT" \
    >>"$LOG_FILE" 2>&1 </dev/null &
  pid=$!
  write_pid "$pid"
  if ! wait_health "$pid"; then
    kill "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    return 1
  fi
  if [[ "$START_MITM" == "1" ]]; then
    if ! cli mitm start --port "$MITM_PORT" >>"$LOG_FILE" 2>&1; then
      echo "owlx: mitmproxy did not start; use 'nixos/owlx.py mitm start' later (see $LOG_FILE)" >&2
    fi
  fi
  status || true
}

stop() {
  local pid
  if ! pid="$(running_pid)"; then
    rm -f "$PID_FILE"
    echo "engine not running"
    return 0
  fi
  if [[ -n "${OWLX_TOKEN:-}" || -r "$TOKEN_FILE" ]]; then
    load_token
    cli mitm stop >/dev/null 2>&1 || true
  else
    echo "owlx: no token; the service will still clean up its mitmproxy child" >&2
  fi
  kill -TERM "$pid" 2>/dev/null || true
  local i=0 max=$(( STOP_TIMEOUT * 5 ))
  while (( i < max )) && kill -0 "$pid" 2>/dev/null; do
    i=$((i + 1))
    sleep 0.2
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "owlx: service did not stop in ${STOP_TIMEOUT}s; sending SIGKILL" >&2
    kill -KILL "$pid" 2>/dev/null || true
    sleep 0.2
  fi
  rm -f "$PID_FILE"
  echo "engine stopped (pid $pid)"
}

status() {
  local pid
  if ! pid="$(running_pid)"; then
    echo "engine stopped"
    return 1
  fi
  echo "engine pid $pid | device $DEVICE | listen ${OWLX_HOST}:${OWLX_PORT} | mitm ${START_MITM}"
  echo "dashboard base: $(dashboard_url)"
  if [[ -z "${OWLX_TOKEN:-}" && ! -r "$TOKEN_FILE" ]]; then
    echo "owlx: no token; set OWLX_TOKEN or create $TOKEN_FILE" >&2
    return 1
  fi
  load_token
  cli status || return 1
}

foreground() {
  load_token
  echo "engine foreground: device $DEVICE, listen ${OWLX_HOST}:${OWLX_PORT}" >&2
  echo "dashboard base: $(dashboard_url)" >&2
  exec python3 "$SERVICE" --host "$OWLX_HOST" --port "$OWLX_PORT" \
    --device "$DEVICE" --frida-timeout "$FRIDA_TIMEOUT"
}

main() {
  validate_config
  case "${1:-status}" in
    start)     start ;;
    stop)      stop ;;
    restart)   stop || true; start ;;
    status)    status ;;
    foreground) foreground ;;
    *) echo "usage: $0 {start|stop|restart|status|foreground}" >&2; exit 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
