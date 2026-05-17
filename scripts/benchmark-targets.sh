#!/usr/bin/env sh
set -eu

command_name="${1:-up}"

dvwa_name="${NOX_BENCHMARK_DVWA_CONTAINER:-nox-benchmark-dvwa}"
juice_name="${NOX_BENCHMARK_JUICE_CONTAINER:-nox-benchmark-juice-shop}"
dvwa_port="${NOX_BENCHMARK_DVWA_PORT:-18080}"
juice_port="${NOX_BENCHMARK_JUICE_PORT:-13000}"
dvwa_url="${NOX_BENCHMARK_DVWA_URL:-http://127.0.0.1:$dvwa_port}"
juice_url="${NOX_BENCHMARK_JUICE_URL:-http://127.0.0.1:$juice_port}"

require_docker() {
  command -v docker >/dev/null 2>&1 || {
    echo "docker is required for benchmark targets" >&2
    exit 1
  }
}

wait_url() {
  url="$1"
  label="$2"
  i=0
  until curl -fsS "$url" >/dev/null 2>&1 || [ "$i" -ge 90 ]; do
    i=$((i + 1))
    sleep 2
  done
  if [ "$i" -ge 90 ]; then
    echo "$label did not become ready at $url" >&2
    docker ps -a --filter "name=$label" >&2 || true
    exit 1
  fi
}

container_exists() {
  docker inspect "$1" >/dev/null 2>&1
}

container_running() {
  [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || echo false)" = "true" ]
}

start_or_create_dvwa() {
  if container_exists "$dvwa_name"; then
    docker start "$dvwa_name" >/dev/null
  else
    docker run -d --name "$dvwa_name" -p "127.0.0.1:$dvwa_port:80" vulnerables/web-dvwa >/dev/null
  fi
  wait_url "$dvwa_url" "$dvwa_name"
}

start_or_create_juice() {
  if container_exists "$juice_name"; then
    docker start "$juice_name" >/dev/null
  else
    docker run -d --name "$juice_name" \
      -e NODE_OPTIONS="${NOX_BENCHMARK_JUICE_NODE_OPTIONS:---max-old-space-size=8192}" \
      -p "127.0.0.1:$juice_port:3000" \
      bkimminich/juice-shop >/dev/null
  fi
  wait_url "$juice_url" "$juice_name"
}

status() {
  docker ps -a --filter "name=nox-benchmark-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  for url in "$dvwa_url" "$juice_url"; do
    code="$(curl -m 2 -s -o /dev/null -w '%{http_code}' "$url/" || true)"
    echo "$url status=$code"
  done
}

require_docker

case "$command_name" in
  up)
    start_or_create_dvwa
    start_or_create_juice
    status
    ;;
  down)
    docker rm -f "$dvwa_name" "$juice_name" >/dev/null 2>&1 || true
    ;;
  reset)
    docker rm -f "$dvwa_name" "$juice_name" >/dev/null 2>&1 || true
    start_or_create_dvwa
    start_or_create_juice
    status
    ;;
  status)
    status
    ;;
  urls)
    if ! container_running "$dvwa_name"; then
      echo "warning: $dvwa_name is not running" >&2
    fi
    if ! container_running "$juice_name"; then
      echo "warning: $juice_name is not running" >&2
    fi
    echo "DVWA=$dvwa_url"
    echo "JUICE_SHOP=$juice_url"
    ;;
  *)
    echo "usage: $0 {up|down|reset|status|urls}" >&2
    exit 2
    ;;
esac
