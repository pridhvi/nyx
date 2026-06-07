#!/usr/bin/env sh
set -eu

command_name="${1:-up}"
target_filter="${2:-all}"

dvwa_name="${NYX_BENCHMARK_DVWA_CONTAINER:-nyx-benchmark-dvwa}"
juice_name="${NYX_BENCHMARK_JUICE_CONTAINER:-nyx-benchmark-juice-shop}"
crapi_project="${NYX_BENCHMARK_CRAPI_PROJECT:-nyx-benchmark-crapi}"
benchmark_name="${NYX_BENCHMARK_OWASP_BENCHMARK_CONTAINER:-nyx-benchmark-owasp-benchmark}"
dvga_name="${NYX_BENCHMARK_DVGA_CONTAINER:-nyx-benchmark-dvga}"
webgoat_name="${NYX_BENCHMARK_WEBGOAT_CONTAINER:-nyx-benchmark-webgoat}"
nodegoat_name="${NYX_BENCHMARK_NODEGOAT_CONTAINER:-nyx-benchmark-nodegoat}"
dvwa_port="${NYX_BENCHMARK_DVWA_PORT:-18080}"
juice_port="${NYX_BENCHMARK_JUICE_PORT:-13000}"
crapi_port="${NYX_BENCHMARK_CRAPI_PORT:-8888}"
crapi_https_port="${NYX_BENCHMARK_CRAPI_HTTPS_PORT:-8443}"
crapi_mail_port="${NYX_BENCHMARK_CRAPI_MAIL_PORT:-8025}"
benchmark_port="${NYX_BENCHMARK_OWASP_BENCHMARK_PORT:-18443}"
dvga_port="${NYX_BENCHMARK_DVGA_PORT:-15013}"
webgoat_port="${NYX_BENCHMARK_WEBGOAT_PORT:-18088}"
webwolf_port="${NYX_BENCHMARK_WEBWOLF_PORT:-19090}"
nodegoat_port="${NYX_BENCHMARK_NODEGOAT_PORT:-14000}"
dvwa_url="${NYX_BENCHMARK_DVWA_URL:-http://127.0.0.1:$dvwa_port}"
juice_url="${NYX_BENCHMARK_JUICE_URL:-http://127.0.0.1:$juice_port}"
crapi_url="${NYX_BENCHMARK_CRAPI_URL:-http://127.0.0.1:$crapi_port}"
benchmark_url="${NYX_BENCHMARK_OWASP_BENCHMARK_URL:-https://127.0.0.1:$benchmark_port/benchmark}"
dvga_url="${NYX_BENCHMARK_DVGA_URL:-http://127.0.0.1:$dvga_port}"
webgoat_url="${NYX_BENCHMARK_WEBGOAT_URL:-http://127.0.0.1:$webgoat_port/WebGoat}"
nodegoat_url="${NYX_BENCHMARK_NODEGOAT_URL:-http://127.0.0.1:$nodegoat_port}"
crapi_dir="${NYX_BENCHMARK_CRAPI_DIR:-$HOME/.cache/nyx/benchmarks/crapi}"

require_docker() {
  command -v docker >/dev/null 2>&1 || {
    echo "docker is required for benchmark targets" >&2
    exit 1
  }
}

wait_url() {
  url="$1"
  label="$2"
  curl_flags="${3:-}"
  attempts="${4:-90}"
  i=0
  # shellcheck disable=SC2086
  until curl $curl_flags -fsS "$url" >/dev/null 2>&1 || [ "$i" -ge "$attempts" ]; do
    i=$((i + 1))
    sleep 2
  done
  if [ "$i" -ge "$attempts" ]; then
    echo "$label did not become ready at $url" >&2
    docker ps -a --filter "name=$label" >&2 || true
    exit 1
  fi
}

compose_bin() {
  if docker compose version >/dev/null 2>&1; then
    printf '%s' "docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    printf '%s' "docker-compose"
  else
    echo "docker compose is required for crAPI benchmark target" >&2
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
      -e NODE_OPTIONS="${NYX_BENCHMARK_JUICE_NODE_OPTIONS:---max-old-space-size=8192}" \
      -p "127.0.0.1:$juice_port:3000" \
      bkimminich/juice-shop >/dev/null
  fi
  wait_url "$juice_url" "$juice_name"
}

prepare_crapi_compose() {
  if [ -f "$crapi_dir/deploy/docker/docker-compose.yml" ]; then
    return
  fi
  mkdir -p "$crapi_dir"
  tmp_zip="$crapi_dir/crapi.zip"
  curl -fsSL -o "$tmp_zip" "${NYX_BENCHMARK_CRAPI_ZIP_URL:-https://github.com/OWASP/crAPI/archive/refs/heads/main.zip}"
  python3 - "$tmp_zip" "$crapi_dir" <<'PY'
import shutil
import sys
import zipfile
from pathlib import Path

archive = Path(sys.argv[1])
dest = Path(sys.argv[2])
for child in dest.iterdir():
    if child.name == archive.name:
        continue
    if child.is_dir():
        shutil.rmtree(child)
    else:
        child.unlink()
with zipfile.ZipFile(archive) as zf:
    zf.extractall(dest)
roots = [p for p in dest.iterdir() if p.is_dir() and (p / "deploy/docker/docker-compose.yml").exists()]
if not roots:
    raise SystemExit("downloaded crAPI archive did not contain deploy/docker/docker-compose.yml")
source = roots[0]
for child in source.iterdir():
    target = dest / child.name
    if target.exists():
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    shutil.move(str(child), str(target))
shutil.rmtree(source)
PY
}

start_or_create_crapi() {
  prepare_crapi_compose
  python3 - "$crapi_dir/deploy/docker/docker-compose.yml" "$crapi_port" "$crapi_https_port" "$crapi_mail_port" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
http_port, https_port, mail_port = sys.argv[2:5]
text = path.read_text(encoding="utf-8")
text = re.sub(r'(\$\{LISTEN_IP:-127\.0\.0\.1\}:)\d+(:80")', rf'\g<1>{http_port}\g<2>', text, count=1)
text = re.sub(r'(\$\{LISTEN_IP:-127\.0\.0\.1\}:)\d+(:443")', rf'\g<1>{https_port}\g<2>', text, count=1)
text = re.sub(r'(\$\{LISTEN_IP:-127\.0\.0\.1\}:)\d+(:8025")', rf'\g<1>{mail_port}\g<2>', text, count=1)
path.write_text(text, encoding="utf-8")
PY
  compose="$(compose_bin)"
  (
    cd "$crapi_dir/deploy/docker"
    LISTEN_IP=127.0.0.1 \
      $compose -p "$crapi_project" -f docker-compose.yml --compatibility up -d
  )
  wait_url "$crapi_url" "$crapi_project"
}

start_or_create_owasp_benchmark() {
  if container_running "$benchmark_name"; then
    :
  else
    if container_exists "$benchmark_name"; then
      docker rm "$benchmark_name" >/dev/null
    fi
    docker run -d --name "$benchmark_name" \
      -p "127.0.0.1:$benchmark_port:8443" \
      owasp/benchmark \
      /bin/bash -lc 'cd /owasp/BenchmarkJava && exec ./runRemoteAccessibleBenchmark.sh -q' >/dev/null
  fi
  wait_url "$benchmark_url" "$benchmark_name" "-k" "${NYX_BENCHMARK_OWASP_BENCHMARK_WAIT_ATTEMPTS:-240}"
}

start_or_create_dvga() {
  if container_exists "$dvga_name"; then
    docker start "$dvga_name" >/dev/null
  else
    docker run -d --name "$dvga_name" -p "127.0.0.1:$dvga_port:5013" -e WEB_HOST=0.0.0.0 dolevf/dvga >/dev/null
  fi
  wait_url "$dvga_url" "$dvga_name"
}

start_or_create_webgoat() {
  if container_exists "$webgoat_name"; then
    docker start "$webgoat_name" >/dev/null
  else
    docker run -d --name "$webgoat_name" \
      -p "127.0.0.1:$webgoat_port:8080" \
      -p "127.0.0.1:$webwolf_port:9090" \
      webgoat/webgoat >/dev/null
  fi
  wait_url "$webgoat_url" "$webgoat_name"
}

start_or_create_nodegoat() {
  if container_exists "$nodegoat_name"; then
    docker start "$nodegoat_name" >/dev/null
  else
    docker run -d --name "$nodegoat_name" -p "127.0.0.1:$nodegoat_port:4000" nirocr/nodegoat >/dev/null
  fi
  wait_url "$nodegoat_url" "$nodegoat_name"
}

status() {
  docker ps -a --filter "name=nyx-benchmark-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  for url in "$dvwa_url" "$juice_url" "$crapi_url" "$benchmark_url" "$dvga_url" "$webgoat_url" "$nodegoat_url"; do
    if printf '%s' "$url" | grep -q '^https:'; then
      code="$(curl -k -m 2 -s -o /dev/null -w '%{http_code}' "$url/" || true)"
    else
      code="$(curl -m 2 -s -o /dev/null -w '%{http_code}' "$url/" || true)"
    fi
    echo "$url status=$code"
  done
}

require_docker

start_selected() {
  case "$target_filter" in
    all)
      start_or_create_dvwa
      start_or_create_juice
      start_or_create_crapi
      start_or_create_owasp_benchmark
      start_or_create_dvga
      start_or_create_webgoat
      start_or_create_nodegoat
      ;;
    dvwa)
      start_or_create_dvwa
      ;;
    juice|juice-shop)
      start_or_create_juice
      ;;
    crapi)
      start_or_create_crapi
      ;;
    benchmark|owasp-benchmark)
      start_or_create_owasp_benchmark
      ;;
    dvga)
      start_or_create_dvga
      ;;
    webgoat)
      start_or_create_webgoat
      ;;
    nodegoat)
      start_or_create_nodegoat
      ;;
    *)
      echo "unknown benchmark target $target_filter" >&2
      exit 2
      ;;
  esac
}

down_selected() {
  case "$target_filter" in
    all)
      if [ -f "$crapi_dir/deploy/docker/docker-compose.yml" ]; then
        compose="$(compose_bin)"
        (cd "$crapi_dir/deploy/docker" && $compose -p "$crapi_project" -f docker-compose.yml down >/dev/null 2>&1) || true
      fi
      docker rm -f "$dvwa_name" "$juice_name" "$benchmark_name" "$dvga_name" "$webgoat_name" "$nodegoat_name" >/dev/null 2>&1 || true
      ;;
    dvwa)
      docker rm -f "$dvwa_name" >/dev/null 2>&1 || true
      ;;
    juice|juice-shop)
      docker rm -f "$juice_name" >/dev/null 2>&1 || true
      ;;
    crapi)
      if [ -f "$crapi_dir/deploy/docker/docker-compose.yml" ]; then
        compose="$(compose_bin)"
        (cd "$crapi_dir/deploy/docker" && $compose -p "$crapi_project" -f docker-compose.yml down >/dev/null 2>&1) || true
      fi
      ;;
    benchmark|owasp-benchmark)
      docker rm -f "$benchmark_name" >/dev/null 2>&1 || true
      ;;
    dvga)
      docker rm -f "$dvga_name" >/dev/null 2>&1 || true
      ;;
    webgoat)
      docker rm -f "$webgoat_name" >/dev/null 2>&1 || true
      ;;
    nodegoat)
      docker rm -f "$nodegoat_name" >/dev/null 2>&1 || true
      ;;
    *)
      echo "unknown benchmark target $target_filter" >&2
      exit 2
      ;;
  esac
}

case "$command_name" in
  up)
    start_selected
    status
    ;;
  down)
    down_selected
    ;;
  reset)
    "$0" down "$target_filter"
    start_selected
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
    if ! container_running "$benchmark_name"; then
      echo "warning: $benchmark_name is not running" >&2
    fi
    if ! container_running "$dvga_name"; then
      echo "warning: $dvga_name is not running" >&2
    fi
    if ! container_running "$webgoat_name"; then
      echo "warning: $webgoat_name is not running" >&2
    fi
    if ! container_running "$nodegoat_name"; then
      echo "warning: $nodegoat_name is not running" >&2
    fi
    echo "DVWA=$dvwa_url"
    echo "JUICE_SHOP=$juice_url"
    echo "CRAPI=$crapi_url"
    echo "OWASP_BENCHMARK=$benchmark_url"
    echo "DVGA=$dvga_url"
    echo "WEBGOAT=$webgoat_url"
    echo "NODEGOAT=$nodegoat_url"
    ;;
  *)
    echo "usage: $0 {up|down|reset|status|urls} [all|dvwa|juice-shop|crapi|owasp-benchmark|dvga|webgoat|nodegoat]" >&2
    exit 2
    ;;
esac
