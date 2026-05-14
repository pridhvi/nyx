#!/usr/bin/env sh
set -eu

image="${NOX_DOCKER_IMAGE:-nox:smoke}"
container="${NOX_DOCKER_CONTAINER:-nox-smoke}"
port="${NOX_DOCKER_PORT:-18080}"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker build -t "$image" .
cleanup
docker run -d --name "$container" -p "127.0.0.1:${port}:8080" "$image" >/dev/null

deadline=$((SECONDS + 45))
while [ "$SECONDS" -lt "$deadline" ]; do
  if curl -fsS "http://127.0.0.1:${port}/api/health" >/dev/null; then
    docker exec "$container" nox version
    curl -fsS "http://127.0.0.1:${port}/api/tools" >/dev/null
    echo "Docker smoke passed on http://127.0.0.1:${port}"
    exit 0
  fi
  sleep 1
done

docker logs "$container" >&2 || true
echo "Docker smoke failed: health endpoint did not become ready" >&2
exit 1
