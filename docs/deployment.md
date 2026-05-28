# Nyx Deployment Notes

## Docker

Build and run the container locally:

```sh
docker build -t nyx:local .
NYX_API_KEY=$(openssl rand -hex 24)
docker run --rm -p 127.0.0.1:8080:8080 -e NYX_API_KEY="$NYX_API_KEY" -v nyx-data:/home/nyx/.nyx nyx:local serve --host 0.0.0.0 --port 8080
curl -H "X-Nyx-API-Key: $NYX_API_KEY" http://127.0.0.1:8080/api/health
```

The web console prompts for the same API key when auth is enabled and stores only an opaque HttpOnly session cookie. Do not put API keys in URLs; query-string API keys are rejected.

Run the packaged smoke check:

```sh
make docker-smoke
```

The image uses a pinned Debian 13 slim runtime digest, enables Debian's non-free
component for `nikto`, and installs the baseline scanner set documented in the
README. The smoke check builds the image, starts Nyx, verifies `/api/health`,
verifies `/api/tools`, runs `nyx version`, and checks bundled scanner versions
inside the container.

## Compose

`docker-compose.yml` starts Nyx and Ollama with persistent volumes:

```sh
export NYX_API_KEY=$(openssl rand -hex 24)
docker compose up --build
```

Compose publishes Nyx on `127.0.0.1:6767` and requires `NYX_API_KEY`. Nyx refuses to bind to non-loopback interfaces without an API key.

For containerized custom config, create a config file and mount it at
`/home/nyx/.nyx/config.yaml`:

```sh
mkdir -p config
nyx config init --path config/nyx.yaml
docker run --rm -p 127.0.0.1:8080:8080 \
  -e NYX_API_KEY="$NYX_API_KEY" \
  -v nyx-data:/home/nyx/.nyx \
  -v "$PWD/config/nyx.yaml:/config/nyx.yaml:ro" \
  nyx:local serve --config /config/nyx.yaml --host 0.0.0.0 --port 8080
```

LLM settings can be provided through the config file or environment variables:

```yaml
llm:
  enabled: true
  provider: openai-compatible
  base_url: http://ollama:11434/v1
  model: llama3:8b
```

For tighter host deployments, constrain source scans and every LLM endpoint
that can initiate outbound model traffic:

```sh
export NYX_SOURCE_ROOTS=/srv/audits,/work/repos
export NYX_LLM_ALLOWED_HOSTS=127.0.0.1,localhost,ollama,10.0.0.100
export NYX_SECURE_COOKIES=true
```

Private, loopback, link-local, multicast, unspecified, and metadata-service LLM
endpoints are blocked unless their host is explicitly included in
`NYX_LLM_ALLOWED_HOSTS`. Use `NYX_SECURE_COOKIES=true` or
`server.secure_cookies: true` for HTTPS reverse-proxy deployments so the
browser login cookie always carries the `Secure` flag.

Single-binary local mode remains supported. Optional external tools degrade
gracefully when they are not installed.

## Release Snapshots

Use:

```sh
make release-snapshot
```

The snapshot release runs the frontend build before compiling binaries so the
embedded UI is included in release artifacts.
