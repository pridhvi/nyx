# Nox Deployment Notes

## Docker

Build and run the container locally:

```sh
docker build -t nox:local .
docker run --rm -p 127.0.0.1:8080:8080 -v nox-data:/home/nox/.nox nox:local
curl http://127.0.0.1:8080/api/health
```

Run the packaged smoke check:

```sh
make docker-smoke
```

The smoke check builds the image, starts Nox, verifies `/api/health`, verifies
`/api/tools`, and runs `nox version` inside the container.

## Compose

`docker-compose.yml` starts Nox and Ollama with persistent volumes:

```sh
docker compose up --build
```

For containerized custom config, create a config file and mount it at
`/home/nox/.nox/config.yaml`:

```sh
mkdir -p config
nox config init --path config/nox.yaml
docker run --rm -p 127.0.0.1:8080:8080 \
  -v nox-data:/home/nox/.nox \
  -v "$PWD/config/nox.yaml:/config/nox.yaml:ro" \
  nox:local serve --config /config/nox.yaml --host 0.0.0.0 --port 8080
```

LLM settings can be provided through the config file or environment variables:

```yaml
llm:
  enabled: true
  provider: openai-compatible
  base_url: http://ollama:11434/v1
  model: llama3:8b
```

Single-binary local mode remains supported. Optional external tools degrade
gracefully when they are not installed.

## Release Snapshots

Use:

```sh
make release-snapshot
```

The snapshot release runs the frontend build before compiling binaries so the
embedded UI is included in release artifacts.
