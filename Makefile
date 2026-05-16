.PHONY: build ci dev test test-integration tool-version-smoke lint web web-build run sqlc migrate-up docker-smoke compose-config clean release-snapshot

build:
	cd web && npm run build
	go build -o bin/nox .

ci: test web build compose-config

dev:
	@echo "Starting Nox API on http://127.0.0.1:6767"
	go run . serve --host 127.0.0.1 --port 6767

test:
	go test ./...

test-integration:
	./scripts/integration-smoke.sh

tool-version-smoke:
	./scripts/tool-version-smoke.sh host

lint:
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run; else echo "golangci-lint not installed; skipping Go lint"; fi
	cd web && npm run build

web:
	cd web && npm run build

web-build: web

run:
	go run . serve

sqlc:
	@if command -v sqlc >/dev/null 2>&1; then sqlc generate; else echo "sqlc not installed; handwritten store is currently used"; fi

migrate-up:
	@echo "SQLite migrations are embedded and run automatically when sessions open."
	go test ./internal/db

docker-smoke:
	./scripts/docker-smoke.sh

compose-config:
	NOX_API_KEY=nox-compose-config docker compose config >/dev/null

clean:
	rm -rf bin coverage web/dist

release-snapshot:
	@if command -v goreleaser >/dev/null 2>&1; then goreleaser release --snapshot --clean; else echo "goreleaser not installed; install goreleaser to build release artifacts"; fi
