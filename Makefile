.PHONY: build ci dev test security-scan benchmark-summary-test test-integration power-integration browser-smoke tool-version-smoke linux-full-smoke benchmark-targets-up benchmark-targets-down benchmark-targets-status benchmark-dvwa benchmark-juice benchmark-all lint web web-build run sqlc migrate-up docker-smoke compose-config clean release-snapshot

build:
	cd web && npm run build
	go build -o bin/nyx .

ci: test web build compose-config

dev:
	@echo "Starting Nyx API on http://127.0.0.1:6767"
	go run . serve --host 127.0.0.1 --port 6767

test:
	go test ./...
	./scripts/benchmark-summary-test.py

security-scan:
	./scripts/security-scan.sh

benchmark-summary-test:
	./scripts/benchmark-summary-test.py

test-integration:
	./scripts/integration-smoke.sh

power-integration:
	./scripts/power-integration-smoke.sh

browser-smoke:
	./scripts/browser-smoke.sh

tool-version-smoke:
	./scripts/tool-version-smoke.sh host

linux-full-smoke:
	./scripts/linux-full-smoke.sh

benchmark-targets-up:
	./scripts/benchmark-targets.sh up

benchmark-targets-down:
	./scripts/benchmark-targets.sh down

benchmark-targets-status:
	./scripts/benchmark-targets.sh status

benchmark-dvwa:
	./scripts/benchmark-run.sh dvwa

benchmark-juice:
	./scripts/benchmark-run.sh juice-shop

benchmark-all:
	./scripts/benchmark-run.sh all

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
	NYX_API_KEY=nyx-compose-config docker compose config >/dev/null

clean:
	rm -rf bin coverage web/dist

release-snapshot:
	@if command -v goreleaser >/dev/null 2>&1; then goreleaser release --snapshot --clean; else echo "goreleaser not installed; install goreleaser to build release artifacts"; fi
