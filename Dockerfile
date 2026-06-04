FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS frontend
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS backend
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/internal/api/web/dist ./internal/api/web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/nyx .

FROM debian:13-slim@sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8
ENV DEBIAN_FRONTEND=noninteractive
RUN if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i 's/Components: main/Components: main contrib non-free non-free-firmware/g' /etc/apt/sources.list.d/debian.sources; \
    fi \
  && apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    dnsutils \
    ffuf \
    nikto \
    nmap \
    python3 \
    python3-pip \
    sqlmap \
    whatweb \
    whois \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /usr/sbin/nologin nyx \
  && mkdir -p /home/nyx/.nyx \
  && chown -R nyx:nyx /home/nyx/.nyx
USER nyx
WORKDIR /home/nyx
COPY --from=backend /out/nyx /usr/local/bin/nyx
COPY scripts/tool-version-smoke.sh /usr/local/bin/nyx-tool-version-smoke
EXPOSE 6767
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD sh -c 'curl -fsS ${NYX_API_KEY:+-H "X-Nyx-API-Key: $NYX_API_KEY"} http://127.0.0.1:6767/api/health >/dev/null || exit 1'
ENTRYPOINT ["nyx"]
CMD ["serve", "--host", "0.0.0.0", "--port", "6767"]
