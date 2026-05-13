FROM node:20-alpine AS frontend
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS backend
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/internal/api/web/dist ./internal/api/web/dist
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/nox .

FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
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

RUN useradd --create-home --shell /usr/sbin/nologin nox \
  && mkdir -p /home/nox/.nox \
  && chown -R nox:nox /home/nox/.nox
USER nox
WORKDIR /home/nox
COPY --from=backend /out/nox /usr/local/bin/nox
EXPOSE 8080
ENTRYPOINT ["nox"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
