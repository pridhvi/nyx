FROM golang:1.26-alpine AS backend
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go build -o /out/nox .

FROM alpine:3.20
RUN adduser -D nox
USER nox
WORKDIR /app
COPY --from=backend /out/nox /usr/local/bin/nox
EXPOSE 8080
ENTRYPOINT ["nox"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
