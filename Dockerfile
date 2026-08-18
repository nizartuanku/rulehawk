# RuleHawk — minimal production image.
# Build:  docker build -t rulehawk .
# Run:    docker run -d -p 127.0.0.1:8426:8426 -v rulehawk-data:/data rulehawk

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO is required by the mattn/go-sqlite3 driver used in this build.
ARG ISSUER_PUBKEY=""
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.issuerPublicKeyB64=${ISSUER_PUBKEY}" \
    -o /out/rulehawk ./cmd/rulehawk

FROM debian:bookworm-slim
RUN useradd -r -u 10001 rulehawk \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/rulehawk /usr/local/bin/rulehawk
USER rulehawk
VOLUME /data
EXPOSE 8426
ENTRYPOINT ["rulehawk", "-listen", "0.0.0.0:8426", "-db", "/data/rulehawk.db", "-license", "/data/rulehawk-license.key"]
