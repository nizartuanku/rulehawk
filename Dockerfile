# RuleHawk — minimal production image.
# Pull:  docker pull hexward/rulehawk:0.1.0   (linux/amd64, linux/arm64)
# Build: docker build -t hexward/rulehawk .
# Run:   docker run -d -p 127.0.0.1:8426:8426 -v rulehawk-data:/data hexward/rulehawk

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO is required by the mattn/go-sqlite3 driver used in this build.
# Deliberately empty for the public image: no issuer key means every licence
# reads as invalid, which is exactly what the free edition is. Licensed release
# builds pass the real public key here.
ARG ISSUER_PUBKEY=""
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.issuerPublicKeyB64=${ISSUER_PUBKEY}" \
    -o /out/rulehawk ./cmd/rulehawk

FROM debian:bookworm-slim
# /data is created and chowned here so a named volume inherits the app user's
# ownership. Without this the volume defaults to root:root and the unprivileged
# process cannot create its database.
RUN useradd -r -u 10001 rulehawk \
 && apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /data \
 && chown rulehawk:rulehawk /data
COPY --from=build /out/rulehawk /usr/local/bin/rulehawk
USER rulehawk
VOLUME /data
EXPOSE 8426
ENTRYPOINT ["rulehawk", "-listen", "0.0.0.0:8426", "-db", "/data/rulehawk.db", "-license", "/data/rulehawk-license.key"]
