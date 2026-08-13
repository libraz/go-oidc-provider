# Build the OP example binary inside an isolated builder stage. The
# build context MUST be the repository root because the example
# sub-module's go.mod uses `replace` directives that point at sibling
# directories (../.., ../internal/rpkit, ../../op/storeadapter/{sql,redis}).
#
# The compose.yaml in this directory sets `build.context: ../..` so a
# plain `docker compose up --build` from this folder picks up the
# whole tree.

FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
WORKDIR /src/examples/09-redis-volatile
RUN CGO_ENABLED=0 go build -tags example -trimpath -ldflags="-s -w" -o /op-example .

# Runtime image: distroless static carries only ca-certificates and
# /etc/passwd, which is everything a statically linked Go binary needs.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /op-example /op-example
EXPOSE 8080 9090
USER nonroot:nonroot
ENTRYPOINT ["/op-example"]
