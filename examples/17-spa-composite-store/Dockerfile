# Build the OP example binary inside an isolated builder stage. The
# build context MUST be the repository root because the example
# sub-module's go.mod uses `replace` directives that point at sibling
# directories (../.., ../internal/rpkit, ../../op/storeadapter/{sql,redis}).
#
# The compose.yaml in this directory sets `build.context: ../..` so a
# plain `docker compose up --build` from this folder picks up the
# whole tree.

FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
WORKDIR /src/examples/17-spa-composite-store
RUN CGO_ENABLED=0 go build -tags example -trimpath -ldflags="-s -w" -o /op-example .

# Runtime image: distroless static carries only ca-certificates and
# /etc/passwd, which is everything a statically linked Go binary needs.
#
# The SPA bundle has to come along. op.WithSPAUI serves StaticDir from
# disk at request time rather than embedding it, so the binary alone
# would start and then fail its own StaticDir check.
#
# The bundle is shared with every other SPA example and lives at
# examples/internal/webui, which the example reaches through the
# relative path webui.StaticDir. The layout below reproduces that one
# relationship — the example's working directory beside an internal/
# sibling — so the same path resolves in the image as in a checkout.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app/17-spa-composite-store
COPY --from=builder /op-example /app/17-spa-composite-store/op-example
COPY --from=builder /src/examples/internal/webui/static /app/internal/webui/static
EXPOSE 8080 9090
USER nonroot:nonroot
ENTRYPOINT ["/app/17-spa-composite-store/op-example"]
