# Build the reference application inside an isolated builder stage. The
# build context MUST be the repository root: this module's go.mod uses
# `replace` directives pointing at sibling directories (.., and
# ../op/storeadapter/{sql,redis}), so a context rooted at sample/ would not
# see them.
#
# compose.yaml sets `build.context: ..`, so `docker compose -f
# sample/compose.yaml up --build` picks up the whole tree.

FROM golang:1.27-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /src
COPY . .
WORKDIR /src/sample
RUN CGO_ENABLED=0 go build -tags example -trimpath -ldflags="-s -w" -o /sample .

# Runtime image: distroless static carries ca-certificates and /etc/passwd,
# which is all a statically linked Go binary needs.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /sample /sample
EXPOSE 8080 9090
USER nonroot:nonroot
ENTRYPOINT ["/sample"]
