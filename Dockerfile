# Build stage: the module has no dependencies outside the standard library, so
# nothing here needs a proxy or a private registry to resolve.
FROM golang:1.22-alpine AS build

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

# The module depends on nothing outside the standard library, so there is no
# go.sum to copy and go mod download has nothing to fetch. The go.mod is still
# copied on its own so the dependency layer stays a separate cache entry, ready
# for the day a dependency is added.
COPY go.mod ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# CGO off produces a binary that runs on a base with no libc at all. The
# version is stamped rather than baked into the source so a released image
# reports the tag it was cut from.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/proxyjoss ./cmd/proxyjoss

# Runtime stage. The static distroless base carries the CA bundle the feed fetch
# over HTTPS needs, and nothing else: no shell, no package manager, no libc.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/proxyjoss /usr/local/bin/proxyjoss

# The defaults bind to loopback, which is unreachable from outside the container
# and is the single most common reason a freshly pulled image "starts" and then
# refuses every client. The image therefore ships container-appropriate defaults,
# each of which any environment variable can still override.
ENV PROXYJOSS_LISTEN_ADDR=0.0.0.0:8080 \
    PROXYJOSS_ADMIN_ADDR=0.0.0.0:9090 \
    PROXYJOSS_HEALTH_ENABLED=true \
    PROXYJOSS_LOG_FORMAT=json

EXPOSE 8080 9090

# No shell exists in this base, so the check is the binary asking its own status
# API. It reads PROXYJOSS_ADMIN_ADDR, so moving the API moves the check with it.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/proxyjoss", "healthcheck"]

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/proxyjoss"]
