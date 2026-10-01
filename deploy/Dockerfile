FROM public.ecr.aws/docker/library/golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS build
WORKDIR /source
ENV GOTOOLCHAIN=local
ARG GOPROXY=https://proxy.golang.org,direct
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
COPY api/sensor ./api/sensor
ARG STARBEACON_ROLE=starbeacon
ARG VERSION=dev
ARG COMMIT=unknown
ARG TARGETOS=linux
ARG TARGETARCH
RUN case "$STARBEACON_ROLE" in starbeacon|starbeacon-ingest|starbeacon-worker|starbeacon-agent|starbeaconctl) ;; *) exit 1 ;; esac && \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath \
    -ldflags "-X github.com/kkx600/StarBeacon/internal/buildinfo.Version=$VERSION -X github.com/kkx600/StarBeacon/internal/buildinfo.Commit=$COMMIT" \
    -o /runtime/starbeacon "./cmd/$STARBEACON_ROLE" && \
    mkdir -p /runtime/state && touch /runtime/state/.keep

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /runtime/state /var/lib/starbeacon
COPY --from=build /runtime/starbeacon /app/starbeacon
USER 65532:65532
WORKDIR /app
ENTRYPOINT ["/app/starbeacon"]
