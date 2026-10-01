GO ?= go
PROTOC ?= protoc
VERSION ?= dev
COMPOSE_FILES ?= -f deploy/compose.yaml
COMMIT := $(shell git rev-parse --short HEAD)
GOFLAGS := -trimpath
LDFLAGS := -X github.com/kkx600/StarBeacon/internal/buildinfo.Version=$(VERSION) -X github.com/kkx600/StarBeacon/internal/buildinfo.Commit=$(COMMIT)
export GOTOOLCHAIN := local

.PHONY: check-toolchain build test vet generate dev-init deps-up deps-stop db-init dev-cert dev-setup platform ingest worker collector web collector-web sample integration
check-toolchain:
	@$(GO) version | awk '$$3 == "go1.26.8" {ok=1} END {if(!ok){print "需要 Go 1.26.8；通过 GO=/绝对路径/go 指定已安装工具链";exit 1}}'
build: check-toolchain
	@mkdir -p bin
	@for name in starbeacon starbeacon-ingest starbeacon-worker starbeacon-agent starbeaconctl; do $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$$name ./cmd/$$name || exit 1; done
test: check-toolchain
	$(GO) test -race ./...
vet: check-toolchain
	$(GO) vet ./...
generate: check-toolchain
	@$(PROTOC) --version | awk '$$2 == "36.2" {ok=1} END {if(!ok){print "需要 protoc 36.2";exit 1}}'
	GOBIN=$(CURDIR)/.tools/bin $(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
	GOBIN=$(CURDIR)/.tools/bin $(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
	PATH=$(CURDIR)/.tools/bin:$$PATH $(PROTOC) -I api/proto --go_out=. --go_opt=module=github.com/kkx600/StarBeacon --go-grpc_out=. --go-grpc_opt=module=github.com/kkx600/StarBeacon api/proto/starbeacon/sensor/v1/sensor.proto
dev-init:
	python3 scripts/dev-init.py
deps-up:
	docker compose --env-file .local/compose.env $(COMPOSE_FILES) up -d --wait
deps-stop:
	docker compose --env-file .local/compose.env $(COMPOSE_FILES) stop
db-init: build
	python3 scripts/env-run.py .local/owner.env bin/starbeaconctl migrate
	python3 scripts/env-run.py .local/owner.env bin/starbeaconctl runtime-role
dev-cert: build
	@test -f .local/pki/ca.crt || bin/starbeaconctl dev-pki
dev-setup: build
	python3 scripts/dev-init.py
	$(MAKE) deps-up
	python3 scripts/env-run.py .local/owner.env bin/starbeaconctl migrate
	python3 scripts/env-run.py .local/owner.env bin/starbeaconctl runtime-role
	python3 scripts/env-run.py .local/owner.env bin/starbeaconctl bootstrap --if-missing
	@test -f .local/pki/ca.crt || bin/starbeaconctl dev-pki
	python3 scripts/provision-dev-agent.py
platform:
	python3 scripts/env-run.py .local/platform.env bin/starbeacon
ingest:
	python3 scripts/env-run.py .local/platform.env bin/starbeacon-ingest
worker:
	python3 scripts/env-run.py .local/platform.env bin/starbeacon-worker
collector:
	python3 scripts/env-run.py .local/collector.env bin/starbeacon-agent
web:
	pnpm --dir web --filter @starbeacon/platform dev
collector-web:
	pnpm --dir web --filter @starbeacon/collector dev
sample:
	python3 scripts/emit-eve-sample.py
integration: check-toolchain
	python3 scripts/run-integration.py $(GO)
