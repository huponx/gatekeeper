GO  ?= go
BIN ?= bin
IMAGE_TAG  ?= dev
IMAGE_REPO ?= ghcr.io/huponx

.PHONY: help tidy upgrade outdated routes descriptors test vet build run e2e docker clean

help:
	@printf '%s\n' \
		'tidy    go mod tidy' \
		'upgrade  upgrade the dependencies (PATCH=1: patch releases only), tidy, build and test' \
		'outdated  list the dependencies that have a newer version' \
		'routes  write routes.local.yaml (the chart routes with a local identity upstream)' \
		'descriptors  rebuild descriptors.binpb from ../protos (buf)' \
		'test    go test -race ./...' \
		'vet     go vet ./...' \
		'build   gatekeeper into $(BIN)/' \
		'run     go run ./cmd/gatekeeper (reads the environment, see .env.example)' \
		'e2e     scripts/e2e.sh against a real identity (../identity)' \
		'docker  build the image'

tidy:
	GOWORK=off $(GO) mod tidy

# Upgrade the dependencies to their latest minor/patch releases (PATCH=1: patch releases only), then tidy and
# check that everything still builds and passes. GOWORK=off: resolves against the module proxy, not the sibling
# folders of go.work. Review `git diff go.mod go.sum` before committing.
PATCH ?=
upgrade:
	GOWORK=off $(GO) get -u$(if $(PATCH),=patch) ./...
	GOWORK=off $(GO) mod tidy
	GOWORK=off $(GO) build ./...
	GOWORK=off $(GO) test ./...

# Lists the modules that have a newer version (nothing is changed).
outdated:
	@GOWORK=off $(GO) list -u -m -f '{{if and .Update (not .Indirect)}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' all

routes:
	scripts/routes.sh > routes.local.yaml

# descriptors.binpb describes the services the routes call; the chart ships it (the upstreams keep
# reflection off). Rebuild and commit it whenever ../protos changes a method used in routes.yaml.
descriptors:
	buf build ../protos --path ../protos/identity --path ../protos/dictionary -o descriptors.binpb

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

build:
	@mkdir -p $(BIN)
	$(GO) build -o $(BIN)/gatekeeper ./cmd/gatekeeper

run:
	$(GO) run ./cmd/gatekeeper

e2e:
	scripts/e2e.sh

docker:
	docker build -f build/gatekeeper/Dockerfile -t $(IMAGE_REPO)/gatekeeper:$(IMAGE_TAG) .

clean:
	rm -rf $(BIN) routes.local.yaml
