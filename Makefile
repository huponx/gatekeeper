GO  ?= go
BIN ?= bin
IMAGE_TAG  ?= dev
IMAGE_REPO ?= ghcr.io/huponx

.PHONY: help tidy routes descriptors test vet build run e2e docker clean

help:
	@printf '%s\n' \
		'tidy    go mod tidy' \
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

routes:
	scripts/routes.sh > routes.local.yaml

# descriptors.binpb describes the services the routes call; the chart ships it (the upstreams keep
# reflection off). Rebuild and commit it whenever ../protos changes a method used in routes.yaml.
descriptors:
	buf build ../protos --path ../protos/identity -o descriptors.binpb

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
