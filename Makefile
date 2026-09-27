BINARY  := proxyjoss
PKG     := ./...
WORKER  := worker

.PHONY: all check build test race vet fmt fmt-check worker worker-test tidy clean run

## all: every check, Go and worker.
all: check worker

## check: formatting, vet, build and tests.
check: fmt-check vet build test

## build: compile the binary.
build:
	go build -o $(BINARY) ./cmd/proxyjoss

## test: run the Go tests.
test:
	go test $(PKG)

## race: run the Go tests under the race detector.
race:
	go test -race $(PKG)

## vet: run go vet.
vet:
	go vet $(PKG)

## fmt: rewrite sources with gofmt.
fmt:
	gofmt -w .

## fmt-check: fail when anything is not gofmt clean.
fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "not gofmt clean:"; echo "$$out"; exit 1; \
	fi

## worker: run the worker tests.
worker:
	cd $(WORKER) && bun test

## worker-test: alias for worker.
worker-test: worker

## tidy: prune and verify go.mod.
tidy:
	go mod tidy
	go mod verify

## run: build and serve with the example configuration.
run: build
	./$(BINARY) -config config.example.json

## clean: remove build output.
clean:
	rm -f $(BINARY)
	rm -rf $(WORKER)/node_modules $(WORKER)/.wrangler
