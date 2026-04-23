.PHONY: build test vet lint clean docker

BINARY   := spiffe-sidecar
MODULE   := github.com/jie80219/zt-event-gateway/spiffe-sidecar
LDFLAGS  := -s -w

build:
	go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/spiffe-sidecar

test:
	go test -v -race ./...

vet:
	go vet ./...

lint: vet
	@echo "Lint passed (go vet)"

clean:
	rm -rf bin/

docker:
	docker build -t $(BINARY):latest .
