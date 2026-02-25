BINARY := tf-why
PKG := ./cmd/tf-why

.PHONY: build test lint clean release-dry-run

build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./...

lint:
	@which golangci-lint > /dev/null 2>&1 || echo "golangci-lint not installed, skipping"
	@which golangci-lint > /dev/null 2>&1 && golangci-lint run ./... || true

clean:
	rm -f $(BINARY)

release-dry-run:
	goreleaser release --snapshot --clean
