default: fmt lint install generate

build:
	go build -v ./...

install: build
	go install -v ./...

lint:
	golangci-lint run

vet:
	go vet ./...

generate:
	go generate ./...

docs: generate

fmt:
	gofmt -s -w -e .

test:
	go test -v -cover -timeout=120s -parallel=10 ./...

# Creates and destroys real HERE resources: point the HERE_* variables at a sandbox realm.
testacc:
	TF_ACC=1 go test -v -cover -timeout 120m ./...

depscheck:
	@go mod tidy
	@git diff --exit-code -- go.mod go.sum || \
		(echo; echo "Unexpected difference in go.mod/go.sum. Run 'go mod tidy' and commit."; exit 1)

.PHONY: default build install lint vet generate docs fmt test testacc depscheck
