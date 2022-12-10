.PHONY: lint test vendor clean



default: lint test

lint:
	golangci-lint run

test:
	go test -v -cover ./...

build:
	go build -v .

yaegi_test:
	yaegi test -v .

vendor:
	go mod vendor

clean:
	rm -rf ./vendor
