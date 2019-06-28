.PHONY: all race clean test

all:
	go build

race:
	CGO_ENABLED=1 go build -race

clean:
	go clean

test:
	go test
