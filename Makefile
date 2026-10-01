.PHONY: test test-cover bench fuzz lint

test:
	go vet ./... && go test -race -count=1 ./...

test-cover:
	go test -race -coverprofile=cover.out ./...
	go tool cover -html=cover.out && unlink cover.out

bench:
	go test -run '^$$' -bench . -benchmem

fuzz:
	go test -run '^$$' -fuzz FuzzDecodeArgonHash -fuzztime 30s
	go test -run '^$$' -fuzz FuzzDecodeSCryptHash -fuzztime 30s
	go test -run '^$$' -fuzz FuzzCiphersDecrypt -fuzztime 30s

lint:
	go vet ./... && gofmt -l .
