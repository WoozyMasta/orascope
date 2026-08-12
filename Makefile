GO          ?= go
LINTER      ?= golangci-lint
ALIGNER     ?= betteralign
VULNCHECK   ?= govulncheck
FUZZ_TIME   ?= 30s

.PHONY: check ci

check: verify tidy fmt vulncheck vet lint-fix align-fix test test-race
ci: download tools verify tidy-check fmt-check vulncheck vet lint align test

.PHONY: test test-race

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

.PHONY: fuzz

fuzz:
	$(GO) test -run='^$$' -fuzz='^FuzzConvertAuthEntry$$' -fuzztime=$(FUZZ_TIME) .
	$(GO) test -run='^$$' -fuzz='^FuzzHierarchy$$' -fuzztime=$(FUZZ_TIME) .

.PHONY: download verify vet tidy tidy-check fmt fmt-check vulncheck lint lint-fix align align-fix

download:
	$(GO) mod download

verify:
	$(GO) mod verify

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

tidy-check:
	@$(GO) mod tidy
	@git diff --stat --exit-code -- go.mod go.sum || ( \
		echo "go mod tidy: repository is not tidy"; \
		exit 1; \
	)

fmt:
	gofmt -w .

fmt-check:
	@files="$$(gofmt -l .)"; \
	if [ -n "$$files" ]; then \
		echo "$$files"; \
		echo "gofmt: files need formatting"; \
		exit 1; \
	fi

vulncheck:
	$(VULNCHECK) ./...

lint:
	$(LINTER) run ./...

lint-fix:
	$(LINTER) run --fix ./...

align:
	$(ALIGNER) ./...

align-fix:
	-$(ALIGNER) -apply ./...
	$(ALIGNER) ./...

.PHONY: tools tools-ci tool-golangci-lint tool-betteralign

tools: tool-golangci-lint tool-betteralign tool-govulncheck

tool-golangci-lint:
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

tool-betteralign:
	$(GO) install github.com/dkorunic/betteralign/cmd/betteralign@latest

tool-govulncheck:
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: release-notes

release-notes:
	@awk '\
	/^<!--/,/^-->/ { next } \
	/^## \[[0-9]+\.[0-9]+\.[0-9]+\]/ { if (found) exit; found=1; next } \
	found { \
		if (/^## \[/) { exit } \
		if (/^$$/) { flush(); print; next } \
		if (/^\* / || /^- /) { flush(); buf=$$0; next } \
		if (/^###/ || /^\[/) { flush(); print; next } \
		sub(/^[ \t]+/, ""); sub(/[ \t]+$$/, ""); \
		if (buf != "") { buf = buf " " $$0 } else { buf = $$0 } \
		next \
	} \
	function flush() { if (buf != "") { print buf; buf = "" } } \
	END { flush() } \
	' CHANGELOG.md
