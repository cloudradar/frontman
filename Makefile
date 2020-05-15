.PHONY: all

PROJECT_DIR=/go/src/github.com/cloudradar-monitoring/frontman

ifeq ($(RELEASE_MODE),)
  RELEASE_MODE=release-candidate
endif
ifeq ($(RELEASE_MODE),release-candidate)
  SELF_UPDATES_FEED_URL="https://repo.cloudradar.io/windows/frontman/feed/rolling"
endif
ifeq ($(RELEASE_MODE),stable)
  SELF_UPDATES_FEED_URL="https://repo.cloudradar.io/windows/frontman/feed/stable"
endif

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GORUN=$(GOCMD) run
BINARY_NAME=frontman

all: test build

build:
	$(GOBUILD) -v ./cmd/frontman/...

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

run:
	$(GORUN) -v ./cmd/frontman/...

vendor-install:
	dep ensure -vendor-only

goimports:
	goimports -l $$(find . -type f -name '*.go' -not -path "./vendor/*")

goreleaser-precheck:
	@if [ -z ${SELF_UPDATES_FEED_URL} ]; then echo "SELF_UPDATES_FEED_URL is empty"; exit 1; fi

goreleaser-rm-dist: goreleaser-precheck
	SELF_UPDATES_FEED_URL=$(SELF_UPDATES_FEED_URL) goreleaser --rm-dist

goreleaser-snapshot: goreleaser-precheck
	SELF_UPDATES_FEED_URL=$(SELF_UPDATES_FEED_URL) goreleaser --snapshot --rm-dist

