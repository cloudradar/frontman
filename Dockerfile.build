FROM golang:1.11-alpine

ENV GORELEASER_VERSION 0.85.1

# Install git
RUN apk update && \
    apk add --no-cache git rpm gcc libc-dev

# Get goreleaser
RUN wget -O goreleaser.tar.gz "https://github.com/goreleaser/goreleaser/releases/download/v$GORELEASER_VERSION/goreleaser_Linux_x86_64.tar.gz" && \
    tar xf goreleaser.tar.gz && \
    mv goreleaser /usr/local/bin && \
    rm goreleaser.tar.gz

WORKDIR /go/src/github.com/cloudradar-monitoring/frontman
CMD FRONTMAN_VERSION=$(git describe --always --long --dirty --tag) goreleaser --snapshot --rm-dist
