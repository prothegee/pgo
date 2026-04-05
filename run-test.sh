#!/bin/sh
set -e  # fail fast if any command fails

go test -v \
    ./cmd/... \
    ./uuid/... \
    ./utils/... ;

go test -bench=. \
    -benchmem \
    ./cmd/... \
    ./uuid/... \
    ./utils/... ;

go test -race \
    ./cmd/... \
    ./uuid/... \
    ./utils/... ;
