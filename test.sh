#!/bin/sh
set -e  # fail fast if any command fails

go test -v \
    ./cmd/... \
    ./uuid/...;

go test -bench=. \
    -benchmem ./cmd/... \
    ./uuid/...;

go test -race \
    ./cmd/... \
    ./uuid/...;
