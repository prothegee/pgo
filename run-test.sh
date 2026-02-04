#!/bin/sh
set -e  # fail fast if any command fails

go test -v \
    ./cmd/... \
    ./uuid/... \
    ./utility/... ;

go test -bench=. \
    -benchmem \
    ./cmd/... \
    ./uuid/... \
    ./utility/... ;

go test -race \
    ./cmd/... \
    ./uuid/... \
    ./utility/... ;
