#!/usr/bin/sh
go test -v ./...

# go test -v -run TestUUIDv1Format

go test -bench=. -benchmem

go test -race ./...
