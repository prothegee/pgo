#!/usr/bin/sh
set -e;

TARGET_DIR="$PWD/bin";
CMD_DIR="$PWD/cmd";

echo "NOTE: all build goes to $TARGET_DIR";

# pgo-uuid
mkdir -p $TARGET_DIR/pgo-uuid;
echo "building: pgo-uuid";
go build -o $TARGET_DIR/pgo-uuid/pgo-uuid \
    $CMD_DIR/pgo-uuid;
