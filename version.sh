#!/bin/sh
# version.sh - print current version or bump to a new one
# usage: ./version.sh [new-version]
# Updates VERSION, decai/src/constants.ts, src/r2ai.h, and src/meson.build

VERSION_FILE="VERSION"
TS_FILE="decai/src/constants.ts"
R2AI_H="src/r2ai.h"
MESON_FILE="src/meson.build"

NEW_VERSION="${1:-}"

get_version() {
	if [ -f "$VERSION_FILE" ]; then
		tr -d '[:space:]' < "$VERSION_FILE"
	else
		cat <<EOF >&2
error: $VERSION_FILE not found
EOF
		exit 1
	fi
}

CURRENT=$(get_version)

if [ -z "$NEW_VERSION" ]; then
	printf '%s\n' "$CURRENT"
	exit 0
fi

# basic semver-ish validation: digits.digits.digits with optional pre-release/build
if ! printf '%s' "$NEW_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+.]?[A-Za-z0-9.-]*)?$'; then
	cat <<EOF >&2
error: invalid version '$NEW_VERSION'
expected format: MAJOR.MINOR.PATCH[-prerelease]
EOF
	exit 1
fi

printf '%s\n' "$NEW_VERSION" > "$VERSION_FILE"

if [ -f "$TS_FILE" ]; then
	sed -i -E "s/export const VERSION = \"[^\"]+\";/export const VERSION = \"$NEW_VERSION\";/" "$TS_FILE"
fi

if [ -f "$R2AI_H" ]; then
	sed -i -E "s/#define R2AI_VERSION \"[^\"]+\"/#define R2AI_VERSION \"$NEW_VERSION\"/" "$R2AI_H"
fi

if [ -f "$MESON_FILE" ]; then
	sed -i -E "s/version : '[^']+'/version : '$NEW_VERSION'/" "$MESON_FILE"
fi

printf '%s -> %s\n' "$CURRENT" "$NEW_VERSION"
