#!/bin/sh
# Offline smoke tests for the Vertex AI provider (no network required)
PASS=0
FAIL=0

# Use empty rc to avoid user config interference
R2ENV="R2_RCFILE=/dev/null"

check() {
	desc="$1"
	expected="$2"
	actual="$3"
	if echo "$actual" | grep -q "$expected"; then
		PASS=$((PASS+1))
	else
		FAIL=$((FAIL+1))
		printf "FAIL: %s\n  expected: %s\n  got: %s\n" "$desc" "$expected" "$actual"
	fi
}

# Provider enumeration
providers=$(env $R2ENV r2 -qc 'r2ai -e r2ai.api=?' -- 2>/dev/null)
check "vertex in provider list" "vertex" "$providers"
check "vertex-anthropic in provider list" "vertex-anthropic" "$providers"

# Config defaults
region=$(env $R2ENV r2 -qc 'r2ai -e r2ai.vertex.region' -- 2>/dev/null)
check "vertex.region default is us-central1" "us-central1" "$region"

# Config roundtrip
rt=$(env $R2ENV r2 -qc 'e r2ai.vertex.project=test-proj; e r2ai.vertex.region=europe-west4; r2ai -e r2ai.vertex.project; r2ai -e r2ai.vertex.region' -- 2>/dev/null)
check "vertex config roundtrip project" "test-proj" "$rt"
check "vertex config roundtrip region" "europe-west4" "$rt"

# Error when project not set
err=$(env $R2ENV r2 -qc 'e r2ai.api=vertex; e r2ai.vertex.project=; r2ai hello' -- 2>&1)
check "error when project not set" "vertex.project" "$err"

printf "\n%d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
