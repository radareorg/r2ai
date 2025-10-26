#!/bin/sh
if [ -z "$1" ]; then
	echo "Gimme an url to scrap"
	exit 1
fi

# https://github.com/aaronsw/html2text =>
# https://raw.githubusercontent.com/aaronsw/html2text/master/README.md

curl -s "$1" | html2text -width 1024 -utf8 -nobs | grep -E '.{80}' | grep -v '=====' | grep -v '\*\*\*\*' | grep -v -e '^\d' | sed -r 's/^[[:space:]]+|[[:space:]]+$//g' | grep -v ://
