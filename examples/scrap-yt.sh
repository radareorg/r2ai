#!/bin/sh

yt-dlp -vU --write-auto-sub "$1" > /dev/null 2>&1
cat *.vtt | sed 's/<[^>]*>//g' | grep -v '^0' | sed -e 's/\t/ /g' | grep -v '^\s+$' | uniq | paste -s d ' ' /dev/stdin | sed 's/\t/ /g' | sed -E 's/ +/ /g'
rm -f *.vtt
