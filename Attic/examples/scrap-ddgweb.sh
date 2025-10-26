#!/bin/sh
URLS=`./scrap-ddg.sh -n2 -- $@ |jq '.[].url'`
for URL in ${URLS}; do
	eval ./scrap-web.sh ${URL}
done
