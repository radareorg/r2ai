#!/bin/sh
URLS=`./scrap-ddg.sh -n 4 $@ |jq '.[].url'`
for URL in ${URLS}; do
	eval ./scrap-web.sh ${URL}
done
