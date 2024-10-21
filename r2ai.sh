#!/bin/sh
unset DYLD_LIBRARY_PATH
unset LD_LIBRARY_PATH
PYTHON=python3
if [ -h "$0" ]; then
	F=`readlink $0`
else
	F="$0"
fi
D=`dirname "$F"`
RD=`realpath "$D"`
[ -n "${RD}" ] && D="$RD"
[ -n "$D" ] && cd "$D"
if [ ! -d venv ]; then
	$PYTHON -m venv venv
	./venv/bin/pip3 install -e .
PYTHON=venv/bin/python3
fi

exec $PYTHON -m r2ai.cli "$@"
