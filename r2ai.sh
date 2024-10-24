#!/bin/sh
unset DYLD_LIBRARY_PATH
unset LD_LIBRARY_PATH
export TRANSFORMERS_NO_ADVISORY_WARNINGS=1
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
if [ -d venv ]; then
	. venv/bin/activate
else
	$PYTHON -m venv venv
	. venv/bin/activate
	pip3 install -e .
fi
exec $PYTHON -m r2ai.cli "$@"
