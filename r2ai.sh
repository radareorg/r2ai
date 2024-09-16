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
	. venv/bin/activate
	pip3 install -r requirements.txt
else
	. venv/bin/activate
fi
# export PYTHONPATH=$PWD
exec $PYTHON $D/main.py "$@"
