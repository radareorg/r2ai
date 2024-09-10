#!/bin/sh
unset DYLD_LIBRARY_PATH
unset LD_LIBRARY_PATH
PYTHON=python3
R2AI_DIR="$(pwd)"
if [ -h "$0" ]; then
	F=`readlink $0`
else
	F="$0"
fi
D=`dirname $F`
[ -n "$D" ] && cd "$D"
if [ ! -d venv ]; then
	$PYTHON -m venv venv
	. venv/bin/activate
	pip3 install -r requirements.txt
else
	. venv/bin/activate
fi
# export PYTHONPATH=$PWD
env R2AI_DIR="$R2AI_DIR" $PYTHON $D/main.py $@
