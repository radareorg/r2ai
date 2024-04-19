#!/bin/sh
if [ ! -d venv ]; then
  python -m venv venv
  if [ ! -d venv ]; then
    echo "Cannot create venv" >&2
    exit 1
  fi
fi
. venv/bin/activate
export PYTHONPATH=$PWD
python r2ai/main.py
