"""Entrypoint for the r2ai plugin and repl."""
# pylint: disable=import-outside-toplevel
# pylint: disable=unused-import
# pylint: disable=missing-function-docstring
import sys
import os

def main():
    if os.environ.get('R2AI'):
        print("Cant load r2ai r2 plugin from inside r2ai")
        sys.exit(0)
    r2aihome = os.path.dirname(__file__)
    try:
        r2aihome = os.path.dirname(os.readlink(__file__))
    except (OSError, FileNotFoundError):
        pass
    sys.path.insert(0, r2aihome)
    os.environ["R2AI"] = "1"
    import r2ai.main

if __name__ == "__main__":
    main()
