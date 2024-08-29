"""Entrypoint for the r2ai plugin and repl."""
# pylint: disable=import-outside-toplevel
# pylint: disable=unused-import
# pylint: disable=missing-function-docstring
import sys
import os
import argparse

from r2ai.main import main as r2ai_main

def is_valid_file(parser, arg):
    if not os.path.isfile(arg):
        parser.error(f"The file {arg} does not exist!")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bin", nargs="?", type=str)
    parser.add_argument("-c", "--command", action="append",
        help="Command to be executed. Can be passed multiple times.")
    args =  parser.parse_args()

    r2ai_main(args, args.command)

if __name__ == "__main__":
    main()
