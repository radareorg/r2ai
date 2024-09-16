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
    parser.add_argument("-w", "--webserver", action="store_true",
        help="Start the r2ai webserver. Same as r2ai -c=-w")
    parser.add_argument("-p", "--port", type=str, nargs="?", const="default",
        help="Change listen port number")
    parser.add_argument("-e", "--eval", type=str, nargs="?", const="default",
        help="Change configuration variable")
    parser.add_argument("-m", "--model", type=str, nargs="?", const="default",
        help="Select model name")
    parser.add_argument("-c", "--command", action="append",
        help="Command to be executed. Can be passed multiple times.")
    args =  parser.parse_args()
    runrepl = True
    if args.webserver:
        if args.command is None:
            args.command = []
        args.command.append("-w")
    if args.eval:
        if args.command is None:
            args.command = []
        if args.eval == "default":
            args.command.append("-e")
            runrepl = False
        else:
            args.command.append(f"-e {args.eval}")
    if args.port:
        if args.command is None:
            args.command = []
        if args.port == "default":
            print("8080")
            return
        args.command.append(f"-e http.port={args.port}")
    if args.model:
        if args.command is None:
            args.command = []
        if args.model == "default":
            args.command.append("-mm")
            runrepl = False
        else:
            args.command.append(f"-m {args.model}")

    r2ai_main(args, args.command, runrepl)

if __name__ == "__main__":
    main()
