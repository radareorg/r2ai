"""Entrypoint for the r2ai plugin and repl."""
# pylint: disable=import-outside-toplevel
# pylint: disable=unused-import
# pylint: disable=missing-function-docstring
import sys
import os
import argparse

from r2ai.main import main as r2ai_main
from r2ai.main import register_r2plugin

def is_valid_file(parser, arg):
    if not os.path.isfile(arg):
        parser.error(f"The file {arg} does not exist!")

def massage_args(args):
    runrepl = True
    if args.command is None:
        args.command = []
    if args.webserver:
        args.command.append("-w")
    if args.eval:
        if args.eval == "default":
            args.command.append("-e")
            runrepl = False
        else:
            args.command.append(f"-e {args.eval}")
    if args.port:
        if args.port == "default":
            runrepl = False
            args.command.append("-e http.port")
        else:
            args.command.append(f"-e http.port={args.port}")
    if args.model:
        if args.model == "default":
            args.command.append("-mm")
            runrepl = False
        else:
            args.command.append(f"-m {args.model}")
    return runrepl, args

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
    runrepl, args = massage_args(parser.parse_args())
    r2ai_main(args, args.command, runrepl)

if __name__ == "__main__":
    try:
        import r2lang
        register_r2plugin()
    except:
        main()
