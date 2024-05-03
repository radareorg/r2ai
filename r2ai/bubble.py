"""Bubble chat helper functions to make clippy-ai look nice."""

import os

CLIPPY_BEGIN = """
                                                                      .--.
                                                                     _|_ |
                                                                     O O |
                                                                     ||  |
                                                                   . ||_.|
                                                                  /| |   | 
                                                                 / | `---'  
.---------------------------------------------------------------'  '----"""

CLIPPY_END = """`-----------------------------------------------------------------------"""

USER_BEGIN = """   |\\
   | \\
.--'  '--"""

USER_END = '`---'

def query(text):
    """Display the user text using an ascii-art bubble chat

    Parameters:
    text (string): Message to display

    """
    l = len(text) + 10
    print("\033[F\033[J")
    print(USER_BEGIN + ("-" * (l - 5)) + ".")
    pad = " " * (l - len(text))
    print(f"| {text} {pad} |")
    print(USER_END + ("-"*l) + "'")

def getpad():
    """Generate padding with dashes
    """
    tw = os.get_terminal_size().columns - 75
    pad = "-"
    if tw > 0:
        pad = "-" * tw
    return pad

def response_begin():
    """Print the beginning of the clippy response
    """
    print(CLIPPY_BEGIN + getpad() + ".")

def response_end():
    """Print the end of the clippy response
    """
    print(CLIPPY_END + getpad() + "'")
