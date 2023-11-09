import os

clippy_begin="""
                                                                      .--.
                                                                     _|_ |
                                                                     O O |
                                                                     ||  |
                                                                   . ||_.|
                                                                  /| |   | 
                                                                 / | `---'  
.---------------------------------------------------------------'  '----"""

clippy_end="""`-----------------------------------------------------------------------"""

user_begin="""   |\\
   | \\
.--'  '--"""

user_end='`---'

def query(text):
	l = len(text) + 10
	print("\033[F\033[J")
	print(user_begin + ("-"*(l-5)) + ".")
	pad = " " * (l - len(text))
	print(f"| {text} {pad} |")
	print(user_end+ ("-"*l) + "'")

def getpad():
	tw = os.get_terminal_size().columns - 75
	pad = "-"
	if tw > 0:
		pad = "-" * tw
	return pad
def response_begin():
	print(clippy_begin + getpad() + ".")
def response_end():
	print(clippy_end + getpad() + "'")
