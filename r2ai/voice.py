import subprocess
import os

have_whisper = False
model = None
voice_model = "base" # base
LANGUAGE = "ca"
DEVICE = None
try:
	import whisper
	have_whisper = True
except:
	pass

def run(models):
	for model in models:
		cmd=f"ffmpeg -f avfoundation -list_devices true -i '' 2>&1 | grep '{model}'|cut -d '[' -f 3"
		process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
		output, error = process.communicate()
		output = output.decode().strip()
		if output != "":
			return ":" + output[0]
	return None

def get_microphone():
	global DEVICE
	print (f"DE {DEVICE}")
	if DEVICE is not None:
		return DEVICE
	tts("(r2ai)", "un moment")
	DEVICE = run(["AirPods", "MacBook Pro"])
	return DEVICE

def stt(seconds):
	global model
	global DEVICE
	global LANGUAGE
	global voice_model
	if model == None:
		model = whisper.load_model(voice_model)
	device = get_microphone()
	if device is None:
		tts("(r2ai)", "cannot find a microphone")
		return
	tts("(r2ai) listening for 5s... ", "si?")
	print(f"DEVICE IS {device}")
	os.system("rm -f .audiomsg.wav")
	os.system(f"ffmpeg -f avfoundation -t 5 -i '{device}' .audiomsg.wav > /dev/null 2>&1")
	result = None
	if LANGUAGE is None:
		result = model.transcribe(".audiomsg.wav")
	else:
		result = model.transcribe(".audiomsg.wav", language=LANGUAGE)
	os.system("rm -f .audiomsg.wav")
	tts("(r2ai)", "ah")
	text = result["text"].strip()
	if text == "you":
		return ""
#	print(f"User: {text}")
	return text

def tts(author, text):
	print(f"{author}: {text}")
	subprocess.run(["say", text])
