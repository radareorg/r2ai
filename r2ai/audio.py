import whisper
import subprocess
import os

model = None

def stt(seconds):
	global model
	if model == None:
		model = whisper.load_model("base")
	tts("uh?")
	os.system("rm -f .audiomsg.wav")
	os.system("ffmpeg -f avfoundation -t 6 -i ':1' .audiomsg.wav > /dev/null 2>&1")
	result = model.transcribe(".audiomsg.wav")
	os.system("rm -f .audiomsg.wav")
	text = result["text"]
	print(f"User: {text}")
	return text

def tts(text):
	print(f"Assistant: {text}")
	subprocess.run(["say", text])
