"""Helper functions to handle voice recognition and synthesis."""

import os
import re
import subprocess
from .utils import syscmdstr
from subprocess import Popen, PIPE

HAVE_WHISPER = False
model = None
voice_model = "large" # base
DEVICE = None
try:
    import whisper
    HAVE_WHISPER = True
except:
    pass

have_festival = os.path.isfile("/usr/bin/festival")

def run(models):
    for model in models:
        cmd = f"ffmpeg -f avfoundation -list_devices true -i '' 2>&1 | grep '{model}'|cut -d '[' -f 3"
        output = syscmdstr(cmd)
        if output != "":
            return ":" + output[0]
    return None

def get_microphone(lang):
    global DEVICE
    print (f"DE {DEVICE}")
    if DEVICE is not None:
        return DEVICE
    tts("(r2ai)", "un moment", lang)
    DEVICE = run(["AirPods", "MacBook Pro"])
    print(f"DEVICE: {DEVICE}")
    return DEVICE

def stt(seconds, lang):
    global model
    global DEVICE
    global voice_model
    if lang == "":
        lang = None
    if model == None:
        model = whisper.load_model(voice_model)
    device = get_microphone(lang)
    if device is None:
        tts("(r2ai)", "cannot find a microphone", lang)
        return
    tts("(r2ai) listening for 5s... ", "digues?", lang)
    print(f"DEVICE IS {device}")
    os.system("rm -f .audiomsg.wav")
    rc = os.system(f"ffmpeg -f avfoundation -t 5 -i '{device}' .audiomsg.wav > /dev/null 2>&1")
    if rc != 0:
        tts("(r2ai)", "cannot record from microphone. missing permissions in terminal?", lang)
        return
    result = None
    if lang is None:
        result = model.transcribe(".audiomsg.wav")
    else:
        result = model.transcribe(".audiomsg.wav", language=lang)
    os.system("rm -f .audiomsg.wav")
    tts("(r2ai)", "ok", lang)
    text = result["text"].strip()
    if text == "you":
        return ""
#    print(f"User: {text}")
    return text

def tts(author, text, lang):
    clean_text = re.sub(r'https?://\S+', '', text)
    clean_text = re.sub(r'http?://\S+', '', clean_text)
    print(f"{author}: {text}")
    if have_festival:
        festlang = "english"
        if lang == "ca":
            festlang = "catalan"
        elif lang == "es":
            festlang = "spanish"
        elif lang == "it":
            festlang = "italian"
        p = Popen(['festival', '--tts', '--language', festlang], stdin=PIPE)
        p.communicate(input=text)
    else:
        if lang == "es":
            VOICE = "Marisol"
        elif lang == "ca":
            VOICE = "Montse"
        else:
            VOICE = "Moira"
        subprocess.run(["say", "-v", VOICE, clean_text])
