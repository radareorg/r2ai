"""Helper functions to handle voice recognition and synthesis."""

import os
import re
from .utils import syscmdstr

HAVE_WHISPER = False
model = None
voice_model = "large" # base
DEVICE = None
try:
    import whisper
    HAVE_WHISPER = True
except Exception:
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
    try:
        os.remove(".audiomsg.wav")
    except OSError:
        pass
    _devnull = os.open(os.devnull, os.O_WRONLY)
    _pid = os.fork()
    if _pid == 0:
        os.dup2(_devnull, 1)
        os.dup2(_devnull, 2)
        os.close(_devnull)
        os.execvp("ffmpeg", ["ffmpeg", "-f", "avfoundation", "-t", "5", "-i", device, ".audiomsg.wav"])
        os._exit(1)
    os.close(_devnull)
    _, _status = os.waitpid(_pid, 0)
    rc = os.WEXITSTATUS(_status) if os.WIFEXITED(_status) else 1
    if rc != 0:
        tts("(r2ai)", "cannot record from microphone. missing permissions in terminal?", lang)
        return
    result = None
    if lang is None:
        result = model.transcribe(".audiomsg.wav")
    else:
        result = model.transcribe(".audiomsg.wav", language=lang)
    try:
        os.remove(".audiomsg.wav")
    except OSError:
        pass
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
        _r_fd, _w_fd = os.pipe()
        _pid = os.fork()
        if _pid == 0:
            os.dup2(_r_fd, 0)
            os.close(_r_fd)
            os.close(_w_fd)
            os.execvp("festival", ["festival", "--tts", "--language", festlang])
            os._exit(1)
        os.close(_r_fd)
        os.write(_w_fd, text.encode("utf-8") if isinstance(text, str) else text)
        os.close(_w_fd)
        os.waitpid(_pid, 0)
    else:
        if lang == "es":
            VOICE = "Marisol"
        elif lang == "ca":
            VOICE = "Montse"
        else:
            VOICE = "Moira"
        _pid = os.fork()
        if _pid == 0:
            os.execvp("say", ["say", "-v", VOICE, clean_text])
            os._exit(1)
        os.waitpid(_pid, 0)
