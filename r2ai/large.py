from .models import get_hf_llm, new_get_hf_llm, get_default_model
import re
import json

class Large:
    def __init__(self, ai = None):
        self.mistral = None
        self.window = 4096
        self.maxlen = 12000
        self.maxtokens = 5000
        # self.model = "TheBloke/Mistral-7B-Instruct-v0.2-GGUF"
        self.model = "FaradayDotDev/llama-3-8b-Instruct-GGUF"
        if ai is not None:
            self.ai = ai
        else:
            self.ai = {}
            self.ai.env = {}
            self.ai.env["llm.gpu"] = "true"

    def slice_text(self, amsg):
        slices = []
        pos = self.maxlen
        while len(amsg) > self.maxlen:
            s = amsg[:pos]
            amsg = amsg[pos:]
            slices.append(s)
        slices.append(amsg)
        return slices

    def compress_text(self, msg):
        if self.mistral == None:
            self.mistral = new_get_hf_llm(self.ai, self.model, False, self.window)
        # q = f"Rewrite this code into shorter pseudocode (less than 500 tokens). keep the comments and essential logic:\n```\n{msg}\n```\n"
        #q = f"Rewrite this code into shorter pseudocode (less than 200 tokens). keep the relevant comments and essential logic:\n```\n{msg}\n```\n"
        q = f"Resumen y responde SOLO la información relevante del siguiente texto:\n{msg}"
        response = self.mistral(q, stream=False, temperature=0.001, stop="</s>", max_tokens=self.maxtokens)
        print(response["choices"]) #json.dumps(response))
        text0 = response["choices"][0]["text"]
        return text0

    def summarize_text(self, amsg):
        olen = len(amsg)
        while len(amsg) > self.maxlen:
            slices = self.slice_text(amsg)
            print(f"Re-slicing {len(slices)}")
            short_slices = []
            for s in slices:
                sm = self.compress_text(s)
                short_slices.append(sm)
                print(sm)
                print(f"Went from {len(s)} to {len(sm)}")
            amsg = " ".join(short_slices)
        nlen = len(amsg)
        print(f"total length {nlen} (original length was {olen})")
        return amsg

    def keywords_ai(self, text):
        # kws = self.keywords_ai("who is the author of radare?") => "author,radare2"
        words = []
        ctxwindow = int(self.ai.env["llm.window"])
        mm = new_get_hf_llm(self.ai, self.model, False, ctxwindow)
        msg = f"Considering the sentence \"{text}\" as input, Take the KEYWORDS or combination of TWO words from the given text and respond ONLY a comma separated list of the most relevant words. DO NOT introduce your response, ONLY show the words"
        msg = f"Take \"{text}\" as input, and extract the keywords and combination of keywords to make a search online, the output must be a comma separated list" #Take the KEYWORDS or combination of TWO words from the given text and respond ONLY a comma separated list of the most relevant words. DO NOT introduce your response, ONLY show the words"
        response = mm(msg, stream=False, temperature=0.001, stop="</s>", max_tokens=1750)
        if self.ai.env["debug"] == "true":
            print("KWSPLITRESPONSE", response)
        text0 = response["choices"][0]["text"]
        text0 = text0.replace('"', ",")
        if text0.startswith("."):
            text0 = text0[1:].strip()
        try:
            text0 = text0.split(":")[1].strip()
        except Exception:
            pass
        # print(text0)
        mm = None
        return [word.strip() for word in text0.split(',')]

    def trimsource(self, msg):
        msg = msg.replace("public ", "")
        msg = re.sub(r'import.*\;', "", msg)
        msg = msg.replace("const ", "")
        msg = msg.replace("new ", "")
        msg = msg.replace("undefined", "0")
        msg = msg.replace("null", "0")
        msg = msg.replace("false", "0")
        msg = msg.replace("true", "1")
        msg = msg.replace("let ", "")
        msg = msg.replace("var ", "")
        msg = msg.replace("class ", "")
        msg = msg.replace("interface ", "")
        msg = msg.replace("function ", "fn ")
        msg = msg.replace("substring", "")
        msg = msg.replace("this.", "")
        msg = msg.replace("while (", "while(")
        msg = msg.replace("if (", "if(")
        msg = msg.replace("!== 0", "")
        msg = msg.replace("=== true", "")
        msg = msg.replace(" = ", "=")
        msg = msg.replace(" === ", "==")
        msg = msg.replace("\t", " ")
        msg = msg.replace("\n", "")
        msg = re.sub(r"/\*.*?\*/", '', msg, flags=re.DOTALL)
        # msg = re.sub(r"\n+", "\n", msg)
        msg = re.sub(r"\t+", ' ', msg)
        msg = re.sub(r"\s+", " ", msg)
        # msg = msg.replace(";", "")
        return msg.strip()

    def trimsource_ai(self, msg):
        words = []
        if self.mistral == None:
            ctxwindow = int(self.ai.env["llm.window"])
            self.mistral = new_get_hf_llm(self.ai, self.model, False, ctxwindow)
        # q = f"Rewrite this code into shorter pseudocode (less than 500 tokens). keep the comments and essential logic:\n```\n{msg}\n```\n"
        q = f"Rewrite this code into shorter pseudocode (less than 200 tokens). keep the relevant comments and essential logic:\n```\n{msg}\n```\n"
        response = self.mistral(q, stream=False, temperature=0.1, stop="</s>", max_tokens=4096)
        text0 = response["choices"][0]["text"]
        if "```" in text0:
          return text0.split("```")[1].strip()
        return text0.strip().replace("```", "")

    def compress_code_ai(self, code):
        piecesize = 1024 * 8 # mistral2 supports 32k vs 4096
        codelen = len(code)
        pieces = int(codelen / piecesize)
        if pieces < 1:
            pieces = 1
        plen = int(codelen / pieces)
        off = 0
        res = []
        for i in range(pieces):
            piece = i + 1
            print(f"Processing {piece} / {pieces} ...")
            if piece == pieces:
                r = self.trimsource_ai(code[off:])
            else:
                r = self.trimsource_ai(code[off:off+plen])
            res.append(r)
            off += plen
        return "\n".join(res)

    def compress_messages(self, messages):
        return messages
        # TODO: implement a better logic in here asking the lm to summarize the context
        olen = 0
        msglen = 0
        for msg in messages:
            if self.ai.env["chat.reply"] == "false":
                if msg["role"] != "user":
                    continue
            if "content" in msg:
                amsg = msg["content"]
                olen += len(amsg)
                if len(amsg) > int(self.ai.env["llm.maxmsglen"]):
                    if "while" in amsg and "```" in amsg:
                        que = re.search(r"^(.*?)```", amsg, re.DOTALL).group(0).replace("```", "")
                        cod = re.search(r"```(.*?)$", amsg, re.DOTALL).group(0).replace("```", "")
                        shortcode = cod
                        while len(shortcode) > 4000:
                            olen = len(shortcode)
                            shortcode = self.compress_code_ai(shortcode)
                            nlen = len(shortcode)
                            print(f"Went from {olen} to {nlen}")
                        msg["content"] = f"{que}\n```\n{shortcode}\n```\n"
                    else:
                        print(f"total length {msglen} (original length was {olen})")
                msglen += len(msg["content"])
        # print(f"total length {msglen} (original length was {olen})")
        # if msglen > 4096:
        #   ¡print("Query is too large.. you should consider triming old messages")
        return messages
