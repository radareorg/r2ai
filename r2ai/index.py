# index all the lines
import os
import re
import requests
import json
import traceback
from utils import syscmdstr
from unidecode import unidecode
import sys
try:
	from .utils import slurp
	from .const import R2AI_HISTFILE
except:
	from utils import slurp
	R2AI_HISTFILE = "/dev/null"

have_vectordb = None
vectordb_instance = None

MAXCHARS = 128
MAXMATCHES = 5
MASTODON_KEY = ""
try:
	if "HOME" in os.environ:
		MASTODON_KEY = slurp(os.environ["HOME"] + "/.r2ai.mastodon-key").strip()
except:
	pass
MASTODON_INSTANCE = "mastodont.cat"
if "MASTODON_INSTANCE" in os.environ:
	MASTODON_INSTANCE = os.environ["MASTODON_INSTANCE"]

def mastodon_search(text):
#	print("mastodon", text)
	global MASTODON_INSTANCE
#    print(f"(mastodon) {text}")
	res = []
	full_url = f"https://{MASTODON_INSTANCE}/api/v2/search?resolve=true&limit=8&type=statuses&q={text}"
	try:
		headers = {"Authorization": f"Bearer {MASTODON_KEY}"}
		response = requests.get(full_url, headers=headers)
		response.raise_for_status()  # Raise an HTTPError for bad responses
		for msg in response.json()["statuses"]:
			content = re.sub(r'<.*?>', '', msg["content"])
			res.append(content)
	except requests.exceptions.RequestException as e:
		print(f"Error making request: {e}")
	return res

def mastodon_lines(text, keywords, use_vectordb):
	twords = []
	rtlines = []
	if keywords is None:
		twords = filter_line(text)
		for tw in twords:
			if len(tw) > 2: # arbitrary
				rtlines.extend(mastodon_search(tw))
	else:
		twords = keywords
	
#	print("MASTODON_LINES...", text)
#	print("MASTODON_RTLINES...", rtlines)
	if use_vectordb:
		return rtlines
	words = {} # local rarity ratings
	for line in rtlines:
		fline = filter_line(line)
		for a in fline:
			if words.get(a):
				words[a] += 1
			else:
				words[a] = 1
	rtlines = sorted(set(rtlines))
	rslines = []
	swords = sorted(twords, key=lambda x: words.get(x) or 0)
	nwords = " ".join(swords[:5])
	# find rarity of words in the results + text and 
	# print("NWORDS", nwords)
	rslines.extend(mastodon_search(nwords))
	if len(rslines) < 10:
		for tw in swords:
			w = words.get(tw)
			if len(tw) > 4 and w is not None and w > 0 and w < 40:
				# print(f"RELEVANT WORD {tw} {w}")
				rslines.extend(mastodon_search(tw))
	return rslines

def hist2txt(text):
	newlines = []
	lines = text.split("\n")
	for line in lines:
		line = line.strip().replace("\\040", " ")
		if len(line) < 8:
			continue
		elif "?" in line:
			continue
		elif line.startswith("-") or line.startswith("_") or line.startswith("!"):
			continue
		elif line.startswith("-r"):
			# newlines.append(line[2:])
			continue
		else:
			newlines.append(line)
	newlines = sorted(set(newlines))
	return "\n".join(newlines)

def json2md(text):
	def jsonwalk(obj):
		res = ""
		if isinstance(obj, list):
			for a in obj:
				res += jsonwalk(a)
		elif isinstance(obj, dict):
			if "file" in obj:
				pass
#			elif "impactType" in obj and obj["impactType"] == "pass":
#				pass
			elif "ts" in obj:
				pass
			else:
				for k in obj.keys():
					res += "## " + k + "\n"
					lst = json.dumps(obj[k]).replace("{","").replace("}", "\n").replace("\"", "").replace(",", "*").split("\n")
					res += "\n".join(list(filter(lambda k: 'crc64' not in k and 'file' not in k and 'from_text' not in k and 'backtrace' not in k, lst)))
					res += "\n\n"
		else:
			res += str(obj) # jsonwalk(obj)
		return res
	doc = json.loads(text)
	res = jsonwalk(doc)
#	print("==========")
#	print(res)
#	print("==========")
	return res

def md2txt(text):
	# parser markdown and return a txt
	lines = text.split("\n")
	newlines = []
	data = ""
	titles = ["", "", ""]
	read_block = False
	for line in lines:
		line = line.strip()
		if line == "":
			continue
		if read_block:
			data += line + "\\n"
			if line.startswith("```"):
				read_block = False
			continue
		if line.startswith("```"):
			read_block = True
		elif line.startswith("* "):
			if data != "":
				newlines.append(":".join(titles) +":"+  data + line)
		elif line.startswith("### "):
			if data != "":
				newlines.append(":".join(titles) +":"+  data)
				data = ""
			titles = [titles[0], titles[1], line[3:]]
		elif line.startswith("## "):
			if data != "":
				newlines.append(":".join(titles) +":"+ data)
				data = ""
			titles = [titles[0], line[3:]]
		elif line.startswith("# "):
			if data != "":
				newlines.append(":".join(titles)+ ":"+data)
				data = ""
			titles = [line[2:], "", ""]
		else:
			data += line + " "
#	print("\n".join(newlines))
	return "\n".join(newlines)

def filter_line(line):
	line = unidecode(line) # remove accents
	line = re.sub(r'https?://\S+', '', line)
	line = re.sub(r'http?://\S+', '', line)
	line = line.replace(":", " ").replace("/", " ").replace("`", " ").replace("?", " ")
	line = line.replace("\"", " ").replace("'", " ")
	line = line.replace("<", " ").replace(">", " ").replace("@", " ").replace("#", "")
#line = line.replace("-", " ").replace(".", " ").replace(",", " ").replace("(", " ").replace(")", " ").strip(" ")
	line = line.replace(".", " ").replace(",", " ").replace("(", " ").replace(")", " ").strip(" ")
	line = re.sub(r"\s+", " ", line)
	if len(line) > MAXCHARS:
		line = line[:MAXCHARS]
	words = []
	for a in line.split(" "):
		b = a.strip().lower()
		try:
			int(b)
			continue
		except:
			pass
		if len(b) > 0:
			words.append(b)
	return words

def smart_slurp(file):
	if ignored_file(file):
		return ""
#	print("smart" + file)
#	print(f"slurp: {file}")
	text = slurp(file)
	if file.endswith("r2ai.history"):
		text = hist2txt(text)
	elif file.endswith(".json"):
		text = md2txt(json2md(text))
	elif file.endswith(".md"):
		text = md2txt(text)
	return text

def vectordb_search2(text, keywords, use_mastodon):
	global have_vectordb, vectordb_instance
	vectordb_init()
	result = []
	if use_mastodon:
		print ("[r2ai] Searching in Mastodon", text)
		lines = mastodon_lines(text, keywords, True)
#		print("LINES", lines)
		for line in lines:
#			print("SAVE", line)
			vectordb_instance.save(line, {"url":text})
	if have_vectordb == True and vectordb_instance is not None:
		res = []
		try:
			res = vectordb_instance.search(text, top_n=MAXMATCHES, unique=True, batch_results="diverse")
		except:
			try:
				res = vectordb_instance.search(text, top_n=MAXMATCHES)
			except:
				traceback.print_exc()
				pass
		for r in res:
			if "distance" in r:
				# print("distance", r["distance"])
				if r['distance'] < 1:
					result.append(r["chunk"])
			else:
				# when mprt is not available we cant find the distance
				result.append(r["chunk"])
	#print(result)
	return sorted(set(result))

def vectordb_init():
	global have_vectordb, vectordb_instance
	if have_vectordb == False:
		print("LEAVING")
		return
	if vectordb_instance is not None:
		return
	try:
		import vectordb
		have_vectordb = True
	except Exception as e:
		os.system("python -m spacy download en_core_web_sm")
		try:
			import vectordb
			have_vectordb = True
		except:
			have_vectordb = False
			print("To better data index use:")
			print("  pip install vectordb2")
			print("On macOS you'll need to also do this:")
			print("  python -m pip install spacy")
			print("  python -m spacy download en_core_web_sm")
			return
	try:
		vectordb_instance = vectordb.Memory(embeddings="best") # normal or fast
	except:
		vectordb_instance = vectordb.Memory() # normal or fast
	if vectordb_instance is not None:
		vectordb_instance.save("radare2 is a free reverse engineering tool written by pancake, aka Sergi Alvarez i Capilla. The project started in 2006 as a tool for domestic computer forensics in order to recover some deleted files and it continued the development adding new features like debugging, disassembler, decompiler, code analysis, advanced filesystem capabilities and integration with tons of tools like Frida, Radius, Ghidra, etc", {"url":"."}) # dummy entry

def vectordb_search(text, keywords, source_files, use_mastodon, use_debug):
	global have_vectordb, vectordb_instance
	if have_vectordb == False:
		return []
	if have_vectordb == True and vectordb_instance is not None:
		return vectordb_search2(text, keywords, use_mastodon)
	vectordb_init()
	if vectordb_instance is None:
		print("vdb not initialized")
		return
	# indexing data
	print("[r2ai] Indexing local data with vectordb")
	saved = 0
	for file in source_files:
		if ignored_file(file):
			continue
		lines = smart_slurp(file).splitlines()
		for line in lines:
#			vectordb_instance.save(line)
			vectordb_instance.save(line, {"url":file}) #, "url": file})
			saved = saved + 1
	if use_mastodon:
		lines = mastodon_lines(text, None, True)
		for line in lines:
			saved = saved + 1
			vectordb_instance.save(line, {"url":text})
	if saved == 0:
		print("[r2ai] Nothing indexed")
		vectordb_instance.save("", {})
	else:
		print("[r2ai] VectorDB index done")
	return vectordb_search2(text, keywords, use_mastodon)

class compute_rarity():
	use_mastodon = MASTODON_KEY != "" # False
	use_debug = False
	words = {}
	lines = []
	def __init__(self, source_files, use_mastodon, use_debug):
		self.use_mastodon = use_mastodon
		for file in source_files:
			if ignored_file(file):
				continue
			lines = smart_slurp(file).splitlines()
			for line in lines:
				self.lines.append(line)
				self.compute_rarity_in_line(line)
	def compute_rarity_in_line(self,line):
		fline = filter_line(line)
		for a in fline:
			if self.words.get(a):
				self.words[a] += 1
			else:
				self.words[a] = 1
	def pull_realtime_lines(self, text, keywords, use_vectordb):
		if self.env["debug"] == "true":
			print(f"Pulling from mastodon {text}")
		return mastodon_lines(text, keywords, use_vectordb)

	def find_matches(self, text, keywords):
		if self.use_mastodon:
			# pull from mastodon 
			backup_lines = self.lines
			backup_words = self.words
			realtime_lines = self.pull_realtime_lines(text, keywords, False)
			for line in realtime_lines:
				self.compute_rarity_in_line(line)
			self.lines.extend(realtime_lines)
                # find matches
		res = []
		twords = filter_line(text)
		rarity = []
		for tw in twords:
			if self.words.get(tw):
				rarity.append(self.words[tw])
			else:
				rarity.append(0)
		swords = sorted(twords, key=lambda x: self.words.get(x) or 0)
		maxrate = 0
		maxline = ""
		rates = {}
		lines = []
		for line in self.lines:
			linewords = filter_line(line)
			rate = self.match_line(linewords, swords)
			if rate > 0:
				lines.append(line)
				rates[line] = rate
#			print(f"{rate} = {line}")
		srates = sorted(lines, key=lambda x: rates.get(x) or 0)
		srates.reverse()
		if self.use_mastodon:
			self.lines = backup_lines
			self.words = backup_words
		res = srates[0:MAXMATCHES]
		res = sorted(set(res))
		return res

	def match_line(self,linewords, swords):
		count = 0
		ow = ""
		for w in swords:
			if w == ow:
				continue
			if w in linewords:
				rarity = 1				
				if w in self.words:
					rarity = self.words[w]
				count += rarity
			ow = w
		return count

def ignored_file(fn):
	if fn.endswith("package.json"):
		return True
	if fn.endswith("package-lock.json"):
		return True
	if "/." in fn:
		return True
	return False

def find_sources(srcdir):
	files = []
	try:
		files = os.walk(srcdir)
	except:
		return []
	res = []
	for f in files:
		directory = f[0]
		dirfiles = f[2]
		for f2 in dirfiles:
			if ignored_file(f2):
				continue
			if f2.endswith(".txt") or f2.endswith(".md"):
				res.append(f"{directory}/{f2}")
			elif f2.endswith(".json"):
				res.append(f"{directory}/{f2}")
	return res

def init():
	print("find sources and such")

def source_files(datadir, use_hist):
	files = []
	if datadir is not None and datadir != "":
		files.extend(find_sources(datadir))
	if use_hist:
		files.append(R2AI_HISTFILE)
	return files

def find_wikit(text, keywords):
	print("wikit")
	global have_vectordb, vectordb_instance
	vectordb_init()
	if vectordb_instance is None:
		print("vdb not initialized")
		return
	if keywords is not None:
		for kw in keywords:
			print("wikit " + kw)
			res = syscmdstr("wikit -a " + kw)
			if len(res) > 20:
				vectordb_instance.save(res, {"url":kw})
	words = filter_line(text)
	for kw in words:
		print("wikit " + kw)
		res = syscmdstr("wikit -a " + kw)
		if len(res) > 20:
			vectordb_instance.save(res, {"keyword":kw})
	res = syscmdstr("wikit -a '" + " ".join(words) + "'")
	if len(res) > 20:
		vectordb_instance.save(res, {"keyword":kw})
def reset():
	global vectordb_instance
	vectordb_instance = None

def match(text, keywords, datadir, use_hist, use_mastodon, use_debug, use_wikit, use_vectordb):
	files = source_files(datadir, use_hist)
	if use_vectordb:
		if use_wikit:
			find_wikit(text, keywords)
		return vectordb_search(text, keywords, files, use_mastodon, use_debug)
	raredb = compute_rarity(files, use_mastodon, use_debug)
	if use_wikit:
		print("[r2ai] Warning: data.wikit only works with vectordb")
		
	return raredb.find_matches(text, keywords)

if __name__ == '__main__':
	if len(sys.argv) > 1:
		matches = main_indexer(sys.argv[1])
		for m in matches:
			print(m)
	else:
		print(f"Usage: index.py [query]")
