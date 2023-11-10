# index all the lines
import os
import re
import requests
from unidecode import unidecode
import sys
try:
	from .utils import slurp
except:
	from utils import slurp

SRCDIR = "../doc/data"
R2AI_DIR = os.path.dirname(__file__)
MASTODON_KEY = ""
try:
	if "HOME" in os.environ:
		MASTODON_KEY = slurp(os.environ["HOME"] + "/.r2ai.mastodon-key").strip()
except:
	pass
MASTODON_INSTANCE = "mastodont.cat"

def mastodont_search(text):
    base_url = f"https://{MASTODON_INSTANCE}/api/v2/search?resolve=true&limit=10&type=statuses&q="
    res = []
    full_url = base_url + text
    try:
        headers = {"Authorization": f"Bearer {MASTODON_KEY}"}
        response = requests.get(full_url, headers=headers)
        response.raise_for_status()  # Raise an HTTPError for bad responses
#        print(f"==> {text}")
        for msg in response.json()["statuses"]:
            content = re.sub(r'<.*?>', '', msg["content"])
#            print(f"  - {content}")
            res.append(content)
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")
    return res

def filter_line(line):
	line = unidecode(line) # remove accents
	line = line.replace(":", " ").replace("/", " ").replace("`", " ").replace("?", " ")
	line = line.replace("\"", " ").replace("'", " ")
	line = line.replace("<", " ").replace(">", " ").replace("@", " ").replace("#", " ")
	nline = line.replace("-", " ").replace(".", " ").replace(",", " ").replace("(", " ").replace(")", " ").strip(" ")
	words = []
	for a in nline.split(" "):
		b = a.strip().lower()
		try:
			int(b)
			continue
		except:
			pass
		if len(b) > 0:
			words.append(b)
	return words

class compute_rarity():
	use_mastodon = MASTODON_KEY != "" # False
	words = {}
	lines = []
	def __init__(self, source_files):
		for file in source_files:
			lines = slurp(file).splitlines()
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
	def pull_realtime_lines(self, text, chk):
		rtlines = []
		twords = filter_line(text)
		for tw in twords:
			rtlines.extend(mastodont_search(tw))
		words = {} # local rarity ratings
		for line in rtlines:
			fline = filter_line(line)
			for a in fline:
				if words.get(a):
					words[a] += 1
				else:
					words[a] = 1
		# find rarity of words in the results + text and 
		rslines = []
		swords = sorted(twords, key=lambda x: words.get(x) or 0)
		for tw in swords:
			w = words.get(tw)
			if len(tw) > 4 and w is not None and w > 0 and w < 40:
#				print(f"RELEVANT WORD {tw} {w}")
				rslines.extend(mastodont_search(tw))
		return rslines
	def find_matches(self, text):
		if self.use_mastodon:
			# pull from mastodon 
			backup_lines = self.lines
			backup_words = self.words
			realtime_lines = self.pull_realtime_lines(text, False)
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
		return srates[0:5]
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

def find_sources(srcdir):
	files = os.walk(srcdir)
	res = []
	for f in files:
		for f2 in f[2]:
			if f2.endswith(".txt"):
				res.append(f"{srcdir}/{f2}")
	return res

def main_indexer(text):
	source_files = find_sources(f"{R2AI_DIR}/{SRCDIR}")
	raredb = compute_rarity(source_files)
	return raredb.find_matches(text)

if __name__ == '__main__':
	if len(sys.argv) > 1:
		matches = main_indexer(sys.argv[1])
		for m in matches:
			print(m)
	else:
		print(f"Usage: index.py [query] # takes the data from ${SRCDIR}")