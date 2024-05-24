#!/usr/bin/python3
 
import sys
import nltk
 
#-------------------------------------------------------------------------------
stmts = [
  "disassemble 10 first instructions at main",
  "pet 10 cats and 2 rabbits",
  "what's the weather like in california"
]
 
INTERESTING = [
  "JJ", "CD", "NN", "NNS"
]
 
#-------------------------------------------------------------------------------
def summarize(sentence):
  tokens = nltk.word_tokenize(sentence)
  tagged = nltk.pos_tag(tokens)
  entities = nltk.chunk.ne_chunk(tagged)
  
  summary = []
  for ent in entities:
    if ent[1] in INTERESTING:
      summary.append(ent)
 
  print(">Sentence:", repr(sentence))
  print(">Summary :", list(summary))
  #print(">Entities:", list(entities))
  print()
 
#-------------------------------------------------------------------------------
def main():
  for stmt in stmts:
    summarize(stmt)
 
if __name__ == "__main__":
  main()
