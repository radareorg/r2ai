import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
 
nltk.download('stopwords')
nltk.download('punkt')
long_sentence = "It's such a fine day today, The sun is out, and the sky is blue. Can you tell me what the weather will be like tomorrow?"
word_tokens = word_tokenize(long_sentence)
short_sent = ' '.join([t for t in word_tokens if t not in stopwords.words('english')])
print(short_sent)
