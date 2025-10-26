#!/bin/sh
#
# Launch r2ai and use this prompt to generate the conversation from data.txt
# Copypaste the output into podcast.txt
#
# -f /tmp/data.txt Create a script for a podcast between two technical people named Sam and Max, about the changelog on radare2 5.9.4, focus on important features and stuff that impacts positively to users. The length must be as long as possible. Do not show any "**" section, output must contain only the conversation, be emotional and make the two people ask questions to learn more about the details of each feature

if [ ! -f podcast.txt ]; then
 echo "Missing podcast.txt. Please read the script before running it."
 exit 1
fi

cat podcast.txt | sed -e 's/Sam:/[[pbas 40]]/g' -e 's/Max:/[[pbas 60]]/g' > podcast.say.txt
say -f podcast.say.txt -o podcast.aiff
ffmpeg -i podcast.aiff podcast.mp3
