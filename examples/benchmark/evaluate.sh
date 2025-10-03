#!/bin/bash

# Evaluate decompiled outputs using mai and determine best model+lang

echo "Evaluating decompiled outputs..."

tmpfile=$(mktemp)
MAI="mai -q -p openai -m gpt-4o"
# MAI="mai -q"

for orig in files/complex1.c files/complex2.c files/complex3.c; do
    base=$(basename $orig .c)
    original_code=$(cat $orig)
    for f in tmp/${base}_*.txt; do
        if [ -f "$f" ]; then
            decompiled_code=$(cat $f)
	    #echo "Comparing $orig $f"
	    result=`echo n | ${MAI} -q -r "/template files/CMPROMPT.txt original=@${orig} decompiled=@${f}"`
	    score=`echo "$result" | head -n 1 | grep -oE '[0-9]+'` # |head -n 1`
	    perfect=`echo "$result" | grep 'No sign' && echo yes`
		    [ -z "$score" ] && score=0
	    if [ "$perfect" = yes ]; then
		    score=100
	    else
		    score="$((0+${score}))"
	    fi
	    echo "$score\t$f"
            if [ -n "$score" ]; then
                key="${f%.*}"  # remove .txt
                # Check if key exists in tmpfile
                existing=$(grep "^$key " $tmpfile | awk '{print $2}')
                if [ -n "$existing" ]; then
                    new_score=$(( existing + score ))
                    sed -i "s/^$key .*/$key $new_score/" $tmpfile
                else
                    echo "$key $score" >> $tmpfile
                fi
            fi
        fi
    done
done

# Find the best (highest total score)
best_key=""
best_score=0
while read key score; do
    if [ "$score" -gt "$best_score" ]; then
        best_score=$score
        best_key=$key
    fi
done < $tmpfile

rm $tmpfile

if [ -n "$best_key" ]; then
    echo "Best model+language combination: $best_key with total score $best_score"
else
    echo "No scores found"
fi
