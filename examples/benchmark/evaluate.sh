#!/bin/bash

# Evaluate decompiled outputs using mai and determine best model+lang

echo "Evaluating decompiled outputs..."

tmpfile=$(mktemp)

for orig in test_c_files/complex1.c test_c_files/complex2.c test_c_files/complex3.c; do
    base=$(basename $orig .c)
    original_code=$(cat $orig)
    for f in ${base}_*.txt; do
        if [ -f "$f" ]; then
            decompiled_code=$(cat $f)
            # Assume mai takes prompt file, then original, then decompiled
            result=$(mai CMPROMPT.txt <<< "$original_code" <<< "$decompiled_code")
            score=$(echo "$result" | head -1 | grep -o '[0-9]\+')
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