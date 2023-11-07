e asm.offset=0
e asm.flags=0
e asm.sub.names=0
pId $SS| sort -u | awk '{$1=$1;print}' | sed -e 's, ,=,'
