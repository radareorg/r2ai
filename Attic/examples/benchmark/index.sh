#!/bin/bash

# Find all directories containing BENCH.txt
dirs=$(find . -name "BENCH.txt" -type f | xargs dirname | sort | uniq)

# Start HTML output
cat <<EOF > benchmark_index.html
<html>
<table>
EOF

# Process each directory
for dir in $dirs; do
    cat <<EOF >> benchmark_index.html
	<tr> <td>
	<div>
EOF

    # Add contents of BENCH.txt
    cat "$dir/BENCH.txt" >> benchmark_index.html

    cat <<EOF >> benchmark_index.html
	</div>
	</td>
	<td>
EOF

    # Find and add links to HTML files
    for html_file in $(ls "$dir"/*.html 2>/dev/null | sort); do
        base=$(basename "$html_file" .html)
        cat <<EOF >> benchmark_index.html
	<a href="$dir/$base.html">$base</a>
	<br />
EOF
    done

    cat <<EOF >> benchmark_index.html
	</td>
	</tr>
EOF
done

# End HTML output
cat <<EOF >> benchmark_index.html
</table>
<br />
<br />
</html>
EOF