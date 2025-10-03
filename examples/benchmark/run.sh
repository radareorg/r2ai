#!/bin/bash

# Generate HTML output for command executions with collapsible sections and width control
# If PLAIN=1, output plain text instead

if [ $# -lt 4 ]; then
    echo "Usage: $0 <binary> <model> <provider> <lang1> [lang2 ...]"
    echo "Or: $0 command1 [command2 ...] (legacy)"
    exit 1
fi

# Check if first arg is a file (binary), assume new format
if [ -f "$1" ]; then
    binary="$1"
    model="$2"
    provider="$3"
    shift 3
    langs=("$@")
    commands=()
    for lang in "${langs[@]}"; do
        commands+=("# $lang echo \"decai -e model=$model;decai -e lang=$lang;decai -e api=$provider;af;decai -d\" | r2 -q $binary 2> /dev/null")
    done
    set -- "${commands[@]}"
else
    # Legacy mode
    commands=("$@")
fi

if [ "$PLAIN" = "1" ]; then
    # In plain mode, execute each command and print raw output.
    # Also, if TXTFILE is set, save combined raw output there.
    tmp_plain=$(mktemp)
    for cmd in "$@"; do
        if [[ "$cmd" =~ ^#[[:space:]]*(.*) ]]; then
            exec_cmd="${BASH_REMATCH[1]}"
        else
            exec_cmd="$cmd"
        fi
        tmpout=$(mktemp)
        eval "$exec_cmd" > "$tmpout" 2>&1 || true
        cat "$tmpout"
        cat "$tmpout" >> "$tmp_plain"
        rm -f "$tmpout"
    done
    if [ -n "$TXTFILE" ]; then
        mv "$tmp_plain" "$TXTFILE"
    else
        rm -f "$tmp_plain"
    fi
    exit 0
fi

# Timeout in seconds for each command (configurable via TIMEOUT environment variable)
TIMEOUT=${TIMEOUT:-30}

cat << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Command Execution Results</title>
    <style>
        * {
            box-sizing: border-box;
        }
        :root {
            --max-width: 400px;
        }
        body {
            font-family: monospace;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            overflow-x: hidden;
        }
        .slider-container {
            background: white;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            width: 100%;
        }
        .slider-container label {
            display: block;
            margin-bottom: 10px;
            font-weight: bold;
        }
        .slider-container input {
            width: 100%;
        }
        .commands-container {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            align-items: flex-start;
        }
        .command-section {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
            width: var(--max-width);
        }
        .command-title {
            background: #e9ecef;
            padding: 12px 15px;
            cursor: pointer;
            border: none;
            width: 100%;
            text-align: left;
            font-family: inherit;
            font-size: inherit;
            border-radius: 8px 8px 0 0;
            position: relative;
        }
        .command-title:hover {
            background: #dee2e6;
        }
        .command-time {
            position: absolute;
            top: 12px;
            right: 15px;
            color: #6c757d;
            font-size: 0.9em;
        }
        .command-body {
            padding: 15px;
            border-top: 1px solid #dee2e6;
            display: none;
        }
        .command-output {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-x: auto;
        }
        .command-section.expanded .command-body {
            display: block;
        }
    </style>
</head>
<body>
    <div class="slider-container">
        <label for="width-slider">Maximum Width: <span id="width-value">400</span>px</label>
        <input type="range" id="width-slider" min="200" max="2000" value="400" step="50">
    </div>
    <div class="commands-container">
EOF

# Process each command
for cmd in "$@"; do
    # Extract title: if command starts with #, parse title and command, else use the command
    if [[ "$cmd" =~ ^#[[:space:]]*([^[:space:]]+)[[:space:]]*(.*) ]]; then
        title="${BASH_REMATCH[1]}"
        exec_cmd="${BASH_REMATCH[2]}"
    else
        title="$cmd"
        exec_cmd="$cmd"
    fi

    # Execute command and time it
    start_time=$(date +%s.%N)
    tmpfile=$(mktemp)
    eval "$exec_cmd" > "$tmpfile" 2>&1 &
    pid=$!
    (sleep $TIMEOUT && kill $pid 2>/dev/null) &
    wait $pid 2>/dev/null
    output=$(cat "$tmpfile")
    rm "$tmpfile"
    exit_code=$?
    end_time=$(date +%s.%N)
    
    # Calculate execution time
    execution_time=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
    if [ $? -ne 0 ]; then
        execution_time="N/A"
    else
        execution_time=$(printf "%.3f" "$execution_time")
    fi

    # Save plain output to .txt file if in new format
    if [ -n "$binary" ]; then
        txtfile="tmp/${binary##*/}_${model//\//_}_${title}.txt"
        mkdir -p "$(dirname "$txtfile")" 2>/dev/null || true
        echo "$output" > "$txtfile"
    fi

    # Escape HTML in output
    escaped_output=$(echo "$output" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')

    cat << EOF
        <div class="command-section expanded">
            <button class="command-title" onclick="toggleSection(this)">$title<span class="command-time">${execution_time}s</span></button>
            <div class="command-body">
                <div class="command-output">$escaped_output</div>
            </div>
        </div>
EOF
done

cat << 'EOF'
    </div>

    <script>
        // Slider functionality
        const slider = document.getElementById('width-slider');
        const widthValue = document.getElementById('width-value');
        
        slider.addEventListener('input', function() {
            const value = this.value;
            document.documentElement.style.setProperty('--max-width', value + 'px');
            widthValue.textContent = value;
        });

        // Toggle functionality
        function toggleSection(button) {
            const section = button.parentElement;
            section.classList.toggle('expanded');
        }
    </script>
</body>
</html>
EOF
