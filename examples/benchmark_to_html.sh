#!/bin/bash

# Generate HTML output for command executions with collapsible sections and width control

if [ $# -eq 0 ]; then
    echo "Usage: $0 command1 [command2 ...]"
    exit 1
fi

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
    # Extract title: if command starts with #, use the rest as title, else use the command
    if [[ "$cmd" =~ ^#[[:space:]]*(.*) ]]; then
        title="${BASH_REMATCH[1]}"
        exec_cmd="${cmd#*#}"
        exec_cmd="${exec_cmd#"${exec_cmd%%[![:space:]]*}"}"  # trim leading spaces
    else
        title="$cmd"
        exec_cmd="$cmd"
    fi

    # Execute command and time it
    start_time=$(date +%s.%N)
    #output=$(eval "$exec_cmd" 2>&1)
    output=$(eval "$exec_cmd")
    exit_code=$?
    end_time=$(date +%s.%N)
    
    # Calculate execution time
    execution_time=$(echo "$end_time - $start_time" | bc -l 2>/dev/null || echo "0")
    if [ $? -ne 0 ]; then
        execution_time="N/A"
    else
        execution_time=$(printf "%.3f" "$execution_time")
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
