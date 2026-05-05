# R2AI Prompts

This directory contains predefined prompt files for the r2ai plugin.

## Format

Each prompt is stored in a `.r2ai.md` file with YAML-style frontmatter and a markdown body.

Example:

```markdown
---
description: 'Explain the current function'
author: pancake
command: r2ai -d
if-empty: exit
---
Explain the purpose of this function in one or two short sentences.
```

Supported keys:

- `title`: The title of the prompt
- `author`: The author of the prompt
- `description`: A brief description
- `command`: Commands to execute before sending the prompt, separated by `;` (required)
- `requires`: Requirements for the prompt (e.g., "analysis" to ensure binary analysis)
- `if-empty`: Alternative prompt or message if the command output is empty
- `if-command`: Additional commands to run if the main command produces output
- `model`: Model override for this prompt
- `provider`: Provider override for this prompt

Legacy `.r2ai.txt` files using `Title:`, `Command:`, `Prompt:` or `Query:` are still accepted.

## Variable Substitution

In the markdown body, you can use:

- `${VAR}`: Replaced with the value of the environment variable `VAR`
- `$(cmd)`: Replaced with the output of the r2 command `cmd`

## Usage

- `r2ai -q`: List all available prompts
- `r2ai -q name`: Run the prompt named `name`
- `r2ai -q name extra text`: Run the prompt with additional text appended

## Conditionals

- `if-empty`: If the command output is empty, use this as the prompt instead
- `if-command`: If the command produces output, run these additional commands and append their output

## Future Features

- Support for r2js scripts
- More advanced conditionals
