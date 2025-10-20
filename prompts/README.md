# R2AI Prompts

This directory contains predefined prompt files for the r2ai plugin.

## Format

Each prompt is stored in a `.r2ai` file using a simple Key: Value format.

Lines starting with `#` are comments and ignored.

Supported keys:

- `Title`: The title of the prompt (required)
- `Author`: The author of the prompt
- `Description`: A brief description
- `Command` or `Commands`: Commands to execute before sending the prompt, separated by `;` (required)
- `Prompt` or `Query`: The main prompt text sent to the LLM
- `Requires`: Requirements for the prompt (e.g., "analysis" to ensure binary analysis)
- `If-Empty`: Alternative prompt or message if the command output is empty
- `If-Command`: Additional commands to run if the main command produces output

## Variable Substitution

In the `Prompt` field, you can use:

- `${VAR}`: Replaced with the value of the environment variable `VAR`
- `$(cmd)`: Replaced with the output of the r2 command `cmd`

## Usage

- `r2ai -q`: List all available prompts
- `r2ai -q name`: Run the prompt named `name`
- `r2ai -q name extra text`: Run the prompt with additional text appended

## Conditionals

- `If-Empty`: If the command output is empty, use this as the prompt instead
- `If-Command`: If the command produces output, run these additional commands and append their output

## Future Features

- Support for r2js scripts
- More advanced conditionals