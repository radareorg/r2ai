# R2AI Plugin for radare2

## Locations

- All the source code of the plugin is in the current directory
- Radare2 headers use to be in /usr/local/include/libr

## Formatting Style

- Use the radare2 coding style rules
  - Always add a whitespace before `(` in function calls
  - Indent the code with tabs
  - Indent comments with spaces
  - Do not define variables inside the `for` parenthesis 
  - Do not check for null before calling free

## Test

Run `r2ai` cli tool or radare2 oneliners running the `r2ai` command.

* `r2pm -r r2ai -h` -> help message for the r2ai tool
* `r2 -qc 'r2ai -h' /bin/ls -> help message of the r2ai plugin
* `r2 -qc 'r2ai -a what arch is used here' -> testing auto mode
* `r2 -e r2ai.model=gemma3:12b -e r2ai.rawtools=true -qc 'r2ai -a what arch is used here' -> testing auto mode

## Actions

Run the following commands to perform the action described

- FORMAT: `make fmt`
- COMPILE: `make` (with no extra arguments)
- INSTALL: `make user-install`
