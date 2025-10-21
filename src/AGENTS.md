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

## Actions

Run the following commands to perform the action described

- FORMAT: `make fmt`
- COMPILE: `make`
- INSTALL: `make user-install`
