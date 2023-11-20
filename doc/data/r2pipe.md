# r2pipe

API available for many scripting languages that is used to automate radare2.

The API is as simple as running an r2 command and taking the output in return.

## Example

This is a simple example in r2.js which is the javascript interpreter that is shipped inside r2. This script renders the clippy saying a hello world message.

```js
const message = r2.cmd("?E Hello World");
console.log(message)
```

## JSON

The API also provides another function named `.cmdj()` which calls `.cmd()` internally, but assumes the output of the command contains JSON and returns the parsed object.

This is an example using this api:

```js
const info = r2.cmd("ij");
console.log(info.core.file); // show the file name
console.log(info.core.size); // show the file size
```

## Skeleton

The `r2skel` tool clones the `radare2-skel` repository and provides template to start your scripting projects for radare2. The skeleton templates also provide examples to create plugins for new architectures or parsing binaries.

## Explain

r2pipe is a handful api available in python, javascript, swift, rust and many other programming languages and is the recommended way to automate and script radare2.
