import type { R2PipeSync } from "./r2pipe";

import { COMMAND } from "./constants";
import { handleCommand } from "./commands";

function main(args: string): boolean {
  const output = handleCommand(args, main);
  if (output) {
    r2.log(output);
  }
  return true;
}

function installPlugin(): void {
  r2.unload("core", COMMAND);
  r2.plugin("core", function () {
    function coreCall(cmd: string): boolean {
      if (cmd.startsWith(COMMAND)) {
        const args = cmd.slice(COMMAND.length).trim();
        return main(args);
      }
      return false;
    }

    return {
      name: COMMAND,
      license: "MIT",
      desc: "r2 decompiler based on r2ai",
      call: coreCall,
    };
  });
}

installPlugin();
