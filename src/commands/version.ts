import type { CommandContext } from "../cli/context";
import { printInfo, printJson } from "../lib/output";

export function registerVersionCommand(ctx: CommandContext): void {
  const { program, globals, dmsEnabled } = ctx;

  program
    .command("version")
    .description("Show CLI version")
    .action(() => {
      const opts = globals();
      if (opts.json) {
        printJson({ version: "0.1.0", dms: dmsEnabled ? "enabled" : "disabled" });
        return;
      }
      printInfo(`mb-cli 0.1.0 (dms=${dmsEnabled ? "enabled" : "disabled"})`, opts);
    });
}
