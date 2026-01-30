import type { CommandContext } from "../cli/context";
import { printInfo, printJson } from "../lib/output";

export function registerSafetyCommands(ctx: CommandContext): void {
  const { program, globals, readJailbreakRemote, saveJailbreakRemote } = ctx;

  const safety = program.command("safety").description("Safety utilities");
  const jailbreak = safety.command("jailbreak").description("Jailbreak pattern tools");

  jailbreak
    .command("status")
    .description("Show jailbreak update feed status")
    .action(() => {
      const opts = globals();
      const data = readJailbreakRemote();
      if (opts.json) {
        printJson({ remote: data.url || null });
        return;
      }
      if (data.url) {
        printInfo(`Jailbreak remote feed: ${data.url}`, opts);
        return;
      }
      printInfo("No jailbreak remote feed configured.", opts);
    });

  jailbreak
    .command("update")
    .description("Stub: configure remote jailbreak pattern feed (phase 2)")
    .option("--url <url>", "Remote feed URL")
    .action((cmd) => {
      const opts = globals();
      if (cmd.url) {
        saveJailbreakRemote(cmd.url);
      }
      const data = readJailbreakRemote();
      const note = `Jailbreak pattern remote updates are a phase 2 stub.${data.url ? ` Stored feed: ${data.url}` : ""}`;
      if (opts.json) {
        printJson({ stub: true, message: note, remote: data.url || null });
        return;
      }
      printInfo(note, opts);
    });
}
