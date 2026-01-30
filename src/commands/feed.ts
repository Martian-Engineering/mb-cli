import type { CommandContext } from "../cli/context";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";

export function registerFeedCommands(ctx: CommandContext): void {
  const { program, globals, buildClient, attachInboundSafety, warnSanitization } = ctx;

  program
    .command("feed")
    .description("View your feed")
    .option("--sort <sort>", "hot|new|top|rising", "hot")
    .option("--limit <n>", "Limit", "20")
    .option("--cursor <cursor>", "Pagination cursor")
    .action(async (cmd) => {
      const opts = globals();
      const { client } = buildClient(true);
      let res = await request(client, "GET", "/feed", {
        query: { sort: cmd.sort, limit: cmd.limit, cursor: cmd.cursor },
      });
      let fallback = false;

      if (!res.ok && (res.status === 401 || res.status === 404)) {
        const fallbackRes = await request(client, "GET", "/posts", {
          query: { sort: cmd.sort, limit: cmd.limit, cursor: cmd.cursor },
        });
        if (fallbackRes.ok) {
          res = fallbackRes;
          fallback = true;
        }
      }

      if (!res.ok) {
        printError(`Feed failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const { data, safety, sanitization } = await attachInboundSafety(res.data);
      if (opts.json) {
        printJson({ result: data, safety, sanitization, fallback: fallback ? "posts" : undefined });
        return;
      }

      if (fallback) {
        printInfo("Note: feed endpoint unavailable; showing posts instead.", opts);
      }
      warnSanitization(sanitization, opts, "sanitized inbound feed content");
      if (safety.length > 0) {
        printInfo("Warning: potential prompt-injection patterns detected in feed content.", opts);
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });
}
