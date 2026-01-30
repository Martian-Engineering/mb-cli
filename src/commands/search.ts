import type { CommandContext } from "../cli/context";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";

export function registerSearchCommands(ctx: CommandContext): void {
  const { program, globals, buildClient, attachInboundSafety, warnSanitization } = ctx;

  program
    .command("search")
    .description("Search Moltbook")
    .argument("<query>", "Search query")
    .option("--limit <n>", "Limit", "20")
    .action(async (query, cmd) => {
      const opts = globals();
      const { client } = buildClient(true);
      const res = await request(client, "GET", "/search", { query: { q: query, limit: cmd.limit } });

      if (!res.ok) {
        printError(`Search failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const { data, safety, sanitization } = await attachInboundSafety(res.data);
      if (opts.json) {
        printJson({ result: data, safety, sanitization });
        return;
      }

      warnSanitization(sanitization, opts, "sanitized inbound search results");
      if (safety.length > 0) {
        printInfo("Warning: potential prompt-injection patterns detected in search results.", opts);
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });
}
