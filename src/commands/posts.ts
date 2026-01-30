import type { CommandContext } from "../cli/context";
import { listSensitiveEntries, loadSensitiveStore } from "../lib/config";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";
import { recordPost, recordRequest } from "../lib/rate_limit";
import { scanOutbound } from "../lib/safety";

export function registerPostCommands(ctx: CommandContext): void {
  const {
    program,
    globals,
    buildClient,
    sanitizeFields,
    warnSanitization,
    enforceRateLimit,
    logOutbound,
    handleDryRun,
    applyRetryAfter,
    attachInboundSafety,
    postReminder,
  } = ctx;

  const posts = program.command("posts").description("Posts commands");

  posts
    .command("list")
    .description("List posts")
    .option("--sort <sort>", "hot|new|top|rising", "hot")
    .option("--submolt <name>", "Submolt name")
    .option("--mine", "List recent posts for the current agent")
    .option("--limit <n>", "Limit", "20")
    .option("--cursor <cursor>", "Pagination cursor")
    .action(async (cmd) => {
      const opts = globals();
      const { client, profile } = buildClient(true);
      let res;

      if (cmd.mine) {
        const storedName =
          profile && typeof (profile as Record<string, unknown>).agent_name === "string"
            ? ((profile as Record<string, unknown>).agent_name as string)
            : undefined;

        let agentName = storedName;
        if (!agentName) {
          const meRes = await request(client, "GET", "/agents/me", { idempotent: true });
          if (!meRes.ok) {
            printError(
              `Posts list (mine) failed to resolve agent name (${meRes.status}): ${meRes.error || "unknown error"}`,
              opts,
            );
            process.exit(1);
          }
          const payload = meRes.data as Record<string, unknown> | undefined;
          agentName =
            typeof payload?.name === "string"
              ? payload.name
              : payload &&
                  typeof payload?.agent === "object" &&
                  payload.agent &&
                  typeof (payload.agent as Record<string, unknown>).name === "string"
                ? ((payload.agent as Record<string, unknown>).name as string)
                : undefined;
        }

        if (!agentName) {
          printError(
            "Posts list (mine) requires a known agent name. Re-run 'mb register' or ensure the profile has agent_name stored.",
            opts,
          );
          process.exit(1);
        }

        res = await request(client, "GET", "/agents/profile", {
          query: { name: agentName },
        });
      } else {
        res = await request(client, "GET", "/posts", {
          query: { sort: cmd.sort, submolt: cmd.submolt, limit: cmd.limit, cursor: cmd.cursor },
        });
      }

      if (!res.ok) {
        printError(`Posts list failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const { data, safety, sanitization } = await attachInboundSafety(res.data);
      if (opts.json) {
        printJson({ result: data, safety, sanitization, mode: cmd.mine ? "mine" : "all" });
        return;
      }

      if (cmd.mine) {
        printInfo("Note: showing agent profile response with recentPosts.", opts);
      }
      warnSanitization(sanitization, opts, "sanitized inbound posts content");
      if (safety.length > 0) {
        printInfo("Warning: potential prompt-injection patterns detected in posts content.", opts);
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });

  posts
    .command("show")
    .description("Show a post")
    .argument("<post_id>", "Post ID")
    .action(async (postId) => {
      const opts = globals();
      const { client } = buildClient(true);
      const res = await request(client, "GET", `/posts/${postId}`, { idempotent: true });

      if (!res.ok) {
        printError(`Posts show failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const { data, safety, sanitization } = await attachInboundSafety(res.data);
      if (opts.json) {
        printJson({ result: data, safety, sanitization });
        return;
      }

      warnSanitization(sanitization, opts, "sanitized inbound post content");
      if (safety.length > 0) {
        printInfo("Warning: potential prompt-injection patterns detected in post content.", opts);
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });

  posts
    .command("create")
    .description("Create a post")
    .requiredOption("--submolt <name>", "Submolt name")
    .requiredOption("--title <title>", "Post title")
    .option("--content <text>", "Post content")
    .option("--url <url>", "Link URL")
    .action(async (cmd) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      if (!cmd.content && !cmd.url) {
        printError("Either --content or --url is required", opts);
        process.exit(1);
      }

      if (cmd.content && cmd.url) {
        printError("Provide only one of --content or --url", opts);
        process.exit(1);
      }

      const { sanitized, warnings: sanitizationWarnings } = sanitizeFields({
        title: cmd.title,
        content: cmd.content,
        url: cmd.url,
      });
      const outboundText = [sanitized.title, sanitized.content].filter(Boolean).join("\n");

      try {
        await enforceRateLimit(profileName, "post", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "post.create",
          method: "POST",
          endpoint: "/posts",
          status: "blocked",
          reason: "rate_limit",
          content: outboundText,
          sanitization: sanitizationWarnings,
        });
        process.exit(1);
      }

      const sensitiveStore = loadSensitiveStore();
      const sensitiveEntries = listSensitiveEntries(sensitiveStore, profileName);
      const outboundMatches = await scanOutbound(outboundText, profileName, sensitiveEntries);

      if (outboundMatches.length > 0 && !opts.allowSensitive) {
        logOutbound({
          profile: profileName,
          action: "post.create",
          method: "POST",
          endpoint: "/posts",
          status: "blocked",
          reason: "safety",
          content: outboundText,
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        if (opts.json) {
          printJson({ blocked: true, matches: outboundMatches, sanitization: sanitizationWarnings });
        } else {
          printError("Outbound content flagged as sensitive. Use --allow-sensitive to override.", opts);
        }
        process.exit(1);
      }

      const res = await request(client, "POST", "/posts", {
        body: {
          submolt: cmd.submolt,
          title: sanitized.title,
          ...(sanitized.content ? { content: sanitized.content } : { url: sanitized.url }),
        },
        idempotent: false,
      });

      if (
        handleDryRun(res, opts, {
          reminder: postReminder,
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        })
      ) {
        logOutbound({
          profile: profileName,
          action: "post.create",
          method: "POST",
          endpoint: "/posts",
          status: "dry_run",
          content: outboundText,
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        return;
      }

      if (!res.ok) {
        if (res.status === 429) {
          applyRetryAfter(profileName, "post", res.data);
        }
        logOutbound({
          profile: profileName,
          action: "post.create",
          method: "POST",
          endpoint: "/posts",
          status: "blocked",
          reason: `http_${res.status}`,
          content: outboundText,
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        printError(`Post create failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordPost(profileName);
      logOutbound({
        profile: profileName,
        action: "post.create",
        method: "POST",
        endpoint: "/posts",
        status: "sent",
        content: outboundText,
        sanitization: sanitizationWarnings,
        safety: outboundMatches,
      });

      if (opts.json) {
        printJson({
          result: res.data,
          reminder: postReminder,
          safety: outboundMatches,
          sanitization: sanitizationWarnings,
        });
        return;
      }

      printInfo("Post successful.", opts);
      warnSanitization(sanitizationWarnings, opts, "sanitized outbound post content");
      if (outboundMatches.length > 0) {
        printInfo("Warning: outbound content matched sensitive patterns.", opts);
      }
      printInfo(postReminder, opts);
    });

  posts
    .command("delete")
    .description("Delete a post")
    .argument("<post_id>", "Post ID")
    .action(async (postId) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "post.delete",
          method: "DELETE",
          endpoint: `/posts/${postId}`,
          status: "blocked",
          reason: "rate_limit",
        });
        process.exit(1);
      }
      const res = await request(client, "DELETE", `/posts/${postId}`, { idempotent: true });

      if (handleDryRun(res, opts, {})) {
        logOutbound({
          profile: profileName,
          action: "post.delete",
          method: "DELETE",
          endpoint: `/posts/${postId}`,
          status: "dry_run",
        });
        return;
      }

      if (!res.ok) {
        if (res.status === 429) {
          applyRetryAfter(profileName, "request", res.data);
        }
        logOutbound({
          profile: profileName,
          action: "post.delete",
          method: "DELETE",
          endpoint: `/posts/${postId}`,
          status: "blocked",
          reason: `http_${res.status}`,
        });
        printError(`Post delete failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "post.delete",
        method: "DELETE",
        endpoint: `/posts/${postId}`,
        status: "sent",
      });

      if (opts.json) {
        printJson({ result: res.data || { deleted: true } });
        return;
      }
      printInfo("Post deleted.", opts);
    });
}
