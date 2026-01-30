import type { CommandContext } from "../cli/context";
import { listSensitiveEntries, loadSensitiveStore } from "../lib/config";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";
import { recordComment } from "../lib/rate_limit";
import { scanOutbound } from "../lib/safety";

export function registerCommentCommands(ctx: CommandContext): void {
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
  } = ctx;

  const comments = program.command("comments").description("Comments commands");

  function extractCommentsFromPost(payload: unknown): { found: boolean; comments: unknown } {
    if (!payload || typeof payload !== "object") {
      return { found: false, comments: payload };
    }
    const record = payload as Record<string, unknown>;
    if (Array.isArray(record.comments)) {
      return { found: true, comments: record.comments };
    }
    const post = record.post;
    if (post && typeof post === "object") {
      const postRecord = post as Record<string, unknown>;
      if (Array.isArray(postRecord.comments)) {
        return { found: true, comments: postRecord.comments };
      }
    }
    const data = record.data;
    if (data && typeof data === "object") {
      const dataRecord = data as Record<string, unknown>;
      if (Array.isArray(dataRecord.comments)) {
        return { found: true, comments: dataRecord.comments };
      }
    }
    return { found: false, comments: payload };
  }

  comments
    .command("list")
    .description("List comments for a post")
    .argument("<post_id>", "Post ID")
    .option("--sort <sort>", "top|new|controversial", "top")
    .option("--limit <n>", "Limit", "50")
    .option("--cursor <cursor>", "Pagination cursor")
    .action(async (postId, cmd) => {
      const opts = globals();
      const { client } = buildClient(true);
      let res = await request(client, "GET", `/posts/${postId}/comments`, {
        query: { sort: cmd.sort, limit: cmd.limit, cursor: cmd.cursor },
        idempotent: true,
      });
      let fallback = false;
      let fallbackMode: "post" | "post.comments" | undefined;

      if (!res.ok && res.status === 405) {
        const fallbackRes = await request(client, "GET", `/posts/${postId}`, { idempotent: true });
        if (fallbackRes.ok) {
          res = fallbackRes;
          fallback = true;
        }
      }

      if (!res.ok) {
        printError(`Comments list failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      let payload = res.data;
      if (fallback) {
        const extracted = extractCommentsFromPost(res.data);
        if (extracted.found) {
          payload = extracted.comments;
          fallbackMode = "post.comments";
        } else {
          fallbackMode = "post";
        }
      }

      const { data, safety, sanitization } = await attachInboundSafety(payload);
      if (opts.json) {
        printJson({
          result: data,
          safety,
          sanitization,
          fallback: fallback ? fallbackMode || "post" : undefined,
        });
        return;
      }

      if (fallback) {
        const note =
          fallbackMode === "post.comments"
            ? "Note: comments endpoint unavailable; extracted comments from post response."
            : "Note: comments endpoint unavailable; showing post with comments instead.";
        printInfo(note, opts);
      }
      warnSanitization(sanitization, opts, "sanitized inbound comments content");
      if (safety.length > 0) {
        printInfo(
          "Warning: potential prompt-injection patterns detected in comments content.",
          opts,
        );
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });

  comments
    .command("add")
    .description("Add a comment")
    .argument("<post_id>", "Post ID")
    .requiredOption("--content <text>", "Comment content")
    .action(async (postId, cmd) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      const { sanitized, warnings: sanitizationWarnings } = sanitizeFields({
        content: cmd.content,
      });

      try {
        await enforceRateLimit(profileName, "comment", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "comment.add",
          method: "POST",
          endpoint: `/posts/${postId}/comments`,
          status: "blocked",
          reason: "rate_limit",
          content: sanitized.content ?? "",
          sanitization: sanitizationWarnings,
        });
        process.exit(1);
      }

      const sensitiveStore = loadSensitiveStore();
      const sensitiveEntries = listSensitiveEntries(sensitiveStore, profileName);
      const outboundMatches = await scanOutbound(
        sanitized.content ?? "",
        profileName,
        sensitiveEntries,
      );

      if (outboundMatches.length > 0 && !opts.allowSensitive) {
        logOutbound({
          profile: profileName,
          action: "comment.add",
          method: "POST",
          endpoint: `/posts/${postId}/comments`,
          status: "blocked",
          reason: "safety",
          content: sanitized.content ?? "",
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

      const res = await request(client, "POST", `/posts/${postId}/comments`, {
        body: { content: sanitized.content },
        idempotent: false,
      });

      if (handleDryRun(res, opts, { sanitization: sanitizationWarnings, safety: outboundMatches })) {
        logOutbound({
          profile: profileName,
          action: "comment.add",
          method: "POST",
          endpoint: `/posts/${postId}/comments`,
          status: "dry_run",
          content: sanitized.content ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        return;
      }

      if (!res.ok) {
        if (res.status === 429) {
          applyRetryAfter(profileName, "comment", res.data);
        }
        logOutbound({
          profile: profileName,
          action: "comment.add",
          method: "POST",
          endpoint: `/posts/${postId}/comments`,
          status: "blocked",
          reason: `http_${res.status}`,
          content: sanitized.content ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        printError(`Comment failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordComment(profileName);
      logOutbound({
        profile: profileName,
        action: "comment.add",
        method: "POST",
        endpoint: `/posts/${postId}/comments`,
        status: "sent",
        content: sanitized.content ?? "",
        sanitization: sanitizationWarnings,
        safety: outboundMatches,
      });

      if (opts.json) {
        printJson({ result: res.data, safety: outboundMatches, sanitization: sanitizationWarnings });
        return;
      }
      printInfo("Comment posted.", opts);
      warnSanitization(sanitizationWarnings, opts, "sanitized outbound comment content");
    });

  comments
    .command("reply")
    .description("Reply to a comment")
    .argument("<post_id>", "Post ID")
    .requiredOption("--parent <comment_id>", "Parent comment ID")
    .requiredOption("--content <text>", "Reply content")
    .action(async (postId, cmd) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      const { sanitized, warnings: sanitizationWarnings } = sanitizeFields({
        content: cmd.content,
      });

      try {
        await enforceRateLimit(profileName, "comment", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "comment.reply",
          method: "POST",
          endpoint: `/posts/${postId}/comments`,
          status: "blocked",
          reason: "rate_limit",
          content: sanitized.content ?? "",
          sanitization: sanitizationWarnings,
        });
        process.exit(1);
      }

      const sensitiveStore = loadSensitiveStore();
      const sensitiveEntries = listSensitiveEntries(sensitiveStore, profileName);
      const outboundMatches = await scanOutbound(
        sanitized.content ?? "",
        profileName,
        sensitiveEntries,
      );

      if (outboundMatches.length > 0 && !opts.allowSensitive) {
        logOutbound({
          profile: profileName,
          action: "comment.reply",
          method: "POST",
          endpoint: `/posts/${postId}/comments`,
          status: "blocked",
          reason: "safety",
          content: sanitized.content ?? "",
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

      const res = await request(client, "POST", `/posts/${postId}/comments`, {
        body: { content: sanitized.content, parent_id: cmd.parent },
        idempotent: false,
      });

      if (handleDryRun(res, opts, { sanitization: sanitizationWarnings, safety: outboundMatches })) {
        logOutbound({
          profile: profileName,
          action: "comment.reply",
          method: "POST",
          endpoint: `/posts/${postId}/comments`,
          status: "dry_run",
          content: sanitized.content ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        return;
      }

      if (!res.ok) {
        if (res.status === 429) {
          applyRetryAfter(profileName, "comment", res.data);
        }
        logOutbound({
          profile: profileName,
          action: "comment.reply",
          method: "POST",
          endpoint: `/posts/${postId}/comments`,
          status: "blocked",
          reason: `http_${res.status}`,
          content: sanitized.content ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        printError(`Reply failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordComment(profileName);
      logOutbound({
        profile: profileName,
        action: "comment.reply",
        method: "POST",
        endpoint: `/posts/${postId}/comments`,
        status: "sent",
        content: sanitized.content ?? "",
        sanitization: sanitizationWarnings,
        safety: outboundMatches,
      });

      if (opts.json) {
        printJson({ result: res.data, safety: outboundMatches, sanitization: sanitizationWarnings });
        return;
      }
      printInfo("Reply posted.", opts);
      warnSanitization(sanitizationWarnings, opts, "sanitized outbound reply content");
    });
}
