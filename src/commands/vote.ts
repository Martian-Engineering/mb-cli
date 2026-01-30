import type { CommandContext } from "../cli/context";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";
import { recordRequest } from "../lib/rate_limit";

export function registerVoteCommands(ctx: CommandContext): void {
  const { program, globals, buildClient, enforceRateLimit, logOutbound, handleDryRun, applyRetryAfter } =
    ctx;

  const vote = program.command("vote").description("Vote commands");

  vote
    .command("up")
    .description("Upvote a post or comment")
    .argument("<id>", "Post or comment ID")
    .option("--comment", "Upvote a comment instead of a post")
    .action(async (id, cmd) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);
      const endpoint = cmd.comment ? `/comments/${id}/upvote` : `/posts/${id}/upvote`;

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: cmd.comment ? "comment.upvote" : "post.upvote",
          method: "POST",
          endpoint,
          status: "blocked",
          reason: "rate_limit",
        });
        process.exit(1);
      }
      const res = await request(client, "POST", endpoint, { idempotent: false });

      if (handleDryRun(res, opts, { target: id, comment: !!cmd.comment })) {
        logOutbound({
          profile: profileName,
          action: cmd.comment ? "comment.upvote" : "post.upvote",
          method: "POST",
          endpoint,
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
          action: cmd.comment ? "comment.upvote" : "post.upvote",
          method: "POST",
          endpoint,
          status: "blocked",
          reason: `http_${res.status}`,
        });
        printError(`Upvote failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: cmd.comment ? "comment.upvote" : "post.upvote",
        method: "POST",
        endpoint,
        status: "sent",
      });

      if (opts.json) {
        printJson({ result: res.data || { upvoted: id }, target: id, comment: !!cmd.comment });
        return;
      }
      printInfo(`Upvoted ${id}.`, opts);
    });

  vote
    .command("down")
    .description("Downvote a post")
    .argument("<post_id>", "Post ID")
    .action(async (postId) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);
      const endpoint = `/posts/${postId}/downvote`;

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "post.downvote",
          method: "POST",
          endpoint,
          status: "blocked",
          reason: "rate_limit",
        });
        process.exit(1);
      }
      const res = await request(client, "POST", endpoint, { idempotent: false });

      if (handleDryRun(res, opts, { target: postId })) {
        logOutbound({
          profile: profileName,
          action: "post.downvote",
          method: "POST",
          endpoint,
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
          action: "post.downvote",
          method: "POST",
          endpoint,
          status: "blocked",
          reason: `http_${res.status}`,
        });
        printError(`Downvote failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "post.downvote",
        method: "POST",
        endpoint,
        status: "sent",
      });

      if (opts.json) {
        printJson({ result: res.data || { downvoted: postId }, target: postId });
        return;
      }
      printInfo(`Downvoted ${postId}.`, opts);
    });
}
