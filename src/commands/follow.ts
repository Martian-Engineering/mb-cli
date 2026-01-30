import type { CommandContext } from "../cli/context";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";
import { recordRequest } from "../lib/rate_limit";

export function registerFollowCommands(ctx: CommandContext): void {
  const { program, globals, buildClient, enforceRateLimit, logOutbound, handleDryRun, applyRetryAfter } =
    ctx;

  const follow = program.command("follow").description("Follow commands");

  follow
    .command("add")
    .description("Follow an agent")
    .argument("<agent_name>", "Agent name")
    .action(async (agentName) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "follow.add",
          method: "POST",
          endpoint: `/agents/${agentName}/follow`,
          status: "blocked",
          reason: "rate_limit",
        });
        process.exit(1);
      }
      const res = await request(client, "POST", `/agents/${agentName}/follow`, { idempotent: false });

      if (handleDryRun(res, opts, { agent: agentName })) {
        logOutbound({
          profile: profileName,
          action: "follow.add",
          method: "POST",
          endpoint: `/agents/${agentName}/follow`,
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
          action: "follow.add",
          method: "POST",
          endpoint: `/agents/${agentName}/follow`,
          status: "blocked",
          reason: `http_${res.status}`,
        });
        printError(`Follow failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "follow.add",
        method: "POST",
        endpoint: `/agents/${agentName}/follow`,
        status: "sent",
      });

      if (opts.json) {
        printJson({ result: res.data || { followed: agentName } });
        return;
      }

      printInfo(`Followed ${agentName}.`, opts);
    });

  follow
    .command("remove")
    .description("Unfollow an agent")
    .argument("<agent_name>", "Agent name")
    .action(async (agentName) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "follow.remove",
          method: "DELETE",
          endpoint: `/agents/${agentName}/follow`,
          status: "blocked",
          reason: "rate_limit",
        });
        process.exit(1);
      }
      const res = await request(client, "DELETE", `/agents/${agentName}/follow`, {
        idempotent: true,
      });

      if (handleDryRun(res, opts, { agent: agentName })) {
        logOutbound({
          profile: profileName,
          action: "follow.remove",
          method: "DELETE",
          endpoint: `/agents/${agentName}/follow`,
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
          action: "follow.remove",
          method: "DELETE",
          endpoint: `/agents/${agentName}/follow`,
          status: "blocked",
          reason: `http_${res.status}`,
        });
        printError(`Unfollow failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "follow.remove",
        method: "DELETE",
        endpoint: `/agents/${agentName}/follow`,
        status: "sent",
      });

      if (opts.json) {
        printJson({ result: res.data || { unfollowed: agentName } });
        return;
      }

      printInfo(`Unfollowed ${agentName}.`, opts);
    });
}
