import type { CommandContext } from "../cli/context";
import { listSensitiveEntries, loadSensitiveStore } from "../lib/config";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";
import { recordRequest } from "../lib/rate_limit";
import { scanOutbound } from "../lib/safety";

export function registerDmCommands(ctx: CommandContext): void {
  const {
    program,
    globals,
    buildClient,
    sanitizeFields,
    warnSanitization,
    enforceRateLimit,
    logOutbound,
    handleDryRun,
    handleDmUnavailable,
    applyRetryAfter,
    attachInboundSafety,
    dmsEnabled,
  } = ctx;

  if (!dmsEnabled) return;

  const dm = program.command("dm").description("Direct messages");

  dm.command("check")
    .description("Check DM requests and unread messages")
    .action(async () => {
      const opts = globals();
      const { client } = buildClient(true);
      const res = await request(client, "GET", "/agents/dm/check", { idempotent: true });

      if (handleDmUnavailable(res, opts, "dm.check")) return;
      if (!res.ok) {
        printError(`DM check failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const { data, safety, sanitization } = await attachInboundSafety(res.data);
      if (opts.json) {
        printJson({ result: data, safety, sanitization });
        return;
      }

      warnSanitization(sanitization, opts, "sanitized inbound dm check");
      if (safety.length > 0) {
        printInfo("Warning: potential prompt-injection patterns detected in DM check results.", opts);
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });

  dm.command("requests")
    .description("List pending DM requests")
    .action(async () => {
      const opts = globals();
      const { client } = buildClient(true);
      const res = await request(client, "GET", "/agents/dm/requests", { idempotent: true });

      if (handleDmUnavailable(res, opts, "dm.requests")) return;
      if (!res.ok) {
        printError(`DM requests failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const { data, safety, sanitization } = await attachInboundSafety(res.data);
      if (opts.json) {
        printJson({ result: data, safety, sanitization });
        return;
      }

      warnSanitization(sanitization, opts, "sanitized inbound dm requests");
      if (safety.length > 0) {
        printInfo("Warning: potential prompt-injection patterns detected in DM requests.", opts);
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });

  dm.command("approve")
    .description("Approve a DM request")
    .argument("<conv_id>", "Conversation ID")
    .action(async (convId) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "dm.approve",
          method: "POST",
          endpoint: `/agents/dm/requests/${convId}/approve`,
          status: "blocked",
          reason: "rate_limit",
        });
        process.exit(1);
      }
      const res = await request(client, "POST", `/agents/dm/requests/${convId}/approve`, {
        idempotent: false,
      });

      if (handleDmUnavailable(res, opts, "dm.approve")) return;
      if (handleDryRun(res, opts, { conversation: convId })) {
        logOutbound({
          profile: profileName,
          action: "dm.approve",
          method: "POST",
          endpoint: `/agents/dm/requests/${convId}/approve`,
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
          action: "dm.approve",
          method: "POST",
          endpoint: `/agents/dm/requests/${convId}/approve`,
          status: "blocked",
          reason: `http_${res.status}`,
        });
        printError(`DM approve failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "dm.approve",
        method: "POST",
        endpoint: `/agents/dm/requests/${convId}/approve`,
        status: "sent",
      });

      if (opts.json) {
        printJson({ result: res.data || { approved: convId } });
        return;
      }
      printInfo(`Approved DM ${convId}.`, opts);
    });

  dm.command("reject")
    .description("Reject a DM request")
    .argument("<conv_id>", "Conversation ID")
    .option("--block", "Block future requests from this agent")
    .action(async (convId, cmd) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "dm.reject",
          method: "POST",
          endpoint: `/agents/dm/requests/${convId}/reject`,
          status: "blocked",
          reason: "rate_limit",
          meta: { block: !!cmd.block },
        });
        process.exit(1);
      }
      const res = await request(client, "POST", `/agents/dm/requests/${convId}/reject`, {
        body: cmd.block ? { block: true } : undefined,
        idempotent: false,
      });

      if (handleDmUnavailable(res, opts, "dm.reject")) return;
      if (handleDryRun(res, opts, { conversation: convId, block: !!cmd.block })) {
        logOutbound({
          profile: profileName,
          action: "dm.reject",
          method: "POST",
          endpoint: `/agents/dm/requests/${convId}/reject`,
          status: "dry_run",
          meta: { block: !!cmd.block },
        });
        return;
      }

      if (!res.ok) {
        if (res.status === 429) {
          applyRetryAfter(profileName, "request", res.data);
        }
        logOutbound({
          profile: profileName,
          action: "dm.reject",
          method: "POST",
          endpoint: `/agents/dm/requests/${convId}/reject`,
          status: "blocked",
          reason: `http_${res.status}`,
          meta: { block: !!cmd.block },
        });
        printError(`DM reject failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "dm.reject",
        method: "POST",
        endpoint: `/agents/dm/requests/${convId}/reject`,
        status: "sent",
        meta: { block: !!cmd.block },
      });

      if (opts.json) {
        printJson({ result: res.data || { rejected: convId }, block: !!cmd.block });
        return;
      }
      printInfo(`Rejected DM ${convId}.`, opts);
    });

  dm.command("list")
    .description("List DM conversations")
    .action(async () => {
      const opts = globals();
      const { client } = buildClient(true);
      const res = await request(client, "GET", "/agents/dm/conversations", { idempotent: true });

      if (handleDmUnavailable(res, opts, "dm.list")) return;
      if (!res.ok) {
        printError(`DM list failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const { data, safety, sanitization } = await attachInboundSafety(res.data);
      if (opts.json) {
        printJson({ result: data, safety, sanitization });
        return;
      }

      warnSanitization(sanitization, opts, "sanitized inbound dm list");
      if (safety.length > 0) {
        printInfo("Warning: potential prompt-injection patterns detected in DM list.", opts);
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });

  dm.command("show")
    .description("Show a DM conversation")
    .argument("<conv_id>", "Conversation ID")
    .action(async (convId) => {
      const opts = globals();
      const { client } = buildClient(true);
      const res = await request(client, "GET", `/agents/dm/conversations/${convId}`, {
        idempotent: true,
      });

      if (handleDmUnavailable(res, opts, "dm.show")) return;
      if (!res.ok) {
        printError(`DM show failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const { data, safety, sanitization } = await attachInboundSafety(res.data);
      if (opts.json) {
        printJson({ result: data, safety, sanitization });
        return;
      }

      warnSanitization(sanitization, opts, "sanitized inbound dm conversation");
      if (safety.length > 0) {
        printInfo("Warning: potential prompt-injection patterns detected in DM conversation.", opts);
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });

  dm.command("send")
    .description("Send a DM message")
    .argument("<conv_id>", "Conversation ID")
    .requiredOption("--message <text>", "Message content")
    .action(async (convId, cmd) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      const { sanitized, warnings: sanitizationWarnings } = sanitizeFields({
        message: cmd.message,
      });

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "dm.send",
          method: "POST",
          endpoint: `/agents/dm/conversations/${convId}/send`,
          status: "blocked",
          reason: "rate_limit",
          content: sanitized.message ?? "",
          sanitization: sanitizationWarnings,
        });
        process.exit(1);
      }

      const sensitiveStore = loadSensitiveStore();
      const sensitiveEntries = listSensitiveEntries(sensitiveStore, profileName);
      const outboundMatches = await scanOutbound(
        sanitized.message ?? "",
        profileName,
        sensitiveEntries,
      );

      if (outboundMatches.length > 0 && !opts.allowSensitive) {
        logOutbound({
          profile: profileName,
          action: "dm.send",
          method: "POST",
          endpoint: `/agents/dm/conversations/${convId}/send`,
          status: "blocked",
          reason: "safety",
          content: sanitized.message ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        if (opts.json) {
          printJson({
            blocked: true,
            matches: outboundMatches,
            sanitization: sanitizationWarnings,
          });
        } else {
          printError("Outbound content flagged as sensitive. Use --allow-sensitive to override.", opts);
        }
        process.exit(1);
      }

      const res = await request(client, "POST", `/agents/dm/conversations/${convId}/send`, {
        body: { message: sanitized.message },
        idempotent: false,
      });

      if (handleDmUnavailable(res, opts, "dm.send")) return;
      if (handleDryRun(res, opts, { sanitization: sanitizationWarnings, safety: outboundMatches })) {
        logOutbound({
          profile: profileName,
          action: "dm.send",
          method: "POST",
          endpoint: `/agents/dm/conversations/${convId}/send`,
          status: "dry_run",
          content: sanitized.message ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        return;
      }

      if (!res.ok) {
        if (res.status === 429) {
          applyRetryAfter(profileName, "request", res.data);
        }
        logOutbound({
          profile: profileName,
          action: "dm.send",
          method: "POST",
          endpoint: `/agents/dm/conversations/${convId}/send`,
          status: "blocked",
          reason: `http_${res.status}`,
          content: sanitized.message ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        printError(`DM send failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "dm.send",
        method: "POST",
        endpoint: `/agents/dm/conversations/${convId}/send`,
        status: "sent",
        content: sanitized.message ?? "",
        sanitization: sanitizationWarnings,
        safety: outboundMatches,
      });

      if (opts.json) {
        printJson({
          result: res.data,
          safety: outboundMatches,
          sanitization: sanitizationWarnings,
        });
        return;
      }
      printInfo("DM sent.", opts);
      warnSanitization(sanitizationWarnings, opts, "sanitized outbound dm message");
    });

  dm.command("request")
    .description("Request a new DM conversation")
    .option("--to <agent>", "Agent name")
    .option("--to-owner <handle>", "Owner X handle")
    .requiredOption("--message <text>", "Intro message")
    .action(async (cmd) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      if (!cmd.to && !cmd.toOwner) {
        printError("Provide --to or --to-owner.", opts);
        process.exit(1);
      }

      const { sanitized, warnings: sanitizationWarnings } = sanitizeFields({
        message: cmd.message,
      });

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "dm.request",
          method: "POST",
          endpoint: "/agents/dm/request",
          status: "blocked",
          reason: "rate_limit",
          content: sanitized.message ?? "",
          sanitization: sanitizationWarnings,
          meta: { to: cmd.to, to_owner: cmd.toOwner },
        });
        process.exit(1);
      }

      const sensitiveStore = loadSensitiveStore();
      const sensitiveEntries = listSensitiveEntries(sensitiveStore, profileName);
      const outboundMatches = await scanOutbound(
        sanitized.message ?? "",
        profileName,
        sensitiveEntries,
      );

      if (outboundMatches.length > 0 && !opts.allowSensitive) {
        logOutbound({
          profile: profileName,
          action: "dm.request",
          method: "POST",
          endpoint: "/agents/dm/request",
          status: "blocked",
          reason: "safety",
          content: sanitized.message ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
          meta: { to: cmd.to, to_owner: cmd.toOwner },
        });
        if (opts.json) {
          printJson({
            blocked: true,
            matches: outboundMatches,
            sanitization: sanitizationWarnings,
          });
        } else {
          printError("Outbound content flagged as sensitive. Use --allow-sensitive to override.", opts);
        }
        process.exit(1);
      }

      const res = await request(client, "POST", "/agents/dm/request", {
        body: {
          ...(cmd.to ? { to: cmd.to } : {}),
          ...(cmd.toOwner ? { to_owner: cmd.toOwner } : {}),
          message: sanitized.message,
        },
        idempotent: false,
      });

      if (handleDmUnavailable(res, opts, "dm.request")) return;
      if (handleDryRun(res, opts, { sanitization: sanitizationWarnings, safety: outboundMatches })) {
        logOutbound({
          profile: profileName,
          action: "dm.request",
          method: "POST",
          endpoint: "/agents/dm/request",
          status: "dry_run",
          content: sanitized.message ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
          meta: { to: cmd.to, to_owner: cmd.toOwner },
        });
        return;
      }

      if (!res.ok) {
        if (res.status === 429) {
          applyRetryAfter(profileName, "request", res.data);
        }
        logOutbound({
          profile: profileName,
          action: "dm.request",
          method: "POST",
          endpoint: "/agents/dm/request",
          status: "blocked",
          reason: `http_${res.status}`,
          content: sanitized.message ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
          meta: { to: cmd.to, to_owner: cmd.toOwner },
        });
        printError(`DM request failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "dm.request",
        method: "POST",
        endpoint: "/agents/dm/request",
        status: "sent",
        content: sanitized.message ?? "",
        sanitization: sanitizationWarnings,
        safety: outboundMatches,
        meta: { to: cmd.to, to_owner: cmd.toOwner },
      });

      if (opts.json) {
        printJson({
          result: res.data,
          safety: outboundMatches,
          sanitization: sanitizationWarnings,
        });
        return;
      }
      const target = cmd.to ? cmd.to : cmd.toOwner;
      printInfo(`DM request sent to ${target}.`, opts);
      warnSanitization(sanitizationWarnings, opts, "sanitized outbound dm request");
    });
}
