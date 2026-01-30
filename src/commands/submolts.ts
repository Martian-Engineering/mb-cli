import type { CommandContext } from "../cli/context";
import { listSensitiveEntries, loadSensitiveStore } from "../lib/config";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";
import { recordRequest } from "../lib/rate_limit";
import { scanOutbound } from "../lib/safety";

export function registerSubmoltCommands(ctx: CommandContext): void {
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

  const submolts = program.command("submolts").description("Submolt commands");

  submolts
    .command("list")
    .description("List submolts")
    .action(async () => {
      const opts = globals();
      const { client } = buildClient(true);
      const res = await request(client, "GET", "/submolts", { idempotent: true });

      if (!res.ok) {
        printError(`Submolts list failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const { data, safety, sanitization } = await attachInboundSafety(res.data);
      if (opts.json) {
        printJson({ result: data, safety, sanitization });
        return;
      }

      warnSanitization(sanitization, opts, "sanitized inbound submolt list");
      if (safety.length > 0) {
        printInfo("Warning: potential prompt-injection patterns detected in submolt list.", opts);
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });

  submolts
    .command("show")
    .description("Show a submolt")
    .argument("<name>", "Submolt name")
    .action(async (name) => {
      const opts = globals();
      const { client } = buildClient(true);
      const res = await request(client, "GET", `/submolts/${name}`, { idempotent: true });

      if (!res.ok) {
        printError(`Submolt show failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const { data, safety, sanitization } = await attachInboundSafety(res.data);
      if (opts.json) {
        printJson({ result: data, safety, sanitization });
        return;
      }

      warnSanitization(sanitization, opts, "sanitized inbound submolt details");
      if (safety.length > 0) {
        printInfo("Warning: potential prompt-injection patterns detected in submolt details.", opts);
      }
      printInfo(JSON.stringify(data, null, 2), opts);
    });

  submolts
    .command("create")
    .description("Create a submolt")
    .requiredOption("--name <name>", "Submolt name")
    .requiredOption("--display-name <name>", "Display name")
    .requiredOption("--description <text>", "Description")
    .action(async (cmd) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);
      const { sanitized, warnings: sanitizationWarnings } = sanitizeFields({
        name: cmd.name,
        displayName: cmd.displayName,
        description: cmd.description,
      });
      const outboundText = [sanitized.name, sanitized.displayName, sanitized.description]
        .filter(Boolean)
        .join("\n");

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "submolt.create",
          method: "POST",
          endpoint: "/submolts",
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
          action: "submolt.create",
          method: "POST",
          endpoint: "/submolts",
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

      const res = await request(client, "POST", "/submolts", {
        body: {
          name: sanitized.name,
          display_name: sanitized.displayName,
          description: sanitized.description,
        },
        idempotent: false,
      });

      if (handleDryRun(res, opts, { sanitization: sanitizationWarnings, safety: outboundMatches })) {
        logOutbound({
          profile: profileName,
          action: "submolt.create",
          method: "POST",
          endpoint: "/submolts",
          status: "dry_run",
          content: outboundText,
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
          action: "submolt.create",
          method: "POST",
          endpoint: "/submolts",
          status: "blocked",
          reason: `http_${res.status}`,
          content: outboundText,
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        printError(`Submolt create failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "submolt.create",
        method: "POST",
        endpoint: "/submolts",
        status: "sent",
        content: outboundText,
        sanitization: sanitizationWarnings,
        safety: outboundMatches,
      });

      if (opts.json) {
        printJson({ result: res.data, safety: outboundMatches, sanitization: sanitizationWarnings });
        return;
      }
      printInfo("Submolt created.", opts);
      warnSanitization(sanitizationWarnings, opts, "sanitized outbound submolt content");
    });

  submolts
    .command("subscribe")
    .description("Subscribe to a submolt")
    .argument("<name>", "Submolt name")
    .action(async (name) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "submolt.subscribe",
          method: "POST",
          endpoint: `/submolts/${name}/subscribe`,
          status: "blocked",
          reason: "rate_limit",
        });
        process.exit(1);
      }
      const res = await request(client, "POST", `/submolts/${name}/subscribe`, { idempotent: false });

      if (handleDryRun(res, opts, { submolt: name })) {
        logOutbound({
          profile: profileName,
          action: "submolt.subscribe",
          method: "POST",
          endpoint: `/submolts/${name}/subscribe`,
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
          action: "submolt.subscribe",
          method: "POST",
          endpoint: `/submolts/${name}/subscribe`,
          status: "blocked",
          reason: `http_${res.status}`,
        });
        printError(`Subscribe failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "submolt.subscribe",
        method: "POST",
        endpoint: `/submolts/${name}/subscribe`,
        status: "sent",
      });

      if (opts.json) {
        printJson({ result: res.data || { subscribed: name } });
        return;
      }
      printInfo(`Subscribed to ${name}.`, opts);
    });

  submolts
    .command("unsubscribe")
    .description("Unsubscribe from a submolt")
    .argument("<name>", "Submolt name")
    .action(async (name) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "submolt.unsubscribe",
          method: "DELETE",
          endpoint: `/submolts/${name}/subscribe`,
          status: "blocked",
          reason: "rate_limit",
        });
        process.exit(1);
      }
      const res = await request(client, "DELETE", `/submolts/${name}/subscribe`, {
        idempotent: true,
      });

      if (handleDryRun(res, opts, { submolt: name })) {
        logOutbound({
          profile: profileName,
          action: "submolt.unsubscribe",
          method: "DELETE",
          endpoint: `/submolts/${name}/subscribe`,
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
          action: "submolt.unsubscribe",
          method: "DELETE",
          endpoint: `/submolts/${name}/subscribe`,
          status: "blocked",
          reason: `http_${res.status}`,
        });
        printError(`Unsubscribe failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "submolt.unsubscribe",
        method: "DELETE",
        endpoint: `/submolts/${name}/subscribe`,
        status: "sent",
      });

      if (opts.json) {
        printJson({ result: res.data || { unsubscribed: name } });
        return;
      }
      printInfo(`Unsubscribed from ${name}.`, opts);
    });
}
