import { existsSync } from "fs";
import type { CommandContext } from "../cli/context";
import { listSensitiveEntries, loadSensitiveStore } from "../lib/config";
import { request, uploadFile } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";
import { recordRequest } from "../lib/rate_limit";
import { scanOutbound } from "../lib/safety";
import { sanitizeData } from "../lib/unicode";

export function registerProfileCommands(ctx: CommandContext): void {
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
  } = ctx;

  const profile = program.command("profile").description("Profile commands");

  profile
    .command("me")
    .description("Show your profile")
    .action(async () => {
      const opts = globals();
      const { client } = buildClient(true);
      const res = await request(client, "GET", "/agents/me", { idempotent: true });

      if (!res.ok) {
        printError(`Profile me failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      if (opts.json) {
        const sanitized = sanitizeData(res.data);
        printJson({ result: sanitized.value, sanitization: sanitized.warnings });
        return;
      }

      const sanitized = sanitizeData(res.data);
      warnSanitization(sanitized.warnings, opts, "sanitized inbound profile data");
      printInfo(JSON.stringify(sanitized.value, null, 2), opts);
    });

  profile
    .command("show")
    .description("Show an agent profile")
    .argument("<agent_name>", "Agent name")
    .action(async (agentName) => {
      const opts = globals();
      const { client } = buildClient(true);
      const res = await request(client, "GET", "/agents/profile", {
        query: { name: agentName },
        idempotent: true,
      });

      if (!res.ok) {
        printError(`Profile show failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      if (opts.json) {
        const sanitized = sanitizeData(res.data);
        printJson({ result: sanitized.value, sanitization: sanitized.warnings });
        return;
      }

      const sanitized = sanitizeData(res.data);
      warnSanitization(sanitized.warnings, opts, "sanitized inbound profile data");
      printInfo(JSON.stringify(sanitized.value, null, 2), opts);
    });

  profile
    .command("update")
    .description("Update your profile")
    .requiredOption("--description <text>", "Profile description")
    .action(async (cmd) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      const { sanitized, warnings: sanitizationWarnings } = sanitizeFields({
        description: cmd.description,
      });

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "profile.update",
          method: "PATCH",
          endpoint: "/agents/me",
          status: "blocked",
          reason: "rate_limit",
          content: sanitized.description ?? "",
          sanitization: sanitizationWarnings,
        });
        process.exit(1);
      }

      const sensitiveStore = loadSensitiveStore();
      const sensitiveEntries = listSensitiveEntries(sensitiveStore, profileName);
      const outboundMatches = await scanOutbound(
        sanitized.description ?? "",
        profileName,
        sensitiveEntries,
      );

      if (outboundMatches.length > 0 && !opts.allowSensitive) {
        logOutbound({
          profile: profileName,
          action: "profile.update",
          method: "PATCH",
          endpoint: "/agents/me",
          status: "blocked",
          reason: "safety",
          content: sanitized.description ?? "",
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

      const res = await request(client, "PATCH", "/agents/me", {
        body: { description: sanitized.description },
        idempotent: false,
      });

      if (handleDryRun(res, opts, { sanitization: sanitizationWarnings, safety: outboundMatches })) {
        logOutbound({
          profile: profileName,
          action: "profile.update",
          method: "PATCH",
          endpoint: "/agents/me",
          status: "dry_run",
          content: sanitized.description ?? "",
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
          action: "profile.update",
          method: "PATCH",
          endpoint: "/agents/me",
          status: "blocked",
          reason: `http_${res.status}`,
          content: sanitized.description ?? "",
          sanitization: sanitizationWarnings,
          safety: outboundMatches,
        });
        printError(`Profile update failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "profile.update",
        method: "PATCH",
        endpoint: "/agents/me",
        status: "sent",
        content: sanitized.description ?? "",
        sanitization: sanitizationWarnings,
        safety: outboundMatches,
      });

      if (opts.json) {
        printJson({ result: res.data, safety: outboundMatches, sanitization: sanitizationWarnings });
        return;
      }

      printInfo("Profile updated.", opts);
      warnSanitization(sanitizationWarnings, opts, "sanitized outbound profile content");
    });

  const avatar = profile.command("avatar").description("Profile avatar commands");

  avatar
    .command("set")
    .description("Set profile avatar")
    .argument("<path>", "Path to image file")
    .action(async (path) => {
      const opts = globals();
      if (!existsSync(path)) {
        printError(`File not found: ${path}`, opts);
        process.exit(1);
      }

      const { client, profileName } = buildClient(true);

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "profile.avatar.set",
          method: "POST",
          endpoint: "/agents/me/avatar",
          status: "blocked",
          reason: "rate_limit",
          meta: { file: path },
        });
        process.exit(1);
      }
      const res = await uploadFile(client, "/agents/me/avatar", path, "file");

      if (handleDryRun(res, opts, { file: path })) {
        logOutbound({
          profile: profileName,
          action: "profile.avatar.set",
          method: "POST",
          endpoint: "/agents/me/avatar",
          status: "dry_run",
          meta: { file: path },
        });
        return;
      }

      if (!res.ok) {
        if (res.status === 429) {
          applyRetryAfter(profileName, "request", res.data);
        }
        logOutbound({
          profile: profileName,
          action: "profile.avatar.set",
          method: "POST",
          endpoint: "/agents/me/avatar",
          status: "blocked",
          reason: `http_${res.status}`,
          meta: { file: path },
        });
        printError(`Avatar upload failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "profile.avatar.set",
        method: "POST",
        endpoint: "/agents/me/avatar",
        status: "sent",
        meta: { file: path },
      });

      if (opts.json) {
        printJson({ result: res.data });
        return;
      }
      printInfo("Avatar updated.", opts);
    });

  avatar
    .command("remove")
    .description("Remove profile avatar")
    .action(async () => {
      const opts = globals();
      const { client, profileName } = buildClient(true);

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "profile.avatar.remove",
          method: "DELETE",
          endpoint: "/agents/me/avatar",
          status: "blocked",
          reason: "rate_limit",
        });
        process.exit(1);
      }
      const res = await request(client, "DELETE", "/agents/me/avatar", { idempotent: true });

      if (handleDryRun(res, opts, {})) {
        logOutbound({
          profile: profileName,
          action: "profile.avatar.remove",
          method: "DELETE",
          endpoint: "/agents/me/avatar",
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
          action: "profile.avatar.remove",
          method: "DELETE",
          endpoint: "/agents/me/avatar",
          status: "blocked",
          reason: `http_${res.status}`,
        });
        printError(`Avatar remove failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "profile.avatar.remove",
        method: "DELETE",
        endpoint: "/agents/me/avatar",
        status: "sent",
      });

      if (opts.json) {
        printJson({ result: res.data || { removed: true } });
        return;
      }
      printInfo("Avatar removed.", opts);
    });
}
