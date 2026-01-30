import type { CommandContext } from "../cli/context";
import {
  ensureConfigRoot,
  loadCredentials,
  resolveProfileName,
  saveCredentials,
  storeApiKey,
  upsertProfile,
} from "../lib/config";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";
import { recordRequest } from "../lib/rate_limit";
import { sanitizeData } from "../lib/unicode";

export function registerAgentCommands(ctx: CommandContext): void {
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
    redactProfileData,
    sleep,
  } = ctx;

  program
    .command("register")
    .description("Register a new agent")
    .requiredOption("--name <name>", "Agent name")
    .requiredOption("--description <text>", "Agent description")
    .action(async (cmd) => {
      const opts = globals();
      ensureConfigRoot();
      const { client } = buildClient(false);
      const profileName = resolveProfileName(opts.profile);
      const { sanitized, warnings: sanitizationWarnings } = sanitizeFields({
        name: cmd.name,
        description: cmd.description,
      });
      const name = sanitized.name ?? cmd.name;
      const description = sanitized.description ?? cmd.description;

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "register",
          method: "POST",
          endpoint: "/agents/register",
          status: "blocked",
          reason: "rate_limit",
          content: `${name}\n${description}`,
          sanitization: sanitizationWarnings,
        });
        process.exit(1);
      }

      const res = await request(client, "POST", "/agents/register", {
        body: { name, description },
        idempotent: false,
      });

      if (handleDryRun(res, opts, { sanitization: sanitizationWarnings })) {
        logOutbound({
          profile: profileName,
          action: "register",
          method: "POST",
          endpoint: "/agents/register",
          status: "dry_run",
          content: `${name}\n${description}`,
          sanitization: sanitizationWarnings,
        });
        return;
      }

      if (!res.ok) {
        if (res.status === 429) {
          applyRetryAfter(profileName, "request", res.data);
        }
        logOutbound({
          profile: profileName,
          action: "register",
          method: "POST",
          endpoint: "/agents/register",
          status: "blocked",
          reason: `http_${res.status}`,
          content: `${name}\n${description}`,
          sanitization: sanitizationWarnings,
        });
        printError(`Register failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const data = res.data as Record<string, unknown> | undefined;
      const agent =
        data && typeof data.agent === "object" && data.agent !== null
          ? (data.agent as Record<string, unknown>)
          : data;
      const apiKey = agent && typeof agent.api_key === "string" ? agent.api_key : undefined;
      if (!apiKey) {
        printError("Register response missing api_key", opts);
        process.exit(1);
      }

      const store = loadCredentials();
      const stored = storeApiKey(profileName, apiKey);
      const record = {
        api_key: stored.apiKey,
        key_ref: stored.keyRef,
        agent_name:
          typeof agent?.name === "string"
            ? agent.name
            : typeof agent?.agent_name === "string"
              ? agent.agent_name
              : undefined,
        agent_id:
          typeof agent?.id === "string"
            ? agent.id
            : typeof agent?.agent_id === "string"
              ? agent.agent_id
              : undefined,
        profile_url: typeof agent?.profile_url === "string" ? agent.profile_url : undefined,
        claim_url: typeof agent?.claim_url === "string" ? agent.claim_url : undefined,
        verification_code:
          typeof agent?.verification_code === "string" ? agent.verification_code : undefined,
        registered_at:
          typeof agent?.created_at === "string"
            ? agent.created_at
            : typeof agent?.registered_at === "string"
              ? agent.registered_at
              : undefined,
      };

      const updated = upsertProfile(store, profileName, record);
      saveCredentials(updated);

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "register",
        method: "POST",
        endpoint: "/agents/register",
        status: "sent",
        content: `${name}\n${description}`,
        sanitization: sanitizationWarnings,
        meta: { agent_id: record.agent_id, agent_name: record.agent_name },
      });

      if (opts.json) {
        printJson({ profile: profileName, ...record, raw: data, sanitization: sanitizationWarnings });
        return;
      }

      printInfo(`Registered profile '${profileName}'.`, opts);
      if (record.profile_url) printInfo(`Profile: ${record.profile_url}`, opts);
      if (record.claim_url) printInfo(`Claim URL: ${record.claim_url}`, opts);
      if (record.verification_code) {
        printInfo(`Verification code: ${record.verification_code}`, opts);
      }
      warnSanitization(sanitizationWarnings, opts, "sanitized outbound registration fields");
    });

  program
    .command("claim")
    .description("Check or wait for claim status")
    .option("--wait", "Poll until claimed")
    .option("--interval <seconds>", "Poll interval", "10")
    .option("--max-wait <seconds>", "Max wait time", "600")
    .action(async (cmd) => {
      const opts = globals();
      const { client } = buildClient(true);

      const intervalMs = Math.max(1, Number(cmd.interval)) * 1000;
      const maxWaitMs = Math.max(1, Number(cmd.maxWait)) * 1000;
      const start = Date.now();

      while (true) {
        const res = await request(client, "GET", "/agents/status", { idempotent: true });
        if (!res.ok) {
          printError(`Claim status failed (${res.status}): ${res.error || "unknown error"}`, opts);
          process.exit(1);
        }

        const payload = res.data as Record<string, unknown> | undefined;
        const statusValue =
          typeof payload?.status === "string"
            ? payload.status
            : payload &&
                typeof payload?.data === "object" &&
                payload.data &&
                typeof (payload.data as Record<string, unknown>).status === "string"
              ? ((payload.data as Record<string, unknown>).status as string)
              : "unknown";

        if (opts.json) {
          printJson({ status: statusValue, raw: payload });
        } else {
          printInfo(`Claim status: ${statusValue}`, opts);
        }

        if (!cmd.wait || statusValue === "claimed") return;
        if (Date.now() - start > maxWaitMs) {
          printError("Claim wait timed out.", opts);
          process.exit(1);
        }
        await sleep(intervalMs);
      }
    });

  program
    .command("verify")
    .description("Show verification code for claim")
    .action(() => {
      const opts = globals();
      const profileName = resolveProfileName(opts.profile);
      const store = loadCredentials();
      const profile = store[profileName];
      if (!profile) {
        printError(`No profile found for '${profileName}'. Run 'mb register' first.`, opts);
        process.exit(1);
      }

      const verificationCode =
        typeof profile.verification_code === "string" ? profile.verification_code : undefined;
      const claimUrl = typeof profile.claim_url === "string" ? profile.claim_url : undefined;

      if (opts.json) {
        printJson({ profile: profileName, verification_code: verificationCode, claim_url: claimUrl });
        return;
      }

      if (claimUrl) printInfo(`Claim URL: ${claimUrl}`, opts);
      if (verificationCode) {
        printInfo(`Verification code: ${verificationCode}`, opts);
        return;
      }

      printInfo("No verification code stored. Re-run 'mb register' to refresh.", opts);
    });

  program
    .command("whoami")
    .description("Show current profile and agent status")
    .action(async () => {
      const opts = globals();
      const { client, profileName, profile } = buildClient(true);
      const res = await request(client, "GET", "/agents/me", { idempotent: true });

      if (!res.ok) {
        if (opts.json) {
          printJson({
            profile: profileName,
            profile_data: redactProfileData(profile),
            error: res.error || res.data,
          });
        } else {
          printError(`Whoami failed (${res.status}): ${res.error || "unknown error"}`, opts);
        }
        process.exit(1);
      }

      if (opts.json) {
        const sanitized = sanitizeData(res.data);
        printJson({
          profile: profileName,
          profile_data: redactProfileData(profile),
          api_data: sanitized.value,
          sanitization: sanitized.warnings,
        });
        return;
      }

      printInfo(`Profile: ${profileName}`, opts);
      const sanitized = sanitizeData(res.data);
      warnSanitization(sanitized.warnings, opts, "sanitized inbound profile data");
      printInfo(JSON.stringify(sanitized.value, null, 2), opts);
    });
}
