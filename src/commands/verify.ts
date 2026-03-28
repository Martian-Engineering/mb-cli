import type { CommandContext } from "../cli/context";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";
import { recordRequest } from "../lib/rate_limit";

export function registerVerifyCommands(ctx: CommandContext): void {
  const { program, globals, buildClient, enforceRateLimit, logOutbound, handleDryRun, applyRetryAfter } =
    ctx;

  program
    .command("verify")
    .description("Submit a verification challenge answer")
    .requiredOption("--code <verification_code>", "Verification code from the challenge")
    .requiredOption("--answer <answer>", "Answer to the verification challenge (always sent as string)")
    .action(async (cmd) => {
      const opts = globals();
      const { client, profileName } = buildClient(true);
      const endpoint = "/verify";
      const verificationCode = String(cmd.code);
      const answer = String(cmd.answer);

      try {
        await enforceRateLimit(profileName, "request", opts);
      } catch {
        logOutbound({
          profile: profileName,
          action: "verify",
          method: "POST",
          endpoint,
          status: "blocked",
          reason: "rate_limit",
        });
        process.exit(1);
      }

      const res = await request(client, "POST", endpoint, {
        body: { verification_code: verificationCode, answer },
        idempotent: false,
      });

      if (handleDryRun(res, opts, { verification_code: verificationCode })) {
        logOutbound({
          profile: profileName,
          action: "verify",
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
          action: "verify",
          method: "POST",
          endpoint,
          status: "blocked",
          reason: `http_${res.status}`,
        });
        printError(
          `Verification failed (${res.status}): ${res.error || "unknown error"}\n` +
            "⚠️  Failed attempts count toward AI verification challenges. " +
            "10 failures triggers a 24-hour account suspension.",
          opts,
        );
        process.exit(1);
      }

      recordRequest(profileName);
      logOutbound({
        profile: profileName,
        action: "verify",
        method: "POST",
        endpoint,
        status: "sent",
      });

      if (opts.json) {
        printJson({ result: res.data || { verified: true }, verification_code: verificationCode });
        return;
      }
      printInfo("Verification submitted successfully.", opts);
    });
}
