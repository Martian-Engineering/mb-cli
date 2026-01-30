import type { CommandContext } from "../cli/context";
import {
  getProfile,
  loadCredentials,
  removeStoredApiKey,
  resolveProfileName,
  saveCredentials,
  upsertProfile,
} from "../lib/config";
import { request } from "../lib/http";
import { printError, printInfo, printJson } from "../lib/output";
import { sanitizeData } from "../lib/unicode";

export function registerAuthCommands(ctx: CommandContext): void {
  const { program, globals, buildClient, redactProfileData, warnSanitization } = ctx;

  const auth = program.command("auth").description("Auth utilities");

  auth
    .command("status")
    .description("Show auth status")
    .action(async () => {
      const opts = globals();
      const { client, profileName, profile } = buildClient(true);
      const res = await request(client, "GET", "/agents/me", { idempotent: true });

      if (!res.ok) {
        printError(`Auth status failed (${res.status}): ${res.error || "unknown error"}`, opts);
        process.exit(1);
      }

      const keySource = process.env.MOLTBOOK_API_KEY
        ? "env"
        : profile && typeof (profile as Record<string, unknown>).key_ref === "string"
          ? (profile as Record<string, unknown>).key_ref
          : (profile as Record<string, unknown>)?.api_key
            ? "file"
            : "unknown";

      if (opts.json) {
        const sanitized = sanitizeData(res.data);
        printJson({
          profile: profileName,
          key_source: keySource,
          profile_data: redactProfileData(profile),
          api_data: sanitized.value,
          sanitization: sanitized.warnings,
        });
        return;
      }

      printInfo(`Profile: ${profileName}`, opts);
      printInfo(`API key: ${keySource}`, opts);
      const sanitized = sanitizeData(res.data);
      warnSanitization(sanitized.warnings, opts, "sanitized inbound profile data");
      printInfo(JSON.stringify(sanitized.value, null, 2), opts);
    });

  auth
    .command("logout")
    .description("Remove stored API key for current profile")
    .action(() => {
      const opts = globals();
      const profileName = resolveProfileName(opts.profile);
      const store = loadCredentials();
      const profile = getProfile(store, profileName);
      const keyRef = profile?.key_ref;
      if (!profile || (!profile.api_key && keyRef !== "keychain")) {
        printInfo(`No stored API key for profile '${profileName}'.`, opts);
        return;
      }
      removeStoredApiKey(profileName, keyRef);
      const updated = upsertProfile(store, profileName, { api_key: undefined, key_ref: undefined });
      saveCredentials(updated);
      if (opts.json) {
        printJson({ profile: profileName, removed: true, key_source: keyRef || "file" });
        return;
      }
      printInfo(`Removed API key for profile '${profileName}'.`, opts);
    });
}
