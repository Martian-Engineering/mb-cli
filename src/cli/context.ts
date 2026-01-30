import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import type { Command } from "commander";
import { getApiKey, loadCredentials, resolveProfileName } from "../lib/config";
import { appendAudit, buildContentAudit } from "../lib/audit";
import { printError, printInfo, printJson } from "../lib/output";
import type { ClientOptions } from "../lib/http";
import { scanInbound } from "../lib/safety";
import { sanitizeData, sanitizeText } from "../lib/unicode";
import {
  applyServerRetryAfter,
  checkRateLimit,
  extractRetryAfterSeconds,
} from "../lib/rate_limit";
import { jailbreakDir, jailbreakRemotePath } from "../lib/paths";

type Globals = {
  profile?: string;
  baseUrl?: string;
  json?: boolean;
  timeout?: string | number;
  retries?: string | number;
  verbose?: boolean;
  dryRun?: boolean;
  quiet?: boolean;
  yes?: boolean;
  allowSensitive?: boolean;
  noColor?: boolean;
  wait?: boolean;
  maxWait?: string | number;
  [key: string]: unknown;
};

type BuildClientResult = {
  client: ClientOptions;
  profileName: string;
  profile: unknown;
};

export type LogOutboundParams = {
  profile: string;
  action: string;
  method: string;
  endpoint: string;
  status: "sent" | "blocked" | "dry_run";
  reason?: string;
  content?: string;
  safety?: unknown[];
  sanitization?: string[];
  meta?: Record<string, unknown>;
};

export type CommandContext = {
  program: Command;
  dmsEnabled: boolean;
  postReminder: string;
  globals: () => Globals;
  buildClient: (requireAuth: boolean) => BuildClientResult;
  redactProfileData: (profile: unknown) => unknown;
  sanitizeFields: (fields: Record<string, string | undefined>) => {
    sanitized: Record<string, string | undefined>;
    warnings: string[];
    changed: boolean;
  };
  warnSanitization: (warnings: string[], opts: Globals, context: string) => void;
  handleDryRun: (
    res: { dryRun?: boolean; data?: unknown },
    opts: Globals,
    extra?: Record<string, unknown>,
  ) => boolean;
  handleDmUnavailable: (
    res: { ok: boolean; status: number; data?: unknown; error?: string },
    opts: Globals,
    action: string,
  ) => boolean;
  sleep: (ms: number) => Promise<void>;
  saveJailbreakRemote: (url: string) => void;
  readJailbreakRemote: () => { url?: string };
  enforceRateLimit: (
    profile: string,
    action: "request" | "comment" | "post",
    opts: Globals,
  ) => Promise<void>;
  logOutbound: (params: LogOutboundParams) => void;
  applyRetryAfter: (profile: string, action: "request" | "comment" | "post", data: unknown) => void;
  attachInboundSafety: (data: unknown) => Promise<{
    data: unknown;
    safety: unknown[];
    sanitization: string[];
    meta: { truncated: boolean; qmd: string; scanned_chars?: number; total_chars?: number };
  }>;
};

type ContextOptions = {
  dmsEnabled: boolean;
  postReminder: string;
};

function collectStrings(value: unknown, acc: string[] = [], depth = 0): string[] {
  if (depth > 4) return acc;
  if (typeof value === "string") {
    acc.push(value);
    return acc;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, acc, depth + 1);
  } else if (value && typeof value === "object") {
    for (const val of Object.values(value)) collectStrings(val, acc, depth + 1);
  }
  return acc;
}

export function createCommandContext(program: Command, options: ContextOptions): CommandContext {
  const globals = () => program.opts();

  const buildClient = (requireAuth: boolean): BuildClientResult => {
    const opts = globals();
    const profileName = resolveProfileName(opts.profile);
    const store = loadCredentials();
    const apiKey = getApiKey(store, profileName);

    if (requireAuth && !apiKey) {
      printError(`No API key found for profile '${profileName}'. Run 'mb register' first.`, opts);
      process.exit(1);
    }

    const client: ClientOptions = {
      baseUrl: opts.baseUrl,
      apiKey: apiKey,
      timeoutMs: Math.max(1, Number(opts.timeout)) * 1000,
      retries: Math.max(0, Number(opts.retries)),
      verbose: !!opts.verbose,
      dryRun: !!opts.dryRun,
    };

    return { client, profileName, profile: store[profileName] };
  };

  const redactProfileData = (profile: unknown): unknown => {
    if (!profile || typeof profile !== "object") return profile;
    const record = { ...(profile as Record<string, unknown>) };
    if (typeof record.api_key === "string") {
      record.api_key = "[redacted]";
    }
    return record;
  };

  const sanitizeFields = (fields: Record<string, string | undefined>) => {
    const warnings = new Set<string>();
    let changed = false;
    const sanitized: Record<string, string | undefined> = {};

    for (const [key, value] of Object.entries(fields)) {
      if (typeof value !== "string") {
        sanitized[key] = value;
        continue;
      }
      const result = sanitizeText(value);
      result.warnings.forEach((warning) => warnings.add(warning));
      if (result.changed) changed = true;
      sanitized[key] = result.text;
    }

    return { sanitized, warnings: Array.from(warnings), changed };
  };

  const warnSanitization = (warnings: string[], opts: Globals, context: string) => {
    if (warnings.length === 0) return;
    printInfo(`Warning: ${context}: ${warnings.join("; ")}`, opts);
  };

  const handleDryRun = (
    res: { dryRun?: boolean; data?: unknown },
    opts: Globals,
    extra: Record<string, unknown> = {},
  ) => {
    if (!res.dryRun) return false;
    if (opts.json) {
      printJson({ ...extra, result: res.data, dry_run: true });
      return true;
    }
    printInfo("Dry run: request not sent.", opts);
    if (res.data) {
      printInfo(JSON.stringify(res.data, null, 2), opts);
    }
    return true;
  };

  const handleDmUnavailable = (
    res: { ok: boolean; status: number; data?: unknown; error?: string },
    opts: Globals,
    action: string,
  ): boolean => {
    if (res.ok || res.status !== 404) return false;
    const message = "DM API unavailable on this server (404).";
    if (opts.json) {
      printJson({
        unavailable: true,
        action,
        status: res.status,
        error: res.error || res.data || message,
      });
    } else {
      printInfo(message, opts);
    }
    return true;
  };

  const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

  const saveJailbreakRemote = (url: string): void => {
    const dir = jailbreakDir();
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const payload = { url, updated_at: new Date().toISOString() };
    writeFileSync(jailbreakRemotePath(), JSON.stringify(payload, null, 2), { mode: 0o600 });
  };

  const readJailbreakRemote = (): { url?: string } => {
    const path = jailbreakRemotePath();
    if (!existsSync(path)) return {};
    try {
      const raw = readFileSync(path, "utf-8");
      return JSON.parse(raw) as { url?: string };
    } catch {
      return {};
    }
  };

  const enforceRateLimit = async (
    profile: string,
    action: "request" | "comment" | "post",
    opts: Globals,
  ): Promise<void> => {
    if (opts.dryRun) return;
    const maxWait = Math.max(1, Number(opts.maxWait)) * 1000;
    while (true) {
      const decision = checkRateLimit(profile, action);
      if (decision.allowed) return;
      if (!opts.wait) {
        printError(
          `Rate limit hit: ${decision.reason}. Retry after ${Math.ceil(decision.waitMs / 1000)}s.`,
          opts,
        );
        throw new Error("rate_limit");
      }
      if (decision.waitMs > maxWait) {
        printError(`Rate limit wait exceeds max (${Math.ceil(decision.waitMs / 1000)}s).`, opts);
        throw new Error("rate_limit");
      }
      printInfo(
        `Rate limited (${decision.reason}). Waiting ${Math.ceil(decision.waitMs / 1000)}s...`,
        opts,
      );
      await sleep(decision.waitMs);
    }
  };

  const logOutbound = (params: LogOutboundParams): void => {
    const contentAudit = buildContentAudit(params.content);
    appendAudit({
      timestamp: new Date().toISOString(),
      profile: params.profile,
      action: params.action,
      method: params.method,
      endpoint: params.endpoint,
      status: params.status,
      reason: params.reason,
      safety_matches: params.safety,
      sanitization: params.sanitization,
      ...contentAudit,
      meta: params.meta,
    });
  };

  const applyRetryAfter = (profile: string, action: "request" | "comment" | "post", data: unknown) => {
    const retry = extractRetryAfterSeconds(data);
    if (retry && retry > 0) {
      applyServerRetryAfter(profile, action, retry);
    }
  };

  const attachInboundSafety = async (data: unknown) => {
    const sanitized = sanitizeData(data);
    const strings = collectStrings(sanitized.value);
    if (strings.length === 0) {
      return {
        data: sanitized.value,
        safety: [] as unknown[],
        sanitization: sanitized.warnings,
        meta: { truncated: false, qmd: "skipped" },
      };
    }
    const combined = strings.join("\n");
    const maxChars = Math.max(2000, Number(process.env.MB_INBOUND_MAX_CHARS ?? "20000"));
    const maxQmdChars = Math.max(2000, Number(process.env.MB_INBOUND_QMD_MAX_CHARS ?? "8000"));
    const truncated = combined.length > maxChars;
    const sample = truncated ? combined.slice(0, maxChars) : combined;
    const useQmd = sample.length <= maxQmdChars;
    const matches = await scanInbound(sample, { useQmd });
    const warnings = [...sanitized.warnings];
    if (truncated) warnings.push("Inbound safety scan truncated (large payload)");
    if (!useQmd) warnings.push("Inbound safety qmd scan skipped (large payload)");
    return {
      data: sanitized.value,
      safety: matches,
      sanitization: warnings,
      meta: {
        truncated,
        qmd: useQmd ? "used" : "skipped",
        scanned_chars: sample.length,
        total_chars: combined.length,
      },
    };
  };

  return {
    program,
    dmsEnabled: options.dmsEnabled,
    postReminder: options.postReminder,
    globals,
    buildClient,
    redactProfileData,
    sanitizeFields,
    warnSanitization,
    handleDryRun,
    handleDmUnavailable,
    sleep,
    saveJailbreakRemote,
    readJailbreakRemote,
    enforceRateLimit,
    logOutbound,
    applyRetryAfter,
    attachInboundSafety,
  };
}
