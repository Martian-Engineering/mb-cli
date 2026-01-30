import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { configDir, credentialsPath, sensitiveStorePath } from "./paths";

export type ProfileRecord = Record<string, unknown> & {
  api_key?: string;
  key_ref?: "keychain" | "file";
  agent_name?: string;
  agent_id?: string;
  profile_url?: string;
  claim_url?: string;
  verification_code?: string;
  registered_at?: string;
};

export type CredentialsStore = Record<string, ProfileRecord>;

export type SensitiveEntry = {
  label: string;
  pattern: string;
  severity?: "low" | "medium" | "high";
  regex?: boolean;
};

export type SensitiveStore = Record<string, SensitiveEntry[]>;

function ensureDir(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
  }
}

function writeJsonAtomic(path: string, data: unknown): void {
  ensureDir(dirname(path));
  const tmp = `${path}.tmp`;
  const json = JSON.stringify(data, null, 2);
  writeFileSync(tmp, json, { mode: 0o600 });
  renameSync(tmp, path);
}

export function loadCredentials(): CredentialsStore {
  const path = credentialsPath();
  if (!existsSync(path)) {
    return {};
  }
  try {
    const raw = readFileSync(path, "utf-8");
    const parsed = JSON.parse(raw) as CredentialsStore;
    return parsed ?? {};
  } catch {
    return {};
  }
}

export function saveCredentials(store: CredentialsStore): void {
  writeJsonAtomic(credentialsPath(), store);
}

export function resolveProfileName(explicit?: string | undefined): string {
  if (explicit && explicit.trim().length > 0) return explicit.trim();
  const env = process.env.MOLTBOOK_PROFILE;
  if (env && env.trim().length > 0) return env.trim();
  return "default";
}

export function getProfile(store: CredentialsStore, profileName: string): ProfileRecord | undefined {
  return store[profileName];
}

export function upsertProfile(store: CredentialsStore, profileName: string, record: ProfileRecord): CredentialsStore {
  return {
    ...store,
    [profileName]: {
      ...(store[profileName] || {}),
      ...record,
    },
  };
}

export function getApiKey(store: CredentialsStore, profileName: string): string | undefined {
  const envKey = process.env.MOLTBOOK_API_KEY;
  if (envKey && envKey.trim().length > 0) {
    return envKey.trim();
  }
  const profile = store[profileName];
  if (profile?.key_ref === "keychain") {
    const keychainKey = readKeychainKey(profileName);
    if (keychainKey) return keychainKey;
  }
  return profile?.api_key;
}

function canUseKeychain(): boolean {
  return process.platform === "darwin" && !!Bun.which("security");
}

function runSecurity(args: string[]): { ok: boolean; stdout: string } {
  const proc = Bun.spawnSync(["security", ...args], { stdout: "pipe", stderr: "pipe" });
  const stdout = proc.stdout ? new TextDecoder().decode(proc.stdout) : "";
  return { ok: proc.exitCode === 0, stdout: stdout.trim() };
}

function keychainService(): string {
  return "mb-cli";
}

function readKeychainKey(profileName: string): string | undefined {
  if (!canUseKeychain()) return undefined;
  const res = runSecurity(["find-generic-password", "-a", profileName, "-s", keychainService(), "-w"]);
  return res.ok ? res.stdout : undefined;
}

function writeKeychainKey(profileName: string, apiKey: string): boolean {
  if (!canUseKeychain()) return false;
  const res = runSecurity(["add-generic-password", "-a", profileName, "-s", keychainService(), "-w", apiKey, "-U"]);
  return res.ok;
}

function deleteKeychainKey(profileName: string): boolean {
  if (!canUseKeychain()) return false;
  const res = runSecurity(["delete-generic-password", "-a", profileName, "-s", keychainService()]);
  return res.ok;
}

export function storeApiKey(profileName: string, apiKey: string): { keyRef: "keychain" | "file"; apiKey?: string } {
  if (writeKeychainKey(profileName, apiKey)) {
    return { keyRef: "keychain" };
  }
  return { keyRef: "file", apiKey };
}

export function removeStoredApiKey(profileName: string, keyRef?: "keychain" | "file"): void {
  if (keyRef === "keychain") {
    deleteKeychainKey(profileName);
    return;
  }
}

export function loadSensitiveStore(): SensitiveStore {
  const path = sensitiveStorePath();
  if (!existsSync(path)) {
    return {};
  }
  try {
    const raw = readFileSync(path, "utf-8");
    const parsed = JSON.parse(raw) as SensitiveStore;
    return parsed ?? {};
  } catch {
    return {};
  }
}

export function saveSensitiveStore(store: SensitiveStore): void {
  writeJsonAtomic(sensitiveStorePath(), store);
}

export function listSensitiveEntries(store: SensitiveStore, profileName: string): SensitiveEntry[] {
  return store[profileName] || [];
}

export function upsertSensitiveEntry(store: SensitiveStore, profileName: string, entry: SensitiveEntry): SensitiveStore {
  const existing = store[profileName] || [];
  const filtered = existing.filter((e) => e.label !== entry.label);
  return {
    ...store,
    [profileName]: [...filtered, entry],
  };
}

export function removeSensitiveEntry(store: SensitiveStore, profileName: string, label: string): SensitiveStore {
  const existing = store[profileName] || [];
  return {
    ...store,
    [profileName]: existing.filter((e) => e.label !== label),
  };
}

export function ensureConfigRoot(): void {
  ensureDir(configDir());
}
