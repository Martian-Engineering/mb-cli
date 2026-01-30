import { homedir } from "os";
import { join } from "path";

export function configDir(): string {
  return join(homedir(), ".config", "moltbook");
}

export function credentialsPath(): string {
  return join(configDir(), "credentials.json");
}

export function sensitiveStorePath(): string {
  return join(configDir(), "sensitive.json");
}

export function sensitiveFactsDir(profile: string): string {
  return join(configDir(), "sensitive", profile);
}

export function jailbreakDir(): string {
  return join(configDir(), "jailbreak");
}

export function jailbreakRemotePath(): string {
  return join(jailbreakDir(), "remote.json");
}

export function qmdConfigDir(): string {
  return join(configDir(), "qmd");
}

export function qmdConfigPath(): string {
  return join(qmdConfigDir(), "index.yml");
}

export function qmdIndexPath(): string {
  return join(qmdConfigDir(), "index.sqlite");
}

export function auditLogPath(): string {
  return join(configDir(), "audit.jsonl");
}

export function rateLimitPath(): string {
  return join(configDir(), "rate_limits.json");
}
