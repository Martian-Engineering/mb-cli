import { appendFileSync, existsSync, mkdirSync } from "fs";
import { dirname } from "path";
import { createHash } from "crypto";
import { auditLogPath } from "./paths";

export type AuditEntry = {
  timestamp: string;
  profile: string;
  action: string;
  method: string;
  endpoint: string;
  status: "sent" | "blocked" | "dry_run";
  reason?: string;
  safety_matches?: unknown[];
  sanitization?: string[];
  content_preview?: string;
  content_sha256?: string;
  meta?: Record<string, unknown>;
};

function ensureDir(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
  }
}

function hashText(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export function buildContentAudit(text?: string): {
  content_preview?: string;
  content_sha256?: string;
} {
  if (!text || text.trim().length === 0) {
    return {};
  }
  const trimmed = text.trim();
  const preview = trimmed.length > 240 ? trimmed.slice(0, 240) + "…" : trimmed;
  return {
    content_preview: preview,
    content_sha256: hashText(trimmed),
  };
}

export function appendAudit(entry: AuditEntry): void {
  const path = auditLogPath();
  ensureDir(dirname(path));
  appendFileSync(path, JSON.stringify(entry) + "\n", { mode: 0o600 });
}
