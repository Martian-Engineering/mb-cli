import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { dirname } from "path";
import { rateLimitPath } from "./paths";

const REQUESTS_PER_MIN = 100;
const COMMENTS_PER_HOUR = 50;
const POST_COOLDOWN_MS = 30 * 60 * 1000;

export type RateState = {
  requests: number[];
  comments: number[];
  posts: number[];
  blocked_until?: Record<string, number>;
};

export type RateStore = Record<string, RateState>;

export type RateDecision = {
  allowed: boolean;
  waitMs: number;
  reason: string;
};

function ensureDir(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
  }
}

function loadStore(): RateStore {
  const path = rateLimitPath();
  if (!existsSync(path)) return {};
  try {
    const raw = readFileSync(path, "utf-8");
    const parsed = JSON.parse(raw) as RateStore;
    return parsed ?? {};
  } catch {
    return {};
  }
}

function saveStore(store: RateStore): void {
  const path = rateLimitPath();
  ensureDir(dirname(path));
  writeFileSync(path, JSON.stringify(store, null, 2), { mode: 0o600 });
}

function ensureState(store: RateStore, profile: string): RateState {
  const existing = store[profile];
  if (existing) return existing;
  const state: RateState = { requests: [], comments: [], posts: [] };
  store[profile] = state;
  return state;
}

function prune(times: number[], windowMs: number, now: number): number[] {
  const cutoff = now - windowMs;
  return times.filter((t) => t >= cutoff);
}

export function checkRateLimit(profile: string, action: "request" | "comment" | "post"): RateDecision {
  const store = loadStore();
  const state = ensureState(store, profile);
  const now = Date.now();

  if (state.blocked_until && state.blocked_until[action] && state.blocked_until[action]! > now) {
    const waitMs = state.blocked_until[action]! - now;
    return { allowed: false, waitMs, reason: `server retry_after for ${action}` };
  }

  state.requests = prune(state.requests, 60_000, now);
  state.comments = prune(state.comments, 60 * 60_000, now);
  state.posts = prune(state.posts, POST_COOLDOWN_MS, now);
  saveStore(store);

  if (action === "request") {
    if (state.requests.length >= REQUESTS_PER_MIN) {
      const oldest = state.requests[0];
      return { allowed: false, waitMs: oldest + 60_000 - now, reason: "rate limit: 100 requests/min" };
    }
    return { allowed: true, waitMs: 0, reason: "ok" };
  }

  if (action === "comment") {
    if (state.comments.length >= COMMENTS_PER_HOUR) {
      const oldest = state.comments[0];
      return { allowed: false, waitMs: oldest + 60 * 60_000 - now, reason: "rate limit: 50 comments/hour" };
    }
    return { allowed: true, waitMs: 0, reason: "ok" };
  }

  if (state.posts.length >= 1) {
    const last = state.posts[state.posts.length - 1];
    const waitMs = last + POST_COOLDOWN_MS - now;
    if (waitMs > 0) {
      return { allowed: false, waitMs, reason: "rate limit: 1 post/30min" };
    }
  }

  return { allowed: true, waitMs: 0, reason: "ok" };
}

export function recordAction(profile: string, action: "request" | "comment" | "post"): void {
  const store = loadStore();
  const state = ensureState(store, profile);
  const now = Date.now();

  if (action === "request") state.requests.push(now);
  if (action === "comment") state.comments.push(now);
  if (action === "post") state.posts.push(now);

  saveStore(store);
}

export function recordRequest(profile: string): void {
  recordAction(profile, "request");
}

export function recordPost(profile: string): void {
  recordAction(profile, "post");
  recordAction(profile, "request");
}

export function recordComment(profile: string): void {
  recordAction(profile, "comment");
  recordAction(profile, "request");
}

export function applyServerRetryAfter(profile: string, action: "request" | "comment" | "post", retryAfterSeconds: number): void {
  const store = loadStore();
  const state = ensureState(store, profile);
  if (!state.blocked_until) state.blocked_until = {};
  state.blocked_until[action] = Date.now() + retryAfterSeconds * 1000;
  saveStore(store);
}

export function extractRetryAfterSeconds(data: unknown): number | null {
  if (!data || typeof data !== "object") return null;
  const record = data as Record<string, unknown>;
  if (typeof record.retry_after_seconds === "number") return record.retry_after_seconds;
  if (typeof record.retry_after_minutes === "number") return record.retry_after_minutes * 60;
  if (typeof record.retry_after === "number") return record.retry_after;
  if (typeof record.retry_after_minutes === "string") {
    const parsed = Number(record.retry_after_minutes);
    if (!Number.isNaN(parsed)) return parsed * 60;
  }
  if (typeof record.retry_after_seconds === "string") {
    const parsed = Number(record.retry_after_seconds);
    if (!Number.isNaN(parsed)) return parsed;
  }
  return null;
}
