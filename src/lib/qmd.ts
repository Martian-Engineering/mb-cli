import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";
import YAML from "yaml";
import { qmdConfigDir, qmdConfigPath, qmdIndexPath } from "./paths";

export type QmdCommand = {
  command: string;
  args: string[];
};

type QmdConfig = {
  global_context?: string;
  collections?: Record<string, { path: string; pattern: string }>;
};

function ensureDir(path: string): void {
  if (!existsSync(path)) {
    mkdirSync(path, { recursive: true });
  }
}

export function resolveQmdCommand(): QmdCommand | null {
  const direct = Bun.which("qmd");
  if (direct) {
    return { command: direct, args: [] };
  }
  const local = join(process.cwd(), ".local", "qmd", "src", "qmd.ts");
  if (existsSync(local)) {
    const bun = Bun.which("bun") || "bun";
    return { command: bun, args: [local] };
  }
  return null;
}

function loadQmdConfig(): QmdConfig {
  const path = qmdConfigPath();
  if (!existsSync(path)) {
    return { collections: {} };
  }
  const raw = readFileSync(path, "utf-8");
  const parsed = YAML.parse(raw) as QmdConfig;
  if (!parsed.collections) parsed.collections = {};
  return parsed;
}

function saveQmdConfig(config: QmdConfig): void {
  ensureDir(qmdConfigDir());
  const yaml = YAML.stringify(config, { indent: 2, lineWidth: 0 });
  writeFileSync(qmdConfigPath(), yaml, "utf-8");
}

export function ensureQmdCollection(name: string, path: string, pattern: string): boolean {
  const config = loadQmdConfig();
  const collections = config.collections || {};
  const existing = collections[name];
  if (existing && existing.path === path && existing.pattern === pattern) {
    return false;
  }
  config.collections = {
    ...collections,
    [name]: { path, pattern },
  };
  saveQmdConfig(config);
  return true;
}

export async function runQmd(
  args: string[],
  options: { timeoutMs?: number } = {}
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const resolved = resolveQmdCommand();
  if (!resolved) {
    return { exitCode: 1, stdout: "", stderr: "qmd not found" };
  }

  ensureDir(qmdConfigDir());

  const env = {
    ...process.env,
    QMD_CONFIG_DIR: qmdConfigDir(),
    INDEX_PATH: qmdIndexPath(),
    NO_COLOR: "1",
  } as Record<string, string>;

  const proc = Bun.spawn([resolved.command, ...resolved.args, ...args], {
    env,
    stdout: "pipe",
    stderr: "pipe",
  });

  const timeoutMs = Number.isFinite(options.timeoutMs)
    ? Number(options.timeoutMs)
    : Number(process.env.MB_QMD_TIMEOUT_MS ?? "15000");

  let timeout: ReturnType<typeof setTimeout> | undefined;

  const resultPromise = (async () => {
    try {
      const stdout = await new Response(proc.stdout).text();
      const stderr = await new Response(proc.stderr).text();
      const exitCode = await proc.exited;
      return { exitCode, stdout, stderr };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { exitCode: 1, stdout: "", stderr: message };
    }
  })();

  if (!timeoutMs || timeoutMs <= 0) {
    return resultPromise;
  }

  const timeoutPromise = new Promise<{ exitCode: number; stdout: string; stderr: string }>((resolve) => {
    timeout = setTimeout(() => {
      try {
        proc.kill();
      } catch {
        // ignore
      }
      resolve({ exitCode: 124, stdout: "", stderr: "qmd timeout" });
    }, timeoutMs);
  });

  const result = await Promise.race([resultPromise, timeoutPromise]);
  if (timeout) clearTimeout(timeout);
  return result;
}

export async function ensureQmdIndex(collectionName: string, collectionPath: string): Promise<void> {
  const changed = ensureQmdCollection(collectionName, collectionPath, "**/*.md");
  const indexExists = existsSync(qmdIndexPath());
  if (!indexExists || changed) {
    const timeoutMs = Number(process.env.MB_QMD_INDEX_TIMEOUT_MS ?? "60000");
    await runQmd(["update"], { timeoutMs });
    await runQmd(["embed"], { timeoutMs });
  }
}
