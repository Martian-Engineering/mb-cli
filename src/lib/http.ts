import { printError } from "./output";

export type ClientOptions = {
  baseUrl: string;
  apiKey?: string;
  timeoutMs: number;
  retries: number;
  verbose?: boolean;
  dryRun?: boolean;
};

export type RequestOptions = {
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  idempotent?: boolean;
};

export type ResponseResult = {
  ok: boolean;
  status: number;
  data?: unknown;
  error?: string;
  dryRun?: boolean;
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildUrl(
  baseUrl: string,
  path: string,
  query?: Record<string, string | number | boolean | undefined>,
): URL {
  const base = new URL(baseUrl);
  const basePath = base.pathname.endsWith("/") ? base.pathname.slice(0, -1) : base.pathname;
  const resolvedPath = path.startsWith("/") ? `${basePath}${path}` : `${basePath}/${path}`;
  const url = new URL(resolvedPath, base);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined) continue;
      url.searchParams.set(key, String(value));
    }
  }
  return url;
}

function buildHeaders(apiKey?: string): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (apiKey) {
    headers["Authorization"] = `Bearer ${apiKey}`;
    headers["X-API-Key"] = apiKey;
  }
  return headers;
}

export async function request(
  client: ClientOptions,
  method: string,
  path: string,
  opts: RequestOptions = {},
): Promise<ResponseResult> {
  const url = buildUrl(client.baseUrl, path, opts.query);

  const headers = buildHeaders(client.apiKey);

  let body: string | undefined;
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }

  if (client.dryRun) {
    return {
      ok: true,
      status: 0,
      data: {
        dry_run: true,
        method,
        url: url.toString(),
        body: opts.body ?? null,
      },
      dryRun: true,
    };
  }

  const idempotent = opts.idempotent ?? ["GET", "HEAD", "DELETE"].includes(method.toUpperCase());
  const attempts = Math.max(0, client.retries);

  for (let attempt = 0; attempt <= attempts; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), client.timeoutMs);

    try {
      if (client.verbose) {
        console.log(`[mb] ${method.toUpperCase()} ${url.toString()}`);
      }

      const res = await fetch(url, {
        method,
        headers,
        body,
        signal: controller.signal,
      });

      clearTimeout(timeout);

      const contentType = res.headers.get("content-type") || "";
      let data: unknown = undefined;
      if (contentType.includes("application/json")) {
        data = await res.json();
      } else {
        const text = await res.text();
        data = text.length > 0 ? text : undefined;
      }

      if (res.ok) {
        return { ok: true, status: res.status, data };
      }

      const retriable = idempotent && (res.status === 429 || res.status >= 500);
      if (retriable && attempt < attempts) {
        const backoff = Math.min(2000, 250 * Math.pow(2, attempt));
        await sleep(backoff);
        continue;
      }

      return {
        ok: false,
        status: res.status,
        data,
        error: typeof data === "string" ? data : JSON.stringify(data),
      };
    } catch (err) {
      clearTimeout(timeout);
      const retriable = idempotent && attempt < attempts;
      if (retriable) {
        const backoff = Math.min(2000, 250 * Math.pow(2, attempt));
        await sleep(backoff);
        continue;
      }
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, status: 0, error: message };
    }
  }

  printError("Request failed", {});
  return { ok: false, status: 0, error: "Request failed" };
}

export async function uploadFile(
  client: ClientOptions,
  path: string,
  filePath: string,
  fieldName: string = "file",
  extraFields?: Record<string, string>,
): Promise<ResponseResult> {
  const url = buildUrl(client.baseUrl, path);
  const headers = buildHeaders(client.apiKey);
  const file = Bun.file(filePath);

  if (client.dryRun) {
    return {
      ok: true,
      status: 0,
      data: {
        dry_run: true,
        method: "POST",
        url: url.toString(),
        file: filePath,
        fields: extraFields ?? {},
      },
      dryRun: true,
    };
  }

  const form = new FormData();
  form.append(fieldName, file);
  if (extraFields) {
    for (const [key, value] of Object.entries(extraFields)) {
      form.append(key, value);
    }
  }

  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: form,
    });

    const contentType = res.headers.get("content-type") || "";
    let data: unknown = undefined;
    if (contentType.includes("application/json")) {
      data = await res.json();
    } else {
      const text = await res.text();
      data = text.length > 0 ? text : undefined;
    }

    if (res.ok) {
      return { ok: true, status: res.status, data };
    }

    return {
      ok: false,
      status: res.status,
      data,
      error: typeof data === "string" ? data : JSON.stringify(data),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, status: 0, error: message };
  }
}
