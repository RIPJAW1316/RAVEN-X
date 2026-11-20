/**
 * HTTP core for the Raven-X control plane.
 *
 * The session token is held in `sessionStorage` so it is dropped when the tab
 * closes and is never shared with another origin. No credential is ever
 * written to source or logged.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | undefined;
  readonly requestId: string | undefined;
  readonly retryAfter: string | undefined;

  constructor(
    message: string,
    status: number,
    options: { code?: string; requestId?: string; retryAfter?: string } = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = options.code;
    this.requestId = options.requestId;
    this.retryAfter = options.retryAfter;
  }

  /** True when the operator is authenticated but lacks permission. */
  get isForbidden(): boolean {
    return this.status === 403;
  }

  get isUnauthorized(): boolean {
    return this.status === 401;
  }

  get isUnavailable(): boolean {
    return this.status === 503;
  }

  get isNotFound(): boolean {
    return this.status === 404;
  }
}

const SESSION_KEY = "ravenx.session";

type Listener = (token: string | null) => void;
const listeners = new Set<Listener>();

function readStoredToken(): string | null {
  try {
    return sessionStorage.getItem(SESSION_KEY);
  } catch {
    return null;
  }
}

let token: string | null = readStoredToken();

export const session = {
  get(): string | null {
    return token;
  },
  set(value: string | null): void {
    token = value;
    try {
      if (value) sessionStorage.setItem(SESSION_KEY, value);
      else sessionStorage.removeItem(SESSION_KEY);
    } catch {
      /* storage unavailable — the in-memory token still works for this tab */
    }
    listeners.forEach((listener) => listener(value));
  },
  subscribe(listener: Listener): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
};

interface RequestOptions {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
  query?: Record<string, string | number | boolean | string[] | undefined>;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  if (!query) return path;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === "") continue;
    if (Array.isArray(value)) value.forEach((item) => item && params.append(key, String(item)));
    else params.append(key, String(value));
  }
  const encoded = params.toString();
  return encoded ? `${path}?${encoded}` : path;
}

async function parseError(response: Response): Promise<ApiError> {
  let code: string | undefined;
  let message = `Request failed with status ${response.status}`;
  try {
    const payload: unknown = await response.json();
    if (payload && typeof payload === "object" && "detail" in payload) {
      const detail = (payload as { detail: unknown }).detail;
      if (detail && typeof detail === "object") {
        const shaped = detail as { code?: unknown; message?: unknown };
        if (typeof shaped.code === "string") code = shaped.code;
        if (typeof shaped.message === "string") message = shaped.message;
      } else if (typeof detail === "string") {
        message = detail;
      }
    }
  } catch {
    /* non-JSON error body — keep the status-derived message */
  }
  return new ApiError(message, response.status, {
    code,
    requestId: response.headers.get("X-Request-ID") ?? undefined,
    retryAfter: response.headers.get("Retry-After") ?? undefined,
  });
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers = new Headers({ Accept: "application/json" });
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (options.body !== undefined) headers.set("Content-Type", "application/json");

  const response = await fetch(buildUrl(path, options.query), {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    signal: options.signal,
  });

  if (response.status === 401) {
    // The session is gone server-side; clear it so the shell returns to login.
    session.set(null);
    throw await parseError(response);
  }
  if (!response.ok) throw await parseError(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** Fetch a binary/text export and return it with its content type. */
export async function requestBlob(
  path: string,
  options: RequestOptions = {},
): Promise<{ blob: Blob; filename: string | null }> {
  const headers = new Headers();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(buildUrl(path, options.query), {
    method: options.method ?? "GET", headers, signal: options.signal,
  });
  if (response.status === 401) session.set(null);
  if (!response.ok) throw await parseError(response);
  const disposition = response.headers.get("Content-Disposition");
  const match = disposition?.match(/(?:^|;)\s*filename\s*=\s*(?:"([^"]*)"|([^;]+))/i);
  return { blob: await response.blob(), filename: match ? (match[1] ?? match[2]).trim() : null };
}
