// One fetch wrapper for the console (PRD §11): adds the bearer token, maps the §4 error format,
// refreshes once on 401, and serves fixtures/api/*.json when VITE_USE_FIXTURES=1.
import type { ErrorBody } from "../types/contracts";

export const API_BASE: string = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";
export const USE_FIXTURES = import.meta.env.VITE_USE_FIXTURES === "1";

let accessToken: string | null = null;
let onAuthLost: () => void = () => {};

export const getAccessToken = () => accessToken;
export const setAccessToken = (t: string | null) => { accessToken = t; };
export const setOnAuthLost = (fn: () => void) => { onAuthLost = fn; };

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public requestId?: string) {
    super(message);
  }
}

type Opts = { method?: "GET" | "POST"; body?: unknown; retry?: boolean };

export async function api<T>(path: string, opts: Opts = {}): Promise<T> {
  if (USE_FIXTURES) return fixtureFor<T>(path, opts);
  const { method = "GET", body, retry = true } = opts;
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  let res: Response;
  try {
    res = await fetch(API_BASE + path, { method, headers, credentials: "include",
      body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError(0, "NETWORK", `Cannot reach the API at ${API_BASE}`);
  }
  if (res.status === 401 && retry && !path.startsWith("/v1/auth/")) {
    if (await refreshAccessToken()) return api<T>(path, { ...opts, retry: false });
    onAuthLost();
  }
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = (data as ErrorBody | null)?.error;
    throw new ApiError(res.status, err?.code ?? "HTTP_" + res.status, err?.message ?? res.statusText, err?.request_id);
  }
  return data as T;
}

export async function refreshAccessToken(): Promise<{ access_token: string; role: string } | null> {
  if (USE_FIXTURES) return null;
  try {
    const res = await fetch(API_BASE + "/v1/auth/refresh", { method: "POST", credentials: "include" });
    if (!res.ok) return null;
    const data = await res.json();
    accessToken = data.access_token;
    return data;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ fixture mode
const FIXTURES = import.meta.glob("../../../fixtures/api/*.json", { eager: true, import: "default" }) as Record<string, unknown>;
const fx = (name: string) => FIXTURES[`../../../fixtures/api/${name}.json`];

async function fixtureFor<T>(path: string, opts: Opts): Promise<T> {
  await new Promise((r) => setTimeout(r, 120));
  const p = path.split("?")[0];
  const routes: [RegExp, () => unknown][] = [
    [/^\/v1\/auth\/login$/, () => ({ access_token: "fixture", token_type: "bearer", expires_in: 900,
      role: String((opts.body as { email?: string })?.email ?? "analyst").split("@")[0] || "analyst" })],
    [/^\/v1\/health$/, () => ({ status: "ok", db: true, pipeline_ready: true, contract_version: "1.0.0", model_sha256: null })],
    [/^\/v1\/cases$/, () => fx("cases_list")],
    [/^\/v1\/cases\/[^/]+$/, () => fx("case")],
    [/^\/v1\/cases\/[^/]+\/timeline$/, () => fx("timeline")],
    [/^\/v1\/cases\/[^/]+\/graph$/, () => fx("graph")],
    [/^\/v1\/cases\/[^/]+\/explanation$/, () => fx("explanation")],
    [/^\/v1\/cases\/[^/]+\/replay$/, () => fx("replay")],
    [/^\/v1\/metrics\/summary$/, () => fx("metrics")],
    [/^\/v1\/detectors$/, () => fx("detectors")],
    [/^\/v1\/simulate$/, () => fx("simulation")],
  ];
  const hit = routes.find(([re]) => re.test(p));
  if (!hit) throw new ApiError(404, "NOT_FOUND", `no fixture for ${p}`);
  return structuredClone(hit[1]()) as T;
}
