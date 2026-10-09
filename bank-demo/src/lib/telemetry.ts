// Behavioural telemetry for the demo bank app (FraudMesh v3 phase 8, contract 1.1.0 Context + Telemetry).
//
// Privacy rules (enforced here, validated again server-side by the contract models):
// - Only the contract's coarse fields are collected. Keystrokes contribute TIMING ONLY (the gap between key presses,
//   rounded to 10 ms, summarised as mean/std); the key, its code and the field's value are never read.
// - Password, OTP and any field marked data-telemetry="off" are excluded from keystroke timing entirely.
// - Paste: only a yes/no flag, and only for fields marked data-telemetry="sensitive" (payee account, amount). The
//   clipboard is never read (no clipboardData access).
// - No mouse paths, no raw events, nothing stored across tabs: the session id is per tab (sessionStorage).
// - remote_access_demo / active_call_demo are SIMULATED demo toggles; the app cannot detect real remote-access tools or
//   phone calls and does not try.
import type { Context, Telemetry } from "../types/contracts";

type Pointer = "mouse" | "touch" | "pen";

const MAX_INTERVAL_MS = 5000;          // longer pauses are not typing rhythm
const MAX_SAMPLES = 200;

const state = {
  started: false,
  pointer: null as Pointer | null,
  lastKeyAt: null as number | null,
  intervals: [] as number[],
  pasteSensitive: false,
  screen: "",
  resolutionChanges: 0,
  dwell: { payment: 0, beneficiary: 0 } as Record<"payment" | "beneficiary", number>,
  dwellStart: { payment: null, beneficiary: null } as Record<"payment" | "beneficiary", number | null>,
};

function excluded(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.closest("[data-telemetry='off']")) return true;
  const input = target as HTMLInputElement;
  return input.type === "password" || input.autocomplete === "one-time-code";
}

function screenString(): string {
  try { return `${window.screen.width}x${window.screen.height}`.slice(0, 32); } catch { return ""; }
}

/** Installs the listeners once. Safe to call repeatedly (React StrictMode). */
export function startTelemetry(): void {
  if (state.started || typeof window === "undefined") return;
  state.started = true;
  state.screen = screenString();
  window.addEventListener("pointerdown", (e) => {
    if (e.pointerType === "mouse" || e.pointerType === "touch" || e.pointerType === "pen") state.pointer = e.pointerType;
  }, { passive: true, capture: true });
  window.addEventListener("keydown", (e) => {
    if (excluded(e.target)) { state.lastKeyAt = null; return; }
    const now = performance.now();                      // the time only: e.key / e.code are never read
    if (state.lastKeyAt !== null) {
      const gap = now - state.lastKeyAt;
      if (gap > 0 && gap <= MAX_INTERVAL_MS) {
        state.intervals.push(Math.round(gap / 10) * 10);
        if (state.intervals.length > MAX_SAMPLES) state.intervals.shift();
      }
    }
    state.lastKeyAt = now;
  }, { passive: true, capture: true });
  window.addEventListener("paste", (e) => {
    // a flag only, for designated sensitive fields; e.clipboardData is never touched
    if (e.target instanceof HTMLElement && e.target.closest("[data-telemetry='sensitive']")) state.pasteSensitive = true;
  }, { capture: true });
  window.addEventListener("resize", () => {
    const s = screenString();
    if (s && s !== state.screen) { state.screen = s; state.resolutionChanges = Math.min(1000, state.resolutionChanges + 1); }
  }, { passive: true });
}

/** Screen dwell for the beneficiary (payees) and payment (transfer) screens: call on mount, the cleanup on unmount. */
export function enterScreen(kind: "payment" | "beneficiary"): () => void {
  state.dwellStart[kind] = performance.now();
  return () => {
    const t = state.dwellStart[kind];
    if (t !== null) state.dwell[kind] += (performance.now() - t) / 1000;
    state.dwellStart[kind] = null;
  };
}

function dwellSeconds(kind: "payment" | "beneficiary"): number | null {
  const t = state.dwellStart[kind];
  const total = state.dwell[kind] + (t !== null ? (performance.now() - t) / 1000 : 0);
  return total > 0 ? Math.min(86_400, Math.round(total * 10) / 10) : null;
}

function meanStd(xs: number[]): [number | null, number | null] {
  if (xs.length < 2) return [null, null];
  const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
  const sd = Math.sqrt(xs.reduce((a, b) => a + (b - mean) ** 2, 0) / xs.length);
  return [Math.min(60_000, Math.round(mean)), Math.min(60_000, Math.round(sd))];
}

export type DemoSignals = { remoteAccess: boolean; activeCall: boolean };

/** The Telemetry object for the next event. Demo flags are sent only when switched on. */
export function snapshotTelemetry(demo: DemoSignals): Telemetry {
  const [mean, std] = meanStd(state.intervals);
  return {
    pointer_type: state.pointer,
    keystroke_interval_ms_mean: mean,
    keystroke_interval_ms_std: std,
    paste_in_sensitive_field: state.pasteSensitive ? true : null,
    payment_screen_dwell_s: dwellSeconds("payment"),
    beneficiary_screen_dwell_s: dwellSeconds("beneficiary"),
    screen_resolution_changes: state.resolutionChanges,
    remote_access_demo: demo.remoteAccess ? true : null,
    active_call_demo: demo.activeCall ? true : null,
  };
}

/** Per-tab random session id (crypto RNG). sessionStorage keeps it across reloads of this tab only. */
export function tabSessionId(): string {
  const make = () => {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    return "tab_" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  };
  try {
    const existing = sessionStorage.getItem("nb.session_id");
    if (existing && /^tab_[0-9a-f]{32}$/.test(existing)) return existing;
    const id = make();
    sessionStorage.setItem("nb.session_id", id);
    return id;
  } catch {
    return make();
  }
}

function webglRenderer(): string | null {
  try {
    const gl = document.createElement("canvas").getContext("webgl");
    if (!gl) return null;
    const ext = gl.getExtension("WEBGL_debug_renderer_info");
    if (!ext) return null;                                // not available: omit, never guess
    const r = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
    return typeof r === "string" && r ? r.slice(0, 256) : null;
  } catch {
    return null;
  }
}

let staticCache: Pick<Context, "session_id" | "browser_timezone" | "locale" | "platform" | "webgl_renderer"> | null = null;

/** The 1.1.0 Context device fields (computed once per tab) plus the current screen resolution. */
export function deviceContext(): Pick<Context, "session_id" | "browser_timezone" | "locale" | "platform" | "webgl_renderer" | "screen"> {
  if (!staticCache) {
    const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
    let tz: string | null = null;
    try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone?.slice(0, 64) || null; } catch { tz = null; }
    staticCache = {
      session_id: tabSessionId(),
      browser_timezone: tz,
      locale: (navigator.language || "").slice(0, 35) || null,
      platform: (nav.userAgentData?.platform || navigator.platform || "").slice(0, 64) || null,
      webgl_renderer: webglRenderer(),
    };
  }
  return { ...staticCache, screen: screenString() || null };
}
