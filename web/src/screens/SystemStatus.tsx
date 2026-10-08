// /status — live connectivity checks for the human tester (PRD §14.4 rows that the browser can exercise),
// plus Dev 1 phase progress. Each check calls the real API.
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, API_BASE, ApiError, getAccessToken, USE_FIXTURES } from "../lib/api";
import { useAuth } from "../lib/auth";
import type { CasesPage, Health } from "../types/contracts";

type Result = { ok: boolean; detail: string } | null;

function Row({ name, how, result }: { name: string; how: string; result: Result | "loading" }) {
  const state = result === "loading" ? "loading" : result === null ? "idle" : result.ok ? "ok" : "fail";
  const badge = { ok: "bg-risk-low-fill text-risk-low", fail: "bg-risk-critical-fill text-risk-critical",
    loading: "bg-surface-container text-on-surface-variant", idle: "bg-surface-container text-on-surface-variant" }[state];
  return (
    <tr className="h-10 border-b border-outline-variant">
      <td className="px-3 text-on-surface font-medium">{name}</td>
      <td className="px-3 text-on-surface-variant text-body-xs">{how}</td>
      <td className="px-3"><span className={`inline-flex px-2 h-[22px] items-center rounded-lg text-[11px] font-semibold ${badge}`}>
        {{ ok: "PASS", fail: "FAIL", loading: "…", idle: "NOT RUN" }[state]}</span></td>
      <td className="px-3 font-code-sm text-code-sm text-on-surface-variant">{result && result !== "loading" ? result.detail : ""}</td>
    </tr>
  );
}

function wsCheck(token: string | null): Promise<Result> {
  return new Promise((resolve) => {
    const url = API_BASE.replace(/^http/, "ws") + "/v1/stream";
    const ws = new WebSocket(url);
    let opened = false;
    const done = (r: Result) => { try { ws.close(); } catch { /* closed */ } resolve(r); };
    ws.onopen = () => { opened = true; ws.send(JSON.stringify({ token: token ?? "missing" })); setTimeout(() => done({ ok: true, detail: "authenticated, stayed open 1.5 s" }), 1500); };
    ws.onclose = (e) => { if (opened) resolve({ ok: false, detail: `closed with ${e.code}` }); };
    ws.onerror = () => resolve({ ok: false, detail: "could not connect" });
  });
}

function wsRejectCheck(): Promise<Result> {
  return new Promise((resolve) => {
    const ws = new WebSocket(API_BASE.replace(/^http/, "ws") + "/v1/stream");
    ws.onopen = () => ws.send(JSON.stringify({ token: "not-a-jwt" }));
    ws.onclose = (e) => resolve(e.code === 4401 ? { ok: true, detail: "closed with 4401 as required" } : { ok: false, detail: `closed with ${e.code}` });
    ws.onerror = () => {};
  });
}

const PHASES: [string, string, "done" | "next" | "todo"][] = [
  ["P0", "Setup and contracts — repo, contracts.py, engine/common, stubs, fixtures, compose, CI", "done"],
  ["D1-P1", "Data platform — schema, PgStore, signed /v1/events, auth, seed users", "done"],
  ["D1-P2", "API and worker — worker loop, real case routes, WebSocket broadcast, demo emit, step-up", "next"],
  ["D1-P3", "Stitch UI wiring — case page, timeline, graph, risk chart, bank app, phones", "todo"],
  ["D1-P4", "Security and audit — audit verify, headers, rate limits, RBAC/IDOR", "todo"],
  ["D1-P5", "Demo tooling — play.py, load.py, reset_demo.sh, autopilot, Suricata adapter", "todo"],
  ["D1-P6", "Investigator AI, replay, simulator UI", "todo"],
  ["D1-P7", "Tests, smoke test, perf", "todo"],
];

export function SystemStatus() {
  const { session } = useAuth();
  const health = useQuery({ queryKey: ["health"], queryFn: () => api<Health>("/v1/health"), refetchInterval: 10_000 });
  const [ws, setWs] = useState<Result | "loading">(null);
  const [wsBad, setWsBad] = useState<Result | "loading">(null);
  const [rbac, setRbac] = useState<Result | "loading">(null);
  const [cases, setCases] = useState<Result | "loading">(null);

  const h = health.data;
  const hr = (ok: boolean | undefined, detail: string): Result | "loading" =>
    health.isLoading ? "loading" : health.isError ? { ok: false, detail: (health.error as ApiError).message } : { ok: !!ok, detail };

  async function runAll() {
    setCases("loading"); setRbac("loading");
    if (!USE_FIXTURES) { setWs("loading"); setWsBad("loading"); }
    try {
      const page = await api<CasesPage>("/v1/cases?limit=5");
      setCases({ ok: true, detail: `${page.items.length} cases returned with bearer token` });
      const cid = page.items[0]?.case_id;
      try {
        await api(`/v1/cases/${cid}/actions`, { method: "POST", body: { actions: ["HOLD_OUTBOUND_PAYMENTS"], reason: "status-page RBAC probe" } });
        setRbac(session?.role === "analyst" ? { ok: false, detail: "analyst was allowed (expected 403)" } : { ok: true, detail: `${session?.role} allowed (lead+)` });
      } catch (e) {
        const code = e instanceof ApiError ? e.code : "error";
        setRbac(session?.role === "analyst" && code === "FORBIDDEN" ? { ok: true, detail: "analyst got 403 FORBIDDEN" } : { ok: false, detail: code });
      }
    } catch (e) {
      setCases({ ok: false, detail: e instanceof ApiError ? `${e.code}: ${e.message}` : String(e) });
      setRbac(null);
    }
    if (!USE_FIXTURES) {
      setWs(await wsCheck(getAccessToken()));
      setWsBad(await wsRejectCheck());
    }
  }

  return (
    <div className="p-space-base flex flex-col gap-space-base">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-headline-lg text-headline-lg tracking-tight">System status</h1>
          <p className="text-body-sm text-on-surface-variant">Live checks against <span className="font-mono">{API_BASE}</span>{USE_FIXTURES && " (fixture mode: the API is not called)"}</p>
        </div>
        <button onClick={runAll} className="h-8 px-3 rounded-lg bg-primary-container hover:bg-primary text-on-primary font-label-md text-label-md flex items-center gap-1.5">
          <span className="material-symbols-outlined !text-[16px]">play_arrow</span> Run browser checks
        </button>
      </div>

      <section className="bg-surface-container-lowest border border-outline-variant rounded-lg overflow-hidden">
        <div className="h-10 px-3 flex items-center border-b border-outline-variant font-headline-sm text-headline-sm">Connectivity</div>
        <table className="w-full text-left text-body-sm">
          <tbody>
            <Row name="API → Postgres" how="GET /v1/health → db" result={hr(h?.db, h ? `db: ${h.db}` : "")} />
            <Row name="Pipeline ready" how="GET /v1/health → pipeline_ready (Phase 0 stub until Dev 2's D2-P2)" result={hr(h?.pipeline_ready, h ? `pipeline_ready: ${h.pipeline_ready}` : "")} />
            <Row name="Contract version" how="engine/contracts.py CONTRACT_VERSION" result={hr(!!h?.contract_version, h?.contract_version ?? "")} />
            <Row name="Model artifact" how="ml/artifacts/manifest.json (Dev 2, D2-P3)" result={hr(!!h?.model_sha256, h?.model_sha256 ?? "not present yet — expected before Checkpoint 1")} />
            <Row name="Login + bearer token" how="POST /v1/auth/login, then GET /v1/cases" result={cases} />
            <Row name="Role check on /actions" how="analyst → 403, lead/admin → 200" result={rbac} />
            <Row name="WebSocket with token" how="GET /v1/stream, first message {token}" result={ws} />
            <Row name="WebSocket without token" how="bad token must close with 4401" result={wsBad} />
          </tbody>
        </table>
      </section>

      <section className="bg-surface-container-lowest border border-outline-variant rounded-lg overflow-hidden">
        <div className="h-10 px-3 flex items-center border-b border-outline-variant font-headline-sm text-headline-sm">Dev 1 phase progress</div>
        <table className="w-full text-left text-body-sm">
          <tbody>
            {PHASES.map(([id, label, st]) => (
              <tr key={id} className="h-9 border-b border-outline-variant last:border-0">
                <td className="px-3 w-20 font-code-sm text-code-sm">{id}</td>
                <td className="px-3">{label}</td>
                <td className="px-3 w-28">
                  <span className={"inline-flex px-2 h-[22px] items-center rounded-lg text-[11px] font-semibold " +
                    (st === "done" ? "bg-risk-low-fill text-risk-low" : st === "next" ? "bg-surface-container text-primary-container" : "bg-surface-container text-on-surface-variant")}>
                    {st === "done" ? "Done" : st === "next" ? "Next" : "Pending"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
