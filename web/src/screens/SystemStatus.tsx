// /status — live connectivity checks for the human tester (PRD §14.4 rows that the browser can exercise).
// Each check calls the real API.
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, API_BASE, ApiError, getAccessToken, USE_FIXTURES } from "../lib/api";
import { useAuth } from "../lib/auth";
import { Kpi, PageHeader, Panel } from "../components/ui";
import type { AuditVerify, CasesPage, Health } from "../types/contracts";

type Result = { ok: boolean; detail: string; waiting?: boolean } | null;

function Row({ name, how, result, icon }: { name: string; how: string; result: Result | "loading"; icon: string }) {
  const state = result === "loading" ? "loading" : result === null ? "idle" : result.ok ? "ok" : result.waiting ? "waiting" : "fail";
  const badge = { ok: "bg-risk-low-fill text-risk-low", fail: "bg-risk-critical-fill text-risk-critical",
    waiting: "bg-risk-medium-fill text-risk-medium", loading: "bg-surface-container text-on-surface-variant",
    idle: "bg-surface-container text-on-surface-variant" }[state];
  return (
    <tr className="fm-row border-t border-taupe/20 h-16">
      <td className="pl-6"><div className="flex items-center gap-3">
        <span className="w-9 h-9 rounded-xl bg-primary-fixed text-primary flex items-center justify-center shadow-porcelain-sm"><span className="material-symbols-outlined !text-[18px]">{icon}</span></span>
        <div><div className="font-semibold text-on-surface">{name}</div><div className="font-mono text-[11.5px] text-on-surface-variant">{how}</div></div></div></td>
      <td className="px-3"><span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-mono text-[11.5px] font-medium ${badge}`}>
        <span className="w-1.5 h-1.5 rounded-full bg-current" />{{ ok: "Operational", fail: "Failing", waiting: "Waiting", loading: "Checking…", idle: "Not run" }[state]}</span></td>
      <td className="px-3 pr-6 font-mono text-[12px] text-on-surface-variant">{result && result !== "loading" ? result.detail : ""}</td>
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

export function SystemStatus() {
  const { session } = useAuth();
  const [rtt, setRtt] = useState<number | null>(null);
  const health = useQuery({ queryKey: ["health-status"], refetchInterval: 10_000,
    queryFn: async () => { const t = performance.now(); const r = await api<Health>("/v1/health"); setRtt(Math.round(performance.now() - t)); return r; } });
  const [ws, setWs] = useState<Result | "loading">(null);
  const [wsBad, setWsBad] = useState<Result | "loading">(null);
  const [rbac, setRbac] = useState<Result | "loading">(null);
  const [cases, setCases] = useState<Result | "loading">(null);
  const [audit, setAudit] = useState<Result | "loading">(null);

  const h = health.data;
  const hr = (ok: boolean | undefined, detail: string, waiting = false): Result | "loading" =>
    health.isLoading ? "loading" : health.isError ? { ok: false, detail: (health.error as ApiError).message } : { ok: !!ok, detail, waiting };

  async function runAll() {
    setCases("loading"); setRbac("loading"); setAudit("loading");
    try {
      const v = await api<AuditVerify>("/v1/audit/verify");
      setAudit(v.ok ? { ok: true, detail: `${v.rows} rows, hash chain intact` } : { ok: false, detail: `chain broken at row ${v.broken_at} (${v.rows} checked)` });
    } catch (e) {
      setAudit(e instanceof ApiError && e.code === "FORBIDDEN" ? { ok: false, waiting: true, detail: "lead or admin only — sign in as lead@ to verify" }
        : { ok: false, detail: e instanceof ApiError ? `${e.code}: ${e.message}` : String(e) });
    }
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

  const allOk = !!h?.db && !!h?.pipeline_ready && !!h?.model_sha256;
  return (
    <div className="px-8 py-7 flex flex-col gap-7" data-testid="system-health">
      <PageHeader meta={<>live checks against <span className="font-mono">{API_BASE}</span>{USE_FIXTURES && " (fixture mode)"}</>}
        title="System Health" subtitle="API, database, pipeline, model, sign-in, roles, audit chain and stream."
        actions={<button onClick={runAll} className="fm-btn-primary"><span className="material-symbols-outlined !text-[18px]">play_arrow</span>Run browser checks</button>} />
      <div className="grid grid-cols-4 gap-6">
        <Kpi label="Overall system status" value={<span className="text-[26px] leading-[32px] block">{health.isLoading ? "Checking" : allOk ? "All healthy" : "Degraded"}</span>}
          icon="verified" tone={allOk ? "low" : "critical"} sub={h ? `db ${h.db ? "up" : "down"} · pipeline ${h.pipeline_ready ? "ready" : "starting"}` : ""} />
        <Kpi label="API round-trip" value={rtt ?? "—"} unit="ms" icon="speed" sub="GET /v1/health from this browser" />
        <Kpi label="Txn model artifact" value={<span className="font-mono text-[22px]">{h?.model_sha256 ? h.model_sha256.slice(0, 10) : "missing"}</span>} icon="memory"
          tone={h?.model_sha256 ? "low" : "critical"} sub="SHA-256 verified against manifest.json" />
        <Kpi label="Contract" value={h?.contract_version ?? "—"} icon="handshake" sub="engine/contracts.py (frozen, hash-checked in CI)" />
      </div>
      <Panel title="Core services & checks" subtitle="Server-side status refreshes every 10 s; the browser checks run when you press the button"
        right={<span className="fm-pill">{allOk ? "engine healthy" : "attention"}</span>}>
        <table className="w-full text-left text-body-sm">
          <thead><tr className="font-mono text-[11px] tracking-[0.08em] uppercase text-on-surface-variant bg-surface-container-low/70">
            <th className="pl-6 py-3">Service</th><th className="px-3">Status</th><th className="px-3 pr-6">Detail</th></tr></thead>
          <tbody>
            <Row icon="database" name="API → PostgreSQL" how="GET /v1/health → db" result={hr(h?.db, h ? `db: ${h.db}` : "")} />
            <Row icon="account_tree" name="Engine pipeline" how="GET /v1/health → pipeline_ready" result={hr(h?.pipeline_ready, h ? `pipeline_ready: ${h.pipeline_ready}` : "")} />
            <Row icon="memory" name="Model artifact" how="ml/artifacts/manifest.json (trained txn model)" result={hr(!!h?.model_sha256, h?.model_sha256 ?? "no trained model loaded", true)} />
            <Row icon="handshake" name="Contract version" how="engine/contracts.py CONTRACT_VERSION" result={hr(!!h?.contract_version, h?.contract_version ?? "")} />
            <Row icon="key" name="Login + bearer token" how="POST /v1/auth/login, then GET /v1/cases" result={cases} />
            <Row icon="admin_panel_settings" name="Role check on /actions" how="analyst → 403, lead/admin → 200" result={rbac} />
            <Row icon="lock" name="Audit chain" how="GET /v1/audit/verify (lead+): recompute every row hash" result={audit} />
            <Row icon="cell_tower" name="WebSocket with token" how="GET /v1/stream, first message {token}" result={ws} />
            <Row icon="block" name="WebSocket without token" how="bad token must close with 4401" result={wsBad} />
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
