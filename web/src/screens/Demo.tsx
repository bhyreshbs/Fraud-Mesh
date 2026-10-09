// /demo (admin) — Stitch "Demo Attack Simulator": scenario cards, execution pipeline, live telemetry stream (WebSocket
// case updates), the intervention result and the detectors that fired. Run = POST /v1/demo/run/{id} (autopilot plays
// signed events like the real senders); Reset = POST /v1/demo/reset.
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { RunResponse, StatusOk, Timeline } from "../types/contracts";
import { api, ApiError } from "../lib/api";
import { inr, pct, shortCaseId } from "../lib/format";
import { ACTION_LABEL, DETECTOR, reasonText, STAGE_LABEL } from "../lib/labels";
import { useStream } from "../lib/stream";
import { BandPill } from "../components/Risk";
import { LiveDot, PageHeader, Panel } from "../components/ui";

const SCENARIOS = [
  { id: "midnight_ato", title: "Midnight account takeover", icon: "nightlight", minutes: 27,
    tags: ["9 events", "IDS + login + SIM swap", "KYC + cloud + payee"],
    text: "Credential stuffing, new-device login, SMS swap, deepfake KYC, support-console limit raise, mule-linked payee, ₹4,80,000 transfer, then Priya taps “Not me”." },
  { id: "mule_fanin", title: "Mule fan-in", icon: "account_tree", minutes: 115,
    tags: ["26 events", "12 senders → 1 mule", "90% forwarded"],
    text: "Twelve customers pay one mule account within two hours; the mule forwards 90% onward." },
  { id: "benign_odd", title: "Benign but odd", icon: "flight", minutes: 6,
    tags: ["3 events", "new phone in Mumbai", "known payee"],
    text: "Priya travels, logs in on a new phone and approves the push on her registered phone. Should never exceed MEDIUM." },
];
const STAGES = [
  { n: "01", title: "Ingress", sub: "signed events accepted" },
  { n: "02", title: "Correlation", sub: "evidence joined into one case" },
  { n: "03", title: "Policy engine", sub: "band → actions" },
  { n: "04", title: "Mitigation", sub: "step-up / hold / block" },
];

export function Demo() {
  const qc = useQueryClient();
  const { status, feed } = useStream();
  const [scenario, setScenario] = useState("midnight_ato");
  const [speed, setSpeed] = useState(8);
  const [startedAt, setStartedAt] = useState<string | null>(null);
  const [note, setNote] = useState<{ text: string; bad?: boolean } | null>(null);

  const run = useMutation({
    mutationFn: () => api<RunResponse>(`/v1/demo/run/${scenario}`, { method: "POST", body: { speed } }),
    onMutate: () => setStartedAt(new Date().toISOString()),
    onSuccess: (r) => setNote({ text: `Started ${scenario} at ${speed}× (${r.run_id}). Events stream in below as the engine scores them.` }),
    onError: (e) => setNote({ text: `Run failed: ${(e as ApiError).code} ${(e as ApiError).message}`, bad: true }),
  });
  const reset = useMutation({
    mutationFn: () => api<StatusOk>("/v1/demo/reset", { method: "POST" }),
    onSuccess: () => { setNote({ text: "Sandbox reset: tables truncated, background reloaded, Midnight ATO preload and fraud seeds in place." }); setStartedAt(null); qc.invalidateQueries(); },
    onError: (e) => setNote({ text: `Reset failed: ${(e as ApiError).code} ${(e as ApiError).message}`, bad: true }),
  });
  const sc = SCENARIOS.find((s) => s.id === scenario)!;

  const runFeed = useMemo(() => (startedAt ? feed.filter((f) => f.at >= startedAt) : feed), [feed, startedAt]);
  const latest = runFeed[0]?.msg.case;
  const caseId = useMemo(() => {
    const score = new Map<string, number>();
    for (const f of runFeed) score.set(f.msg.case.case_id, (score.get(f.msg.case.case_id) ?? 0) + 1);
    return [...score.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  }, [runFeed]);
  const focus = runFeed.find((f) => f.msg.case.case_id === caseId)?.msg.case ?? latest;
  const tl = useQuery({ queryKey: ["timeline", caseId], enabled: !!caseId, queryFn: () => api<Timeline>(`/v1/cases/${caseId}/timeline`) });
  const fired = useMemo(() => {
    const by = new Map<string, { p: number; reasons: string[] }>();
    for (const e of tl.data?.evidence ?? []) {
      const cur = by.get(e.detector);
      if (!cur || e.p > cur.p) by.set(e.detector, { p: e.p, reasons: e.reasons.map((r) => r.code) });
    }
    return [...by.entries()].sort((a, b) => b[1].p - a[1].p);
  }, [tl.data]);
  const stageDone = [runFeed.length > 0, !!focus, !!focus && focus.latest_actions.length > 0,
    !!focus && (focus.payment_state !== "normal" || focus.latest_actions.some((a) => a.startsWith("STEP_UP")))];
  const outcome = !focus ? null : focus.payment_state === "blocked" ? "AUTO-BLOCKED" : focus.payment_state === "held" ? "PAYMENTS HELD"
    : focus.band === "MEDIUM" ? "STEP-UP ASKED" : "MONITORING";

  return (
    <div className="px-8 py-7 flex flex-col gap-7" data-testid="demo-page">
      <PageHeader eyebrow="Sandbox telemetry" meta={<><LiveDot on={status === "live"} /> stream {status}</>} title="Demo Attack Simulator"
        subtitle="Autopilot plays a scenario into the API exactly like the real senders: signed events, and step-ups answered through the bank-app and phone routes."
        actions={<>
          <button onClick={() => { if (confirm("Reset the demo? This truncates all runtime data and takes several minutes.")) reset.mutate(); }} disabled={reset.isPending}
            data-testid="reset" className="fm-btn"><span className="material-symbols-outlined !text-[18px]">restart_alt</span>{reset.isPending ? "Resetting…" : "Reset sandbox"}</button>
          <button onClick={() => run.mutate()} disabled={run.isPending || reset.isPending} data-testid="run" className="fm-btn-primary">
            <span className="material-symbols-outlined !text-[18px]">play_arrow</span>Trigger scenario</button>
        </>} />
      {note && <div className={"fm-card-sm px-4 py-3 text-body-sm " + (note.bad ? "text-risk-critical" : "")} data-testid="demo-log">{note.text}</div>}

      <div className="grid grid-cols-3 gap-6">
        {SCENARIOS.map((s) => {
          const on = s.id === scenario;
          return (
            <button key={s.id} onClick={() => setScenario(s.id)} data-testid={`scenario-${s.id}`}
              className={"text-left p-6 rounded-[1.25rem] transition-all flex flex-col gap-3 " + (on ? "fm-card ring-2 ring-primary-container/40" : "fm-card-sm hover:shadow-porcelain")}
              style={on ? { borderTop: "3px solid #D96B35" } : undefined}>
              <div className="flex items-center justify-between">
                <span className="w-11 h-11 rounded-xl bg-primary-fixed text-primary flex items-center justify-center shadow-porcelain-sm"><span className="material-symbols-outlined">{s.icon}</span></span>
                <span className="fm-pill">{on ? "Ready to inject" : `ID: ${s.id}`}</span>
              </div>
              <div className="text-[20px] font-semibold tracking-[-0.015em]">{s.title}</div>
              <div className="font-mono text-[12px] text-primary-container">{s.tags.join(" · ")}</div>
              <p className="text-body-sm text-on-surface-variant">{s.text}</p>
            </button>
          );
        })}
      </div>
      <div className="fm-card-sm px-5 py-3 flex items-center gap-4 flex-wrap">
        <label className="text-body-sm flex items-center gap-2 font-medium">Speed
          <input type="number" min={1} max={1000} step={1} value={speed} onChange={(e) => setSpeed(Math.max(1, Number(e.target.value) || 1))}
            data-testid="speed" className="w-24 h-10 px-3 tnum" /> ×</label>
        <span className="font-mono text-[12px] text-on-surface-variant">≈ {(sc.minutes / speed).toFixed(1)} wall-clock minutes for {sc.minutes} scenario-minutes</span>
        <Link to="/queue" className="ml-auto text-body-sm text-primary-container hover:underline">Watch the case queue →</Link>
      </div>

      <div className="grid grid-cols-[1.5fr_1fr] gap-6">
        <div className="flex flex-col gap-6">
          <Panel title="Execution pipeline & progression" right={<span className="font-mono text-[12px] text-on-surface-variant">single FIFO worker</span>}>
            <div className="px-5 pb-5 grid grid-cols-4 gap-3">
              {STAGES.map((st, i) => {
                const done = stageDone[i], active = !done && (i === 0 || stageDone[i - 1]) && !!startedAt;
                return (
                  <div key={st.n} className={done ? "fm-tint p-3" : "fm-sunken p-3"}>
                    <div className="flex items-center justify-between font-mono text-[11px] text-on-surface-variant">{st.n} / STAGE
                      <span className={"w-2 h-2 rounded-full " + (done ? "bg-primary-container" : active ? "bg-primary-fixed-dim fm-live-dot" : "bg-taupe/50")} /></div>
                    <div className="font-semibold mt-1">{st.title}</div>
                    <div className={"font-mono text-[11px] " + (done ? "text-primary-container" : "text-on-surface-variant")}>{done ? "complete" : active ? "running" : st.sub}</div>
                    <div className="h-1 mt-2 rounded-full bg-surface-container overflow-hidden"><div className="h-full bg-primary-container" style={{ width: done ? "100%" : active ? "45%" : "0%" }} /></div>
                  </div>
                );
              })}
            </div>
          </Panel>
          <Panel title={<span className="flex items-center gap-2"><LiveDot on={status === "live"} />Live telemetry stream</span>}
            right={<span className="font-mono text-[12px] text-on-surface-variant">{runFeed.length} case updates{startedAt ? " this run" : ""}</span>} testid="telemetry">
            <div className="mx-5 mb-5 fm-sunken p-3 max-h-[420px] overflow-y-auto flex flex-col gap-1.5 font-mono text-[12px]">
              {runFeed.length === 0 && <div className="text-on-surface-variant p-2">Waiting for events… trigger a scenario.</div>}
              {runFeed.map((f, i) => (
                <div key={i} className="grid grid-cols-[86px_96px_1fr_auto] gap-2 items-start px-2 py-1.5 rounded-lg hover:bg-porcelain">
                  <span className="text-on-surface-variant">{new Date(f.at).toLocaleTimeString("en-GB", { timeZone: "Asia/Kolkata", hour12: false })}</span>
                  <span className="px-1.5 rounded bg-primary-fixed text-primary text-center">{f.msg.payment_outcome ? "PAYMENT" : f.msg.step_up ? "STEP-UP" : "EVIDENCE"}</span>
                  <span className="text-on-surface">{shortCaseId(f.msg.case.case_id)} · {f.msg.case.current_stage ? STAGE_LABEL[f.msg.case.current_stage] : "—"} · P {pct(f.msg.case.p_attack)}
                    {f.msg.case.latest_actions.length > 0 && <span className="text-primary-container"> → {f.msg.case.latest_actions.map((a) => ACTION_LABEL[a]).join(", ")}</span>}
                    {f.msg.payment_outcome && <span className="text-risk-critical"> · transfer {f.msg.payment_outcome}</span>}</span>
                  <BandPill band={f.msg.case.band} />
                </div>
              ))}
            </div>
          </Panel>
        </div>
        <div className="flex flex-col gap-6">
          <Panel title="Autonomous intervention result" right={focus && <span className="fm-pill">{shortCaseId(focus.case_id)}</span>} testid="intervention">
            <div className="px-5 pb-5 flex flex-col gap-3">
              <div className={"p-5 rounded-2xl " + (outcome === "AUTO-BLOCKED" ? "bg-risk-critical-fill" : "fm-sunken")}>
                <div className="font-mono text-[11px] tracking-[0.1em] text-primary">INTERVENTION STATUS</div>
                <div className={"text-[40px] leading-[44px] font-bold tracking-[-0.03em] mt-1 " + (outcome === "AUTO-BLOCKED" ? "text-risk-critical" : "text-on-surface")}>{outcome ?? "IDLE"}</div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="fm-card-sm p-3"><div className="font-mono text-[11px] text-on-surface-variant">FUSED RISK</div>
                  <div className="text-[22px] font-semibold tnum text-primary-container">{focus ? pct(focus.p_attack) : "—"}</div>
                  <div className="text-body-xs text-on-surface-variant">{focus ? `${focus.stages_reached.length} stages reached` : ""}</div></div>
                <div className="fm-card-sm p-3"><div className="font-mono text-[11px] text-on-surface-variant">EXPOSURE KEPT</div>
                  <div className="text-[22px] font-semibold tnum">{focus && focus.payment_state !== "normal" ? inr(focus.amount_at_risk_paise) : inr(0)}</div>
                  <div className="text-body-xs text-on-surface-variant">{focus ? `payments ${focus.payment_state}` : ""}</div></div>
              </div>
              <div className="fm-tint px-4 py-3 text-body-sm">Triggered policy: <b>{focus?.latest_actions.map((a) => ACTION_LABEL[a]).join(", ") || "—"}</b></div>
            </div>
          </Panel>
          <Panel title="Detectors that fired" right={<span className="font-mono text-[12px] text-on-surface-variant">{fired.length} of 7</span>}>
            <div className="px-5 pb-5 flex flex-col gap-2.5">
              {fired.length === 0 && <div className="fm-sunken p-3 text-body-sm text-on-surface-variant">No evidence yet.</div>}
              {fired.map(([det, v]) => (
                <div key={det} className="fm-tint px-4 py-3">
                  <div className="flex items-center justify-between"><span className="font-semibold flex items-center gap-1.5">
                    <span className="material-symbols-outlined !text-[17px]" style={{ color: DETECTOR[det as keyof typeof DETECTOR].color }}>{DETECTOR[det as keyof typeof DETECTOR].icon}</span>
                    {DETECTOR[det as keyof typeof DETECTOR].label}</span><span className="font-mono text-primary-container">{pct(v.p)}</span></div>
                  <div className="h-1.5 my-2 rounded-full bg-surface-container overflow-hidden"><div className="h-full bg-primary-container" style={{ width: `${v.p * 100}%` }} /></div>
                  <div className="font-mono text-[11.5px] text-on-surface-variant">{v.reasons.map(reasonText).join(" · ")}</div>
                </div>
              ))}
              {caseId && <Link to={`/investigations/${caseId}`} className="fm-btn justify-center">View resulting case {shortCaseId(caseId)} →</Link>}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
