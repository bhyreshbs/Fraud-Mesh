// /demo-panel — the live two-laptop demo. Priya's laptop (her phone page) and the attacker's laptop (bank app as the
// attacker + his phone) act over the same Wi-Fi; this panel shows ONLY the cases created after the demo baseline, live,
// and Reset undoes just them (POST /v1/demo/reset-live restores the baseline snapshot in seconds; the benchmark data
// is not reloaded). Data: GET /v1/demo/live, refreshed by the WebSocket stream.
import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { CaseSummary } from "../types/contracts";
import { api, ApiError } from "../lib/api";
import { hasRole, useAuth } from "../lib/auth";
import { inr, istDateTime, pct, shortCaseId, shortToken } from "../lib/format";
import { ACTION_LABEL, attackVector, STAGE_LABEL } from "../lib/labels";
import { useStream } from "../lib/stream";
import { BandPill, PaymentChip, StageDots } from "../components/Risk";
import { LiveDot, PageHeader, Panel } from "../components/ui";

type Live = { baseline: { saved_at: string; counts: Record<string, number> } | null; cases: CaseSummary[] };

export function DemoPanel() {
  const { session } = useAuth();
  const admin = hasRole(session, "admin");
  const qc = useQueryClient();
  const { status, feed } = useStream();
  const live = useQuery({ queryKey: ["demo-live"], queryFn: () => api<Live>("/v1/demo/live"), refetchInterval: 5_000 });
  const [note, setNote] = useState<{ text: string; bad?: boolean } | null>(null);
  const reset = useMutation({
    mutationFn: () => api<{ seconds: number }>("/v1/demo/reset-live", { method: "POST" }),
    onSuccess: (r) => { setNote({ text: `Reset done in ${r.seconds} s: the live demo case is gone, the benchmark data is untouched.` }); qc.invalidateQueries(); },
    onError: (e) => setNote({ text: (e as ApiError).code === "FORBIDDEN" ? "Only admin can reset: sign in as admin@fraudmesh.local." : (e as ApiError).message, bad: true }),
  });
  const save = useMutation({
    mutationFn: () => api("/v1/demo/baseline", { method: "POST" }),
    onSuccess: () => { setNote({ text: "Current data saved as the demo baseline. Reset will return here." }); qc.invalidateQueries({ queryKey: ["demo-live"] }); },
    onError: (e) => setNote({ text: (e as ApiError).message, bad: true }),
  });
  const cases = live.data?.cases ?? [];
  const ids = new Set(cases.map((c) => c.case_id));
  const events = feed.filter((f) => ids.has(f.msg.case.case_id)).slice(0, 25);
  const host = window.location.hostname;

  return (
    <div className="px-8 py-7 flex flex-col gap-7" data-testid="demo-panel">
      <PageHeader meta={<><LiveDot on={status === "live"} /> stream {status}</>} title="Demo"
        subtitle="Only the cases created by the live demo appear here. Reset removes just them, in seconds."
        actions={<>
          {live.data && !live.data.baseline && admin && <button className="fm-btn" onClick={() => save.mutate()} disabled={save.isPending}>Save current data as baseline</button>}
          <button onClick={() => { if (confirm("Reset the live demo? Only the demo case(s) are removed.")) reset.mutate(); }}
            disabled={reset.isPending || !live.data?.baseline} data-testid="demo-panel-reset" className="fm-btn-primary">
            <span className="material-symbols-outlined !text-[18px]">restart_alt</span>{reset.isPending ? "Resetting…" : "Reset"}</button>
        </>} />
      {note && <div className={"fm-card-sm px-4 py-3 text-body-sm " + (note.bad ? "text-risk-critical" : "")} data-testid="demo-panel-note">{note.text}</div>}

      <div className="grid grid-cols-3 gap-6">
        <div className="fm-card p-5">
          <div className="font-mono text-[11px] tracking-[0.1em] text-on-surface-variant">LAPTOP 1 · PRIYA</div>
          <div className="font-semibold mt-1">Priya's registered phone</div>
          <div className="fm-sunken px-3 py-2 mt-2 font-mono text-[12.5px] break-all">http://{host}:5174/phone/priya</div>
          <div className="text-body-sm text-on-surface-variant mt-2">Her known device and home IP. She receives the bank's push and taps <b>“Not me”</b>.</div>
        </div>
        <div className="fm-card p-5">
          <div className="font-mono text-[11px] tracking-[0.1em] text-risk-critical">LAPTOP 2 · ATTACKER</div>
          <div className="font-semibold mt-1">Bank app as “Attacker laptop”</div>
          <div className="fm-sunken px-3 py-2 mt-2 font-mono text-[12.5px] break-all">http://{host}:5174</div>
          <div className="text-body-sm text-on-surface-variant mt-2">Log in (the network sensor raises an IDS alert live), change the SMS number, add payee <span className="font-mono">A-RAVI-778</span>, transfer ₹4,80,000. OTPs arrive at <span className="font-mono">/phone/attacker</span>.</div>
        </div>
        <div className="fm-card p-5">
          <div className="font-mono text-[11px] tracking-[0.1em] text-on-surface-variant">BASELINE</div>
          {live.data?.baseline ? (
            <>
              <div className="font-semibold mt-1">Saved {istDateTime(live.data.baseline.saved_at)}</div>
              <div className="text-body-sm text-on-surface-variant mt-2">{(live.data.baseline.counts.cases ?? 0).toLocaleString("en-IN")} cases and
                {" "}{(live.data.baseline.counts.events ?? 0).toLocaleString("en-IN")} events stay untouched by Reset.</div>
            </>
          ) : <div className="text-body-sm text-on-surface-variant mt-2">No baseline yet{admin ? ": save the current data first." : " (admin saves it)."}</div>}
        </div>
      </div>

      <Panel title={<span className="flex items-center gap-2"><LiveDot on={status === "live"} />Live demo case{cases.length === 1 ? "" : "s"}</span>}
        subtitle="Created after the baseline: the attacker's actions, scored live" right={<span className="fm-pill">{cases.length}</span>} testid="demo-cases">
        <div className="px-5 pb-5 flex flex-col gap-4">
          {cases.length === 0 && <div className="fm-sunken p-5 text-body-md text-on-surface-variant">Waiting for the attacker… log in from the attacker's laptop.</div>}
          {cases.map((c) => (
            <div key={c.case_id} className="fm-tint p-5 flex flex-col gap-3" data-testid="demo-case">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="font-mono font-semibold">{shortCaseId(c.case_id)}</span><BandPill band={c.band} />
                <span className="font-semibold">{attackVector(c.stages_reached).label}</span>
                <span className="font-mono text-[12px] text-on-surface-variant">{shortToken(c.customer)}</span>
                <span className="ml-auto text-[30px] font-semibold tnum text-primary-container">{pct(c.p_attack)}</span>
              </div>
              <div className="flex items-center gap-4 flex-wrap">
                <StageDots reached={c.stages_reached} />
                <span className="text-body-sm">{c.current_stage ? STAGE_LABEL[c.current_stage] : "—"}</span>
                <PaymentChip state={c.payment_state} />
                {c.amount_at_risk_paise > 0 && <span className="font-mono text-body-sm">{inr(c.amount_at_risk_paise)} at risk</span>}
              </div>
              <div className="text-body-sm">Action: <b>{c.latest_actions.map((a) => ACTION_LABEL[a]).join(", ") || "monitoring"}</b></div>
              <div className="flex gap-2">
                <Link to={`/investigations/${c.case_id}`} className="fm-btn-primary !h-9">Investigate</Link>
                <Link to={`/twin?case=${c.case_id}`} className="fm-btn !h-9">Replay in twin</Link>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Live events" subtitle="Each step the engine scored for the demo case, newest first">
        <div className="mx-5 mb-5 fm-sunken p-3 flex flex-col gap-1.5 font-mono text-[12.5px] min-h-[80px]">
          {events.length === 0 && <div className="text-on-surface-variant p-2">No events yet.</div>}
          {events.map((f, i) => (
            <div key={i} className="grid grid-cols-[86px_1fr_auto] gap-2 items-center px-2 py-1.5 rounded-lg hover:bg-porcelain">
              <span className="text-on-surface-variant">{new Date(f.at).toLocaleTimeString("en-GB", { timeZone: "Asia/Kolkata", hour12: false })}</span>
              <span>{f.msg.case.current_stage ? STAGE_LABEL[f.msg.case.current_stage] : "—"} · P {pct(f.msg.case.p_attack)}
                {f.msg.case.latest_actions.length > 0 && <span className="text-primary-container"> → {f.msg.case.latest_actions.map((a) => ACTION_LABEL[a]).join(", ")}</span>}
                {f.msg.payment_outcome && <span className="text-risk-critical font-semibold"> · transfer {f.msg.payment_outcome}</span>}</span>
              <BandPill band={f.msg.case.band} />
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
