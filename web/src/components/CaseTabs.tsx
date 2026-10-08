// Explanation / Replay / Ask tabs. D1-P3 delivers these bound to their contract types; D1-P6 adds the waterfall,
// the replay toggles + dual chart, and the Investigator AI.
import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import type { AskResponse, Explanation, ReplayResult } from "../types/contracts";
import { api, ApiError } from "../lib/api";
import { DETECTOR, signed } from "../lib/labels";
import { inr, istTime } from "../lib/format";
import { BandPill } from "./Risk";

export function CiteChips({ cites, onCite }: { cites: string[]; onCite: (id: string) => void }) {
  return <>{cites.map((c) => (
    <button key={c} onClick={() => onCite(c)} title="Show in timeline"
      className="ml-1 font-code-xs text-[10px] px-1.5 py-0.5 rounded-lg bg-surface-container text-primary-container hover:underline align-middle">{c}</button>
  ))}</>;
}

export function ExplanationTab({ ex, onCite }: { ex: Explanation | undefined; onCite: (id: string) => void }) {
  if (!ex) return <div className="p-6 text-on-surface-variant">Loading explanation…</div>;
  return (
    <div className="grid grid-cols-2 gap-3" data-testid="explanation-tab">
      <section className="bg-surface-container-lowest border border-outline-variant rounded-lg">
        <div className="h-10 px-3 flex items-center justify-between border-b border-outline-variant">
          <span className="font-headline-sm text-headline-sm">Narrative</span><BandPill band={ex.band} /></div>
        <ol className="p-3 flex flex-col gap-2 text-body-md">
          {ex.narrative.map((s, i) => (
            <li key={i}>{s.text.replace(/\s*\[[^\]]+\]/g, "")}<CiteChips cites={s.cites} onCite={onCite} /></li>
          ))}
        </ol>
      </section>
      <section className="bg-surface-container-lowest border border-outline-variant rounded-lg">
        <div className="h-10 px-3 flex items-center justify-between border-b border-outline-variant">
          <span className="font-headline-sm text-headline-sm">Contributions (log-odds)</span>
          <span className="font-code-xs text-code-xs text-on-surface-variant">{ex.prior_log_odds.toFixed(3)} → {ex.final_log_odds.toFixed(3)}</span></div>
        <table className="w-full text-body-sm tnum">
          <tbody>
            {ex.parts.map((p) => (
              <tr key={p.part_id} className="border-b border-outline-variant last:border-0 h-8">
                <td className="px-3 w-16 font-code-xs text-code-xs text-on-surface-variant">{p.ts ? istTime(p.ts) : ""}</td>
                <td className="px-1">
                  {p.detector && <span className="material-symbols-outlined !text-[14px] align-middle mr-1" style={{ color: DETECTOR[p.detector].color }}>{DETECTOR[p.detector].icon}</span>}
                  {p.label}{p.kind !== "evidence" && <span className="ml-1 text-[10px] uppercase text-on-surface-variant">{p.kind}</span>}</td>
                <td className={"px-3 text-right font-semibold " + (p.kind === "prior" ? "" : p.contribution >= 0 ? "text-risk-critical" : "text-risk-low")}>
                  {p.kind === "prior" ? p.contribution.toFixed(3) : signed(p.contribution, 3)}</td>
                <td className="px-3 text-right text-on-surface-variant w-16">{(p.running_p * 100).toFixed(1)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="px-3 py-2 text-body-xs text-on-surface-variant border-t border-outline-variant">The waterfall chart arrives in D1-P6.</p>
      </section>
    </div>
  );
}

export function ReplayTab({ caseId }: { caseId: string }) {
  const m = useMutation({ mutationFn: (ablate: string[]) => api<ReplayResult>(`/v1/cases/${caseId}/replay`, { method: "POST", body: { ablate, mode: "fused" } }) });
  const r = m.data;
  const tile = (label: string, value: string) => (
    <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-3">
      <div className="font-label-caps text-label-caps uppercase text-on-surface-variant">{label}</div>
      <div className="text-[22px] font-semibold tnum mt-1">{value}</div>
    </div>
  );
  return (
    <div className="flex flex-col gap-3" data-testid="replay-tab">
      <div className="flex items-center gap-2">
        <button onClick={() => m.mutate([])} className="h-8 px-3 rounded-lg bg-primary-container hover:bg-primary text-on-primary font-label-md text-label-md">Replay (fused)</button>
        <span className="text-body-sm text-on-surface-variant">Ablation toggles, siloed mode and the dual chart arrive in D1-P6.</span>
      </div>
      {m.isError && <div className="text-risk-critical text-body-sm">{(m.error as ApiError).message}</div>}
      {r && (
        <div className="grid grid-cols-4 gap-3">
          {tile("Earliest intervention", r.eip ? `${istTime(r.eip.ts, true)} IST` : "none")}
          {tile("Lead time", r.lead_time_s != null ? `${Math.floor(r.lead_time_s / 60)} min ${r.lead_time_s % 60}s` : "—")}
          {tile("Money protected", inr(r.money_protected_paise))}
          {tile("Lead time lost", r.lead_time_lost_s != null ? `${r.lead_time_lost_s}s` : "—")}
        </div>
      )}
    </div>
  );
}

const QUESTIONS = ["Why did you block this?", "What if we ignored KYC?", "What was the earliest intervention point?"];

export function AskTab({ caseId, onCite }: { caseId: string; onCite: (id: string) => void }) {
  const [q, setQ] = useState("");
  const m = useMutation({ mutationFn: (question: string) => api<AskResponse>(`/v1/cases/${caseId}/ask`, { method: "POST", body: { question } }) });
  return (
    <div className="flex flex-col gap-3 max-w-3xl" data-testid="ask-tab">
      <div className="flex gap-2 flex-wrap">
        {QUESTIONS.map((s) => <button key={s} onClick={() => { setQ(s); m.mutate(s); }}
          className="h-8 px-3 rounded-lg border border-outline-variant bg-surface-container-lowest hover:bg-surface-container-low text-body-sm">{s}</button>)}
      </div>
      <form onSubmit={(e) => { e.preventDefault(); if (q.trim()) m.mutate(q.trim()); }} className="flex gap-2">
        <input value={q} onChange={(e) => setQ(e.target.value)} maxLength={500} placeholder="Ask about this case…"
          className="flex-1 h-9 px-3 text-body-sm bg-white border border-outline-variant rounded-lg focus:outline-none focus:border-brand" />
        <button className="h-9 px-3 rounded-lg bg-primary-container text-on-primary font-label-md text-label-md">Ask</button>
      </form>
      {m.data && (
        <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-3 text-body-md">
          {m.data.sentences.length ? m.data.sentences.map((s, i) => <p key={i}>{s.text}<CiteChips cites={s.cites} onCite={onCite} /></p>) : m.data.answer}
        </div>
      )}
    </div>
  );
}
