// Explanation (waterfall + narrative), Replay (what-if with toggles) and Ask (Investigator AI) tabs — PRD §11.1, D1-P6.
import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, ReferenceArea, ReferenceDot, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AskResponse, DetectorId, Explanation, NarrativeSentence, ReplayResult } from "../types/contracts";
import { api, ApiError } from "../lib/api";
import { ACTION_LABEL, DETECTOR, signed } from "../lib/labels";
import { inr, istTime } from "../lib/format";
import { BandPill } from "./Risk";

const LOGIT = (p: number) => Math.log(p / (1 - p));

export function CiteChips({ cites, onCite }: { cites: string[]; onCite: (id: string) => void }) {
  return <>{cites.map((c) => {
    const jump = c.startsWith("ev_");
    return (
      <button key={c} onClick={() => jump && onCite(c)} title={jump ? "Show in timeline" : c} disabled={!jump} data-testid="cite-chip"
        className={"ml-1 font-code-xs text-[10px] px-1.5 py-0.5 rounded-lg align-middle " +
          (jump ? "bg-surface-container text-primary-container hover:underline" : "bg-surface-container-low text-on-surface-variant cursor-default")}>{c}</button>
    );
  })}</>;
}

// ------------------------------------------------------------------ Explanation
type WRow = { name: string; range: [number, number]; delta: number; kind: string; detector: DetectorId | null; id: string };

export function ExplanationTab({ ex, onCite }: { ex: Explanation | undefined; onCite: (id: string) => void }) {
  if (!ex) return <div className="p-6 text-on-surface-variant">Loading explanation…</div>;
  let run = 0;
  const rows: WRow[] = [];
  for (const p of ex.parts) {
    if (p.kind === "floor") continue;
    const start = p.kind === "prior" ? 0 : run;
    run = p.running_log_odds;
    rows.push({ name: p.kind === "prior" ? "Prior" : p.kind === "pattern" ? p.part_id.replace("pat_", "") : (p.detector ? DETECTOR[p.detector].label : p.part_id),
      range: [start, run], delta: p.kind === "prior" ? p.contribution : p.contribution, kind: p.kind, detector: p.detector ?? null, id: p.part_id });
  }
  rows.push({ name: "Final", range: [0, ex.final_log_odds], delta: ex.final_log_odds, kind: "final", detector: null, id: "final" });
  const color = (r: WRow) => r.kind === "prior" ? "#9CA3AF" : r.kind === "final" ? "#2457C5" : r.kind === "pattern" ? "#7C3AED" : r.delta >= 0 ? "#B42318" : "#1E6B45";
  const lo = Math.min(...rows.map((r) => Math.min(...r.range))) - 0.5, hi = Math.max(...rows.map((r) => Math.max(...r.range))) + 0.5;

  return (
    <div className="flex flex-col gap-3" data-testid="explanation-tab">
      <section className="bg-surface-container-lowest border border-outline-variant rounded-lg">
        <div className="h-10 px-3 flex items-center justify-between border-b border-outline-variant">
          <span className="font-headline-sm text-headline-sm">How the score was built (log-odds waterfall)</span>
          <span className="flex items-center gap-2 font-code-xs text-code-xs text-on-surface-variant">
            {ex.prior_log_odds.toFixed(2)} → {ex.final_log_odds.toFixed(2)} · P {(ex.p_attack * 100).toFixed(1)}% <BandPill band={ex.band} /></span>
        </div>
        <div className="p-2" data-testid="waterfall">
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={rows} margin={{ top: 16, right: 92, bottom: 48, left: 0 }}>
              <CartesianGrid stroke="#E2E5E9" vertical={false} />
              <ReferenceArea y1={LOGIT(0.8)} y2={hi} fill="#FEF3F2" fillOpacity={0.6} />
              <ReferenceArea y1={LOGIT(0.5)} y2={LOGIT(0.8)} fill="#FFF4E5" fillOpacity={0.6} />
              <ReferenceArea y1={LOGIT(0.2)} y2={LOGIT(0.5)} fill="#FEF7E0" fillOpacity={0.6} />
              {[[0.2, "MEDIUM 20%"], [0.5, "HIGH 50%"], [0.8, "CRITICAL 80%"]].map(([p, l]) => (
                <ReferenceLine key={l as string} y={LOGIT(p as number)} stroke="#737685" strokeDasharray="4 3"
                  label={{ value: l as string, position: "right", fontSize: 10, fill: "#434653" }} />))}
              <ReferenceLine y={0} stroke="#C3C6D5" />
              <XAxis dataKey="name" interval={0} angle={-30} textAnchor="end" tick={{ fontSize: 10 }} height={60} />
              <YAxis domain={[Math.floor(lo), Math.ceil(hi)]} tick={{ fontSize: 11 }} width={36} />
              <Tooltip formatter={(_v, _n, item) => { const r = item.payload as WRow; return [r.kind === "final" || r.kind === "prior" ? r.delta.toFixed(3) : signed(r.delta, 3), r.kind]; }}
                contentStyle={{ fontSize: 12, borderRadius: 4 }} />
              <Bar dataKey="range" isAnimationActive={false}>
                {rows.map((r) => <Cell key={r.id} fill={color(r)} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>
      <div className="grid grid-cols-2 gap-3">
        <section className="bg-surface-container-lowest border border-outline-variant rounded-lg">
          <div className="h-10 px-3 flex items-center border-b border-outline-variant font-headline-sm text-headline-sm">Narrative</div>
          <ol className="p-3 flex flex-col gap-2 text-body-md" data-testid="narrative">
            {ex.narrative.map((s, i) => <li key={i}>{s.text.replace(/\s*\[[^\]]+\]/g, "")}<CiteChips cites={s.cites} onCite={onCite} /></li>)}
          </ol>
        </section>
        <section className="bg-surface-container-lowest border border-outline-variant rounded-lg">
          <div className="h-10 px-3 flex items-center border-b border-outline-variant font-headline-sm text-headline-sm">Parts</div>
          <table className="w-full text-body-sm tnum">
            <tbody>
              {ex.parts.map((p) => (
                <tr key={p.part_id} className="border-b border-outline-variant last:border-0 h-8">
                  <td className="px-3 w-16 font-code-xs text-code-xs text-on-surface-variant">{p.ts ? istTime(p.ts) : ""}</td>
                  <td className="px-1">{p.detector && <span className="material-symbols-outlined !text-[14px] align-middle mr-1" style={{ color: DETECTOR[p.detector].color }}>{DETECTOR[p.detector].icon}</span>}
                    {p.label}{p.kind !== "evidence" && <span className="ml-1 text-[10px] uppercase text-on-surface-variant">{p.kind}</span>}</td>
                  <td className={"px-3 text-right font-semibold " + (p.kind === "prior" || p.kind === "floor" ? "" : p.contribution >= 0 ? "text-risk-critical" : "text-risk-low")}>
                    {p.kind === "prior" ? p.contribution.toFixed(3) : signed(p.contribution, 3)}</td>
                  <td className="px-3 text-right text-on-surface-variant w-16">{(p.running_p * 100).toFixed(1)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ Replay
const TOGGLES: { key: string; label: string; ablate?: DetectorId; siloed?: boolean }[] = [
  { key: "siloed", label: "Siloed (each detector alone)", siloed: true },
  { key: "kyc", label: "Without KYC", ablate: "kyc" }, { key: "cyber", label: "Without cyber", ablate: "cyber" },
  { key: "netsec", label: "Without netsec", ablate: "netsec" },
];
const fmtLead = (s: number | null | undefined) => s == null ? "—" : `${Math.floor(s / 60)} min ${s % 60}s`;

export function ReplayTab({ caseId }: { caseId: string }) {
  const [on, setOn] = useState<Record<string, boolean>>({});
  const ablate = TOGGLES.filter((t) => on[t.key] && t.ablate).map((t) => t.ablate!) as DetectorId[];
  const mode = on.siloed ? "siloed" : "fused";
  const post = (body: { ablate: DetectorId[]; mode: string }) => api<ReplayResult>(`/v1/cases/${caseId}/replay`, { method: "POST", body });
  const base = useQuery({ queryKey: ["replay", caseId, "fused", ""], queryFn: () => post({ ablate: [], mode: "fused" }) });
  const what = useQuery({ queryKey: ["replay", caseId, mode, ablate.join(",")], queryFn: () => post({ ablate, mode }),
    enabled: ablate.length > 0 || mode !== "fused" });
  const r = (ablate.length || mode !== "fused") ? what.data : base.data;
  const b = base.data;
  const pts = new Map<number, { t: number; base?: number; replay?: number }>();
  for (const p of b?.timeline ?? []) { const t = new Date(p.ts).getTime(); pts.set(t, { ...(pts.get(t) ?? { t }), base: p.p }); }
  if (r && r !== b) for (const p of r.timeline) { const t = new Date(p.ts).getTime(); pts.set(t, { ...(pts.get(t) ?? { t }), replay: p.p }); }
  const data = [...pts.values()].sort((x, y) => x.t - y.t);
  const tile = (label: string, value: string, testid: string, sub?: string) => (
    <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-3" data-testid={testid}>
      <div className="font-label-caps text-label-caps uppercase text-on-surface-variant">{label}</div>
      <div className="text-[22px] font-semibold tnum mt-1">{value}</div>{sub && <div className="text-body-xs text-on-surface-variant">{sub}</div>}
    </div>
  );
  const err = (base.error ?? what.error) as ApiError | null;

  return (
    <div className="flex flex-col gap-3" data-testid="replay-tab">
      <div className="flex items-center gap-4 flex-wrap bg-surface-container-lowest border border-outline-variant rounded-lg px-3 py-2">
        <span className="font-label-caps text-label-caps uppercase text-on-surface-variant">What if</span>
        {TOGGLES.map((t) => (
          <label key={t.key} className="flex items-center gap-1.5 text-body-sm cursor-pointer">
            <input type="checkbox" checked={!!on[t.key]} onChange={() => setOn((o) => ({ ...o, [t.key]: !o[t.key] }))} data-testid={`toggle-${t.key}`} />{t.label}</label>
        ))}
        {(base.isFetching || what.isFetching) && <span className="text-body-xs text-on-surface-variant">replaying…</span>}
      </div>
      {err && <div className="text-risk-critical text-body-sm">{err.code}: {err.message}</div>}
      <div className="grid grid-cols-4 gap-3">
        {tile("Earliest intervention", r?.eip ? `${istTime(r.eip.ts, true)} IST` : "never", "tile-eip", r?.eip ? `P ${(r.eip.p * 100).toFixed(1)}% · ${r.eip.actions.map((a) => ACTION_LABEL[a]).join(", ")}` : "no HOLD reached")}
        {tile("Lead time", fmtLead(r?.lead_time_s), "tile-lead", "before the first transfer")}
        {tile("Money protected", r ? inr(r.money_protected_paise) : "—", "tile-money")}
        {tile("Lead time lost", r?.lead_time_lost_s != null ? fmtLead(r.lead_time_lost_s) : r && !r.eip && b?.eip ? "all of it" : "—", "tile-lost", "vs the full system")}
      </div>
      <section className="bg-surface-container-lowest border border-outline-variant rounded-lg">
        <div className="h-10 px-3 flex items-center justify-between border-b border-outline-variant">
          <span className="font-headline-sm text-headline-sm">P(attack): full system vs {mode === "siloed" ? "siloed detectors" : ablate.length ? `without ${ablate.join(", ")}` : "same"}</span>
          <span className="text-body-xs text-on-surface-variant flex gap-3"><span>━ baseline</span><span>┅ what-if</span><span>● EIP</span></span>
        </div>
        <div className="p-2" data-testid="replay-chart">
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={data} margin={{ top: 10, right: 24, bottom: 4, left: 0 }}>
              <ReferenceArea y1={0.8} y2={1} fill="#FEF3F2" fillOpacity={0.8} />
              <ReferenceArea y1={0.5} y2={0.8} fill="#FFF4E5" fillOpacity={0.7} />
              <ReferenceArea y1={0.2} y2={0.5} fill="#FEF7E0" fillOpacity={0.7} />
              <CartesianGrid stroke="#E2E5E9" vertical={false} />
              <XAxis dataKey="t" type="number" scale="time" domain={["dataMin", "dataMax"]} tickFormatter={(t) => istTime(new Date(t).toISOString())} tick={{ fontSize: 11 }} />
              <YAxis domain={[0, 1]} ticks={[0, 0.2, 0.5, 0.8, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} width={44} tick={{ fontSize: 11 }} />
              <Tooltip labelFormatter={(t) => istTime(new Date(t as number).toISOString(), true)} formatter={(v: number, n) => [`${(v * 100).toFixed(1)}%`, n]} />
              <Line type="stepAfter" dataKey="base" name="baseline" stroke="#2457C5" strokeWidth={2} dot={{ r: 3 }} connectNulls isAnimationActive={false} />
              {r !== b && <Line type="stepAfter" dataKey="replay" name="what-if" stroke="#B54708" strokeWidth={2} strokeDasharray="6 4" dot={{ r: 3 }} connectNulls isAnimationActive={false} />}
              {b?.eip && <ReferenceDot x={new Date(b.eip.ts).getTime()} y={b.eip.p} r={7} fill="#2457C5" stroke="#fff" />}
              {r && r !== b && r.eip && <ReferenceDot x={new Date(r.eip.ts).getTime()} y={r.eip.p} r={7} fill="#fff" stroke="#B54708" strokeWidth={3} />}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>
    </div>
  );
}

// ------------------------------------------------------------------ Ask (Investigator AI)
const QUESTIONS = ["Why did you block this?", "What if we ignored KYC?", "What was the earliest intervention point?"];

export function AskTab({ caseId, onCite }: { caseId: string; onCite: (id: string) => void }) {
  const [q, setQ] = useState("");
  const [history, setHistory] = useState<{ q: string; r: AskResponse }[]>([]);
  const m = useMutation({
    mutationFn: (question: string) => api<AskResponse>(`/v1/cases/${caseId}/ask`, { method: "POST", body: { question } }),
    onSuccess: (r, question) => setHistory((h) => [{ q: question, r }, ...h].slice(0, 10)),
  });
  const send = (s: string) => { if (s.trim()) { setQ(""); m.mutate(s.trim()); } };
  return (
    <div className="flex flex-col gap-3 max-w-4xl" data-testid="ask-tab">
      <div className="flex gap-2 flex-wrap">
        {QUESTIONS.map((s) => <button key={s} onClick={() => send(s)} data-testid="ask-chip"
          className="h-8 px-3 rounded-lg border border-outline-variant bg-surface-container-lowest hover:bg-surface-container-low text-body-sm">{s}</button>)}
      </div>
      <form onSubmit={(e) => { e.preventDefault(); send(q); }} className="flex gap-2">
        <input value={q} onChange={(e) => setQ(e.target.value)} maxLength={500} placeholder="Ask about this case…" data-testid="ask-input"
          className="flex-1 h-9 px-3 text-body-sm bg-white border border-outline-variant rounded-lg focus:outline-none focus:border-brand" />
        <button className="h-9 px-3 rounded-lg bg-primary-container text-on-primary font-label-md text-label-md" disabled={m.isPending}>Ask</button>
      </form>
      {m.isError && <div className="text-risk-critical text-body-sm">{(m.error as ApiError).message}</div>}
      <p className="text-body-xs text-on-surface-variant">Answers come from fixed templates over read-only tools for this case. Every sentence cites
        evidence, decisions or replays; a validator removes any sentence whose citation or number does not come from those tools.</p>
      {history.map(({ q: question, r }, i) => (
        <div key={i} className="bg-surface-container-lowest border border-outline-variant rounded-lg" data-testid="ask-answer">
          <div className="px-3 py-2 border-b border-outline-variant text-body-sm font-medium flex items-center gap-2">
            <span className="material-symbols-outlined !text-[16px] text-on-surface-variant">help</span>{question}</div>
          <div className="p-3 flex flex-col gap-1.5 text-body-md">
            {r.sentences.map((s: NarrativeSentence, j) => <p key={j}>{s.text}<CiteChips cites={s.cites} onCite={onCite} /></p>)}
            {r.removed > 0 && <p className="text-body-xs text-on-surface-variant/70 italic" data-testid="ask-removed">
              {r.removed} sentence{r.removed > 1 ? "s" : ""} removed by the validator (unsupported citation or number).</p>}
          </div>
        </div>
      ))}
    </div>
  );
}
