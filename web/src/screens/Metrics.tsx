// /metrics — live tiles + benchmark from GET /v1/metrics/summary, and the policy simulator: three band-threshold
// sliders that re-score the stored cases through POST /v1/simulate (PRD §11.1, F19).
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useCases, useMetrics } from "../lib/queries";
import type { Band, SimulationResult } from "../types/contracts";
import { inr, pct } from "../lib/format";
import { BandPill } from "../components/Risk";
import { Kpi, PageHeader, Panel } from "../components/ui";
import { api, ApiError } from "../lib/api";

function Tile({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="fm-tint p-4">
      <div className="font-mono text-[11px] tracking-[0.08em] uppercase text-on-surface-variant">{label}</div>
      <div className="text-[24px] font-semibold tnum mt-1">{value}</div>
      {sub && <div className="text-body-xs text-on-surface-variant">{sub}</div>}
    </div>
  );
}

const FAMILY: Record<string, string> = { ato: "Account takeover", mule_fanin: "Mule fan-in", structuring: "Structuring" };
const BANDS: Band[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export function Metrics() {
  const q = useMetrics();
  const cases = useCases();
  const live = q.data?.live;
  const b = q.data?.benchmark;
  const items = cases.data?.items ?? [];
  const fam = b ? Object.entries(b.families).map(([k, f]) => ({ name: FAMILY[k] ?? k, fused: f.caught_fused, siloed: f.caught_siloed, n: f.instances })) : [];
  return (
    <div className="px-8 py-7 flex flex-col gap-7" data-testid="metrics">
      <PageHeader eyebrow="Analytics terminal" meta={<>benchmark: seed {b?.seed ?? "—"} · {b?.days ?? "—"} days held out</>}
        title="Metrics & Analytics" subtitle="Money kept in the bank, detection quality on held-out data, and what-if policy thresholds." />
      {q.isError && <div className="text-risk-critical text-body-sm">{(q.error as ApiError).message}</div>}
      <div className="grid grid-cols-4 gap-6">
        <Kpi label="Net loss prevented" value={live ? inr(live.money_protected_paise) : "—"} icon="savings" tone="high" sub="held or blocked, not false positives" />
        <Kpi label="Txn model precision" value={b ? pct(b.txn_pr_auc, 2) : "—"} icon="target" tone="low" sub={b ? `ROC-AUC ${b.txn_roc_auc.toFixed(3)} · ECE ${b.txn_ece.toFixed(4)}` : ""} />
        <Kpi label="Alert compression" value={live ? `${live.alert_compression.toFixed(1)} : 1` : "—"} icon="compress" sub="alerts (p ≥ 0.05) per open case" />
        <Kpi label="False-positive rate" value={b ? pct(b.false_positive_rate, 2) : "—"} icon="verified_user" tone="low"
          sub={b ? `${b.benign_flagged_high} of ${b.benign_customers} genuine customers HIGH · false declines ${pct(b.false_declines_rate, 2)}` : ""} />
      </div>
      <div className="grid grid-cols-[1.5fr_1fr] gap-6">
        <Panel title="Attacks caught: fused vs siloed" subtitle="Held-out benchmark attacks per family, caught before the attack's last event (PRD §10.9)" testid="family-chart">
          <div className="px-4 pb-4">
            {b ? (
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={fam} margin={{ top: 10, right: 16, bottom: 0, left: -10 }}>
                  <CartesianGrid stroke="#E6D9CA" strokeDasharray="3 4" vertical={false} />
                  <XAxis dataKey="name" tick={{ fontSize: 12, fill: "#756D64" }} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#756D64" }} />
                  <Tooltip contentStyle={{ fontSize: 12, borderRadius: 12, border: "1px solid #E6D9CA", background: "#FFFEFC" }} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Bar dataKey="fused" name="FraudMesh (fused)" fill="#D96B35" radius={[8, 8, 0, 0]} isAnimationActive={false} />
                  <Bar dataKey="siloed" name="Siloed detectors" fill="#B8A99A" radius={[8, 8, 0, 0]} isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            ) : <div className="fm-sunken p-4 text-body-sm text-on-surface-variant">No benchmark yet: run <span className="font-mono">python -m benchmark.run</span>.</div>}
          </div>
        </Panel>
        <Panel title="Detection by family" subtitle="Instances and median lead time">
          <div className="px-5 pb-5 flex flex-col gap-3">
            {b && Object.entries(b.families).map(([k, f]) => (
              <div key={k} className="fm-tint px-4 py-3">
                <div className="flex items-center justify-between"><span className="font-semibold">{FAMILY[k] ?? k}</span>
                  <span className="font-mono text-primary-container">{f.caught_fused} / {f.instances}</span></div>
                <div className="flex items-center justify-between font-mono text-[11.5px] text-on-surface-variant mt-1">
                  <span>siloed {f.caught_siloed} / {f.instances}</span>
                  <span>lead {f.median_lead_time_s == null ? "—" : `${Math.round(f.median_lead_time_s / 60)} min`}</span></div>
                <div className="h-1.5 mt-2 rounded-full bg-surface-container overflow-hidden"><div className="h-full bg-primary-container" style={{ width: `${(100 * f.caught_fused) / f.instances}%` }} /></div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
      <Panel title="Live impact by band" subtitle="Cases currently in the mesh">
        <table className="w-full text-body-sm">
          <thead><tr className="font-mono text-[11px] tracking-[0.08em] uppercase text-on-surface-variant bg-surface-container-low/70">
            <th className="pl-6 py-3 text-left">Band</th><th className="px-3 text-right">Cases</th><th className="px-3 text-right">Exposure</th>
            <th className="px-3 text-right">Kept (held / blocked)</th><th className="pr-6 text-left w-72">Containment</th></tr></thead>
          <tbody>{BANDS.map((band) => {
            const rows = items.filter((c) => c.band === band);
            const exp = rows.reduce((s2, c) => s2 + c.amount_at_risk_paise, 0);
            const kept = rows.filter((c) => c.payment_state !== "normal");
            const share = rows.length ? kept.length / rows.length : 0;
            return (
              <tr key={band} className="fm-row border-t border-taupe/20 h-14">
                <td className="pl-6"><BandPill band={band} /></td><td className="px-3 text-right font-mono">{rows.length}</td>
                <td className="px-3 text-right font-mono">{inr(exp)}</td>
                <td className="px-3 text-right font-mono">{inr(kept.reduce((s2, c) => s2 + c.amount_at_risk_paise, 0))}</td>
                <td className="pr-6"><div className="flex items-center gap-2"><div className="flex-1 h-1.5 rounded-full bg-surface-container overflow-hidden">
                  <div className="h-full bg-primary-container" style={{ width: `${share * 100}%` }} /></div><span className="font-mono w-14 text-right">{pct(share, 0)}</span></div></td>
              </tr>);
          })}</tbody>
        </table>
      </Panel>
      <Simulator />
    </div>
  );
}

const DEFAULTS = { medium: 0.2, high: 0.5, critical: 0.8 };

function Simulator() {
  const [t, setT] = useState(DEFAULTS);
  const [debounced, setDebounced] = useState(DEFAULTS);
  useEffect(() => { const id = setTimeout(() => setDebounced(t), 300); return () => clearTimeout(id); }, [t]);
  const q = useQuery({ queryKey: ["simulate", debounced], queryFn: () => api<SimulationResult>("/v1/simulate", { method: "POST", body: debounced }),
    placeholderData: (prev) => prev });
  const base = useQuery({ queryKey: ["simulate", DEFAULTS], queryFn: () => api<SimulationResult>("/v1/simulate", { method: "POST", body: DEFAULTS }) });
  const r = q.data, b = base.data;
  const set = (k: keyof typeof DEFAULTS, v: number) => setT((cur) => {
    const n = { ...cur, [k]: v };
    if (n.medium >= n.high) { if (k === "medium") n.high = Math.min(0.98, n.medium + 0.01); else n.medium = Math.max(0.01, n.high - 0.01); }
    if (n.high >= n.critical) { if (k === "critical") n.high = Math.max(n.medium + 0.01, n.critical - 0.01); else n.critical = Math.min(0.99, n.high + 0.01); }
    return { medium: +n.medium.toFixed(2), high: +n.high.toFixed(2), critical: +n.critical.toFixed(2) };
  });
  const delta = (cur?: number, was?: number) => cur == null || was == null || cur === was ? "" : ` (${cur > was ? "+" : ""}${cur - was} vs default)`;
  return (
    <section className="fm-card" data-testid="simulator">
      <div className="px-6 pt-5 pb-3 flex items-start justify-between">
        <div><div className="text-[19px] font-semibold tracking-[-0.015em]">Policy simulator</div>
          <div className="text-body-sm text-on-surface-variant">Move the band thresholds and re-score every stored case: no customer is affected.</div></div>
        <button onClick={() => setT(DEFAULTS)} className="fm-btn !h-9">Reset to 0.20 / 0.50 / 0.80</button>
      </div>
      <div className="px-6 py-3 grid grid-cols-3 gap-6">
        {(["medium", "high", "critical"] as const).map((k) => (
          <label key={k} className="text-body-sm">
            <span className="flex justify-between"><span className="capitalize font-medium">{k} band from</span>
              <span className="font-mono tnum" data-testid={`thr-${k}`}>{t[k].toFixed(2)}</span></span>
            <input type="range" min={0.01} max={0.99} step={0.01} value={t[k]} onChange={(e) => set(k, Number(e.target.value))}
              data-testid={`slider-${k}`} className="w-full" />
          </label>
        ))}
      </div>
      <div className="px-6 pb-4 grid grid-cols-5 gap-3" data-testid="sim-tiles">
        <Tile label="Attacks caught" value={r ? `${r.attacks_caught} / ${r.attacks_total}` : "—"} sub={"before the attack's last event" + delta(r?.attacks_caught, b?.attacks_caught)} />
        <Tile label="Benign customers flagged" value={r ? `${r.benign_customers_flagged} / ${r.benign_customers_total}` : "—"} sub={"reached HIGH" + delta(r?.benign_customers_flagged, b?.benign_customers_flagged)} />
        <Tile label="Legit payments stopped" value={r ? `${r.legit_payments_stopped} / ${r.legit_payments_total}` : "—"} sub={"held or blocked" + delta(r?.legit_payments_stopped, b?.legit_payments_stopped)} />
        <Tile label="Money protected" value={r ? inr(r.money_protected_paise) : "—"} />
        <Tile label="Median lead time" value={r?.median_lead_time_s != null ? `${Math.floor(r.median_lead_time_s / 60)} min ${r.median_lead_time_s % 60}s` : "—"} sub="caught attacks" />
      </div>
      <p className="px-6 pb-5 text-body-xs text-on-surface-variant">{q.isFetching ? "re-scoring…" : "Scores come from replaying every stored case with these thresholds (labels from the generator / scenario runs)."}</p>
    </section>
  );
}
