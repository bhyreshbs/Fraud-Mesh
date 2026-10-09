// /metrics — live tiles + benchmark from GET /v1/metrics/summary, and the policy simulator: three band-threshold
// sliders that re-score the stored cases through POST /v1/simulate (PRD §11.1, F19).
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useMetrics } from "../lib/queries";
import type { SimulationResult } from "../types/contracts";
import { inr } from "../lib/format";
import { api, ApiError } from "../lib/api";

function Tile({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-3">
      <div className="font-label-caps text-label-caps uppercase text-on-surface-variant">{label}</div>
      <div className="text-[24px] font-semibold tnum mt-1">{value}</div>
      {sub && <div className="text-body-xs text-on-surface-variant">{sub}</div>}
    </div>
  );
}

export function Metrics() {
  const q = useMetrics();
  const live = q.data?.live;
  const b = q.data?.benchmark;
  return (
    <div className="p-space-base flex flex-col gap-3" data-testid="metrics">
      <h1 className="font-headline-lg text-headline-lg tracking-tight">Metrics</h1>
      {q.isError && <div className="text-risk-critical text-body-sm">{(q.error as ApiError).message}</div>}
      <div className="font-label-caps text-label-caps uppercase text-on-surface-variant">Live</div>
      <div className="grid grid-cols-4 gap-3">
        <Tile label="Open cases" value={String(live?.cases_open ?? "—")} />
        <Tile label="Critical open" value={String(live?.critical_open ?? "—")} />
        <Tile label="Money protected" value={live ? inr(live.money_protected_paise) : "—"} sub="held or blocked, not false positives" />
        <Tile label="Alert compression" value={live ? `${live.alert_compression.toFixed(1)} : 1` : "—"} sub="alerts (p ≥ 0.05) per open case" />
      </div>
      <div className="font-label-caps text-label-caps uppercase text-on-surface-variant mt-2">Benchmark (14 days, 1 seed)</div>
      {b ? (
        <div className="grid grid-cols-4 gap-3">
          {Object.entries(b.families).map(([fam, f]) => (
            <Tile key={fam} label={fam} value={`${f.caught_fused}/${f.instances} vs ${f.caught_siloed}/${f.instances}`} sub="caught: fused vs siloed" />
          ))}
          <Tile label="False-positive rate" value={`${(b.false_positive_rate * 100).toFixed(2)}%`} />
          <Tile label="Alert compression" value={`${b.alert_compression.toFixed(1)} : 1`} />
          <Tile label="Txn model PR-AUC" value={b.txn_pr_auc.toFixed(3)} sub={`ROC-AUC ${b.txn_roc_auc.toFixed(3)} · ECE ${b.txn_ece.toFixed(3)}`} />
        </div>
      ) : <div className="text-body-sm text-on-surface-variant bg-surface-container-lowest border border-outline-variant rounded-lg p-3">
        No benchmark yet — run <span className="font-mono">python -m benchmark.run</span> to produce <span className="font-mono">benchmark/report.json</span>.</div>}
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
    <section className="bg-surface-container-lowest border border-outline-variant rounded-lg mt-2" data-testid="simulator">
      <div className="h-10 px-3 flex items-center justify-between border-b border-outline-variant">
        <span className="font-headline-sm text-headline-sm">Policy simulator</span>
        <button onClick={() => setT(DEFAULTS)} className="text-body-xs text-primary-container hover:underline">reset to 0.20 / 0.50 / 0.80</button>
      </div>
      <div className="p-3 grid grid-cols-3 gap-6">
        {(["medium", "high", "critical"] as const).map((k) => (
          <label key={k} className="text-body-sm">
            <span className="flex justify-between"><span className="capitalize font-medium">{k} band from</span>
              <span className="font-mono tnum" data-testid={`thr-${k}`}>{t[k].toFixed(2)}</span></span>
            <input type="range" min={0.01} max={0.99} step={0.01} value={t[k]} onChange={(e) => set(k, Number(e.target.value))}
              data-testid={`slider-${k}`} className="w-full accent-[#2457C5]" />
          </label>
        ))}
      </div>
      <div className="px-3 pb-3 grid grid-cols-5 gap-3" data-testid="sim-tiles">
        <Tile label="Attacks caught" value={r ? `${r.attacks_caught} / ${r.attacks_total}` : "—"} sub={"before the attack's last event" + delta(r?.attacks_caught, b?.attacks_caught)} />
        <Tile label="Benign customers flagged" value={r ? `${r.benign_customers_flagged} / ${r.benign_customers_total}` : "—"} sub={"reached HIGH" + delta(r?.benign_customers_flagged, b?.benign_customers_flagged)} />
        <Tile label="Legit payments stopped" value={r ? `${r.legit_payments_stopped} / ${r.legit_payments_total}` : "—"} sub={"held or blocked" + delta(r?.legit_payments_stopped, b?.legit_payments_stopped)} />
        <Tile label="Money protected" value={r ? inr(r.money_protected_paise) : "—"} />
        <Tile label="Median lead time" value={r?.median_lead_time_s != null ? `${Math.floor(r.median_lead_time_s / 60)} min ${r.median_lead_time_s % 60}s` : "—"} sub="caught attacks" />
      </div>
      <p className="px-3 pb-3 text-body-xs text-on-surface-variant">{q.isFetching ? "re-scoring…" : "Scores come from replaying every stored case with these thresholds (labels from the generator / scenario runs)."}</p>
    </section>
  );
}
