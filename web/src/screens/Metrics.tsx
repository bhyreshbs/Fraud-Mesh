// /metrics — live tiles + benchmark from GET /v1/metrics/summary. The policy-simulator sliders arrive in D1-P6.
import { useMetrics } from "../lib/queries";
import { inr } from "../lib/format";
import { ApiError } from "../lib/api";

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
        No benchmark yet — <span className="font-mono">benchmark/report.json</span> is produced by Dev 2 in D2-P6.</div>}
      <p className="text-body-xs text-on-surface-variant">The policy simulator (threshold sliders) is wired in D1-P6.</p>
    </div>
  );
}
