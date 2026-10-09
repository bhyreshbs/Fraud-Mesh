// /detectors — detector reliability table bound to GET /v1/detectors (PRD §11.1); refreshes after feedback.
import { DETECTOR } from "../lib/labels";
import { useDetectors } from "../lib/queries";
import { ApiError } from "../lib/api";

export function Detectors() {
  const q = useDetectors();
  return (
    <div className="p-space-base flex flex-col gap-3">
      <div>
        <h1 className="font-headline-lg text-headline-lg tracking-tight">Detector reliability</h1>
        <p className="text-body-sm text-on-surface-variant">Beta(α, β) per detector; reliability = α / (α + β). Analyst feedback moves α (confirmed fraud) or β (false positive).</p>
      </div>
      {q.isError && <div className="text-risk-critical text-body-sm">{(q.error as ApiError).message}</div>}
      <table className="w-full bg-surface-container-lowest border border-outline-variant rounded-lg text-body-sm tnum" data-testid="detectors-table">
        <thead><tr className="h-9 bg-surface-container-low border-b border-outline-variant font-label-caps text-label-caps uppercase text-on-surface-variant text-left">
          <th className="px-3">Detector</th><th className="px-3">Family</th><th className="px-3 text-right">α</th><th className="px-3 text-right">β</th>
          <th className="px-3 w-72">Reliability</th></tr></thead>
        <tbody>
          {(q.data ?? []).map((d) => (
            <tr key={d.detector} className="h-10 border-b border-outline-variant last:border-0">
              <td className="px-3"><span className="material-symbols-outlined !text-[16px] align-middle mr-2" style={{ color: DETECTOR[d.detector].color }}>{DETECTOR[d.detector].icon}</span>
                {DETECTOR[d.detector].label} <span className="font-code-xs text-code-xs text-on-surface-variant">{d.detector}</span></td>
              <td className="px-3 capitalize">{d.family}</td>
              <td className="px-3 text-right">{d.alpha.toFixed(1)}</td><td className="px-3 text-right">{d.beta.toFixed(1)}</td>
              <td className="px-3"><div className="flex items-center gap-2">
                <div className="flex-1 h-1.5 bg-neutral-200 rounded-full overflow-hidden"><div className="h-full bg-primary-container" style={{ width: `${d.reliability * 100}%` }} /></div>
                <span className="w-12 text-right font-medium">{d.reliability.toFixed(3)}</span></div></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
