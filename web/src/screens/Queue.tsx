// /queue — Stitch "Case Queue" bound to GET /v1/cases (PRD §11.1). Default filter MEDIUM and above, "show LOW" toggle.
// Live WebSocket updates arrive in D1-P3 (useStream); until then the list refreshes every 5 s.
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";
import { inr, istTime, shortCaseId, shortToken } from "../lib/format";
import { BAND_ORDER, type Band, type CasesPage } from "../types/contracts";
import { BAND_STYLE, BandPill, PaymentChip, RiskMeter, StageDots } from "../components/Risk";

const rank = (b: Band) => BAND_ORDER.indexOf(b);

export function Queue() {
  const navigate = useNavigate();
  const [showLow, setShowLow] = useState(false);
  const [bandFilter, setBandFilter] = useState<Band | null>(null);
  const [search, setSearch] = useState("");
  const q = useQuery({ queryKey: ["cases"], queryFn: () => api<CasesPage>("/v1/cases?limit=200"), refetchInterval: 5000 });

  const all = q.data?.items ?? [];
  const counts = useMemo(() => Object.fromEntries(BAND_ORDER.map((b) => [b, all.filter((c) => c.band === b).length])), [all]);
  const rows = all
    .filter((c) => showLow || bandFilter === "LOW" || c.band !== "LOW")
    .filter((c) => !bandFilter || c.band === bandFilter)
    .filter((c) => !search || (c.case_id + " " + (c.customer ?? "")).toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => rank(b.band) - rank(a.band) || b.p_attack - a.p_attack);
  const open = all.filter((c) => c.status === "OPEN" || c.status === "INVESTIGATING").length;

  return (
    <div className="flex flex-col w-full text-on-surface">
      <div className="flex items-center justify-between px-space-base py-space-sm bg-surface-container-lowest border-b border-outline-variant">
        <div className="flex items-center gap-space-sm">
          <h1 className="font-headline-lg text-headline-lg text-on-surface tracking-tight">Case queue</h1>
          <span className="px-space-xs py-space-2xs rounded-lg bg-surface-container text-on-surface-variant font-label-md text-label-md">{open} open</span>
          <div className="h-4 w-px bg-outline-variant mx-space-2xs" />
          <div className="flex items-center gap-1.5 px-space-xs py-space-2xs rounded-lg bg-surface-container-low">
            <span className={"w-2 h-2 rounded-full " + (q.isError ? "bg-red-500" : "bg-emerald-600 animate-pulse")} />
            <span className="font-label-md text-label-md text-on-surface">{q.isError ? "Offline" : "Live"}</span>
            <span className="font-body-xs text-body-xs text-on-surface-variant ml-1">
              {q.dataUpdatedAt ? `Updated ${istTime(new Date(q.dataUpdatedAt).toISOString(), true)} IST (polling 5 s)` : "Loading…"}
            </span>
          </div>
        </div>
      </div>

      <div className="flex flex-col bg-surface-container-lowest border-b border-outline-variant">
        <div className="px-space-base py-2 flex items-center justify-between gap-space-md">
          <div className="flex items-center gap-3">
            <div className="relative w-72">
              <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-on-surface-variant !text-[16px]">search</span>
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search case ID or customer token…"
                className="w-full h-8 pl-8 pr-3 text-body-sm bg-surface-container-low border border-outline-variant rounded-lg placeholder:text-on-surface-variant/70 focus:outline-none focus:border-primary-container focus:bg-surface-container-lowest" />
            </div>
            <div className="h-4 w-px bg-outline-variant" />
            <span className="font-label-caps text-label-caps uppercase text-on-surface-variant">Severity:</span>
            <button onClick={() => setBandFilter(null)}
              className={"px-2 py-0.5 rounded-lg font-label-md text-label-md " + (!bandFilter ? "bg-on-surface text-surface" : "hover:bg-surface-container")}>All</button>
            {[...BAND_ORDER].reverse().map((b) => (
              <button key={b} onClick={() => setBandFilter(bandFilter === b ? null : b)}
                className={"px-2 py-0.5 rounded-lg font-label-md text-label-md flex items-center gap-1 " + (bandFilter === b ? "bg-surface-container ring-1 ring-outline-variant" : "hover:bg-surface-container")}>
                <span className={`w-1.5 h-1.5 rounded-full ${BAND_STYLE[b].dot}`} />{BAND_STYLE[b].label}
                <span className="text-on-surface-variant text-[11px]">({counts[b] ?? 0})</span>
              </button>
            ))}
          </div>
          <label className="flex items-center gap-1.5 cursor-pointer select-none">
            <button role="switch" aria-checked={showLow} onClick={() => setShowLow(!showLow)}
              className={"w-7 h-4 rounded-full relative flex items-center px-0.5 transition-colors " + (showLow ? "bg-primary-container" : "bg-outline-variant")}>
              <span className={"w-3 h-3 bg-on-primary rounded-full transition-transform " + (showLow ? "translate-x-3" : "")} />
            </button>
            <span className="font-body-xs text-body-xs text-on-surface font-medium">Show LOW</span>
          </label>
        </div>
      </div>

      {q.isError && (
        <div className="m-space-base px-3 py-2.5 rounded-lg bg-risk-critical-fill border border-risk-critical-border text-[13px] text-risk-critical">
          Could not load cases: {(q.error as ApiError).message}
        </div>
      )}

      <div className="w-full bg-surface-container-lowest overflow-x-auto">
        <table className="w-full text-left border-collapse tnum">
          <thead>
            <tr className="h-9 bg-surface-container-low border-b border-outline-variant font-label-caps text-label-caps text-on-surface-variant uppercase">
              <th className="w-28 px-3">Case ID</th>
              <th className="w-28 px-3">Band</th>
              <th className="w-40 px-3">P(attack)</th>
              <th className="w-36 px-3">Customer</th>
              <th className="w-48 px-3">Stages S0–S6</th>
              <th className="w-28 px-3">Payment</th>
              <th className="w-36 px-3 text-right">Amount at risk</th>
              <th className="w-24 px-3 text-right">Updated (IST)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-outline-variant text-body-sm">
            {rows.map((c) => (
              <tr key={c.case_id} onClick={() => navigate(`/cases/${c.case_id}`)}
                className="h-10 hover:bg-surface-container-low cursor-pointer transition-colors fm-slide-in">
                <td className="px-3 font-code-sm text-code-sm font-medium text-primary-container">{shortCaseId(c.case_id)}</td>
                <td className="px-3"><BandPill band={c.band} /></td>
                <td className="px-3"><RiskMeter p={c.p_attack} band={c.band} /></td>
                <td className="px-3 font-code-sm text-code-sm text-on-surface-variant">{shortToken(c.customer)}</td>
                <td className="px-3"><StageDots reached={c.stages_reached} /></td>
                <td className="px-3"><PaymentChip state={c.payment_state} /></td>
                <td className="px-3 text-right font-code-sm text-code-sm font-medium">{c.amount_at_risk_paise ? inr(c.amount_at_risk_paise) : "—"}</td>
                <td className="px-3 text-right text-on-surface-variant text-body-xs">{istTime(c.updated_at)}</td>
              </tr>
            ))}
            {!q.isLoading && rows.length === 0 && (
              <tr><td colSpan={8} className="px-3 py-10 text-center text-on-surface-variant">
                No cases{showLow ? "" : " at MEDIUM or above — toggle “Show LOW” to see the rest"}.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
