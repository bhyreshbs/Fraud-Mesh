// /cases/:id header (Stitch "Case Investigation" header): band, P (large), current stage, latest_actions banner.
import { ACTION_SEVERITY, type Case, type CaseSummary } from "../types/contracts";
import { ACTION_LABEL, STAGE_LABEL } from "../lib/labels";
import { inr, istDateTime, shortCaseId, shortToken } from "../lib/format";
import { BAND_STYLE, BandPill, PaymentChip } from "./Risk";

export function ActionsBanner({ actions }: { actions: Case["latest_actions"] }) {
  if (!actions.length) return null;
  const sev = Math.max(...actions.map((a) => ACTION_SEVERITY[a]));
  const style = sev >= 3 ? "bg-risk-critical-fill border-risk-critical-border text-risk-critical"
    : sev === 2 ? "bg-risk-high-fill border-risk-high-border text-risk-high"
      : sev === 1 ? "bg-risk-medium-fill border-risk-medium-border text-risk-medium"
        : "bg-surface-container-low border-outline-variant text-on-surface-variant";
  const icon = sev >= 3 ? "block" : sev === 2 ? "pause_circle" : sev === 1 ? "verified_user" : "check_circle";
  return (
    <div data-testid="actions-banner" className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-[13px] font-semibold ${style}`}>
      <span className="material-symbols-outlined">{icon}</span>
      {actions.map((a) => ACTION_LABEL[a]).join(" · ")}
    </div>
  );
}

export function CaseHeader({ c, s, onManual }: { c: Case; s: CaseSummary; onManual?: () => void }) {
  const band = BAND_STYLE[c.band];
  return (
    <div className="bg-surface-container-lowest border-b border-outline-variant px-space-base pt-space-sm pb-space-base">
      <div className="flex items-center gap-2 text-body-sm text-on-surface-variant mb-2">
        <a href="/queue" className="hover:underline">Cases</a><span className="text-outline-variant">/</span>
        <span className="font-code-sm text-code-sm px-1.5 py-0.5 rounded-lg bg-surface-container text-on-surface">{shortCaseId(c.case_id)}</span>
        <span className="font-code-xs text-code-xs">{c.case_id}</span>
      </div>
      <div className="flex items-start justify-between gap-6">
        <div className="flex flex-col gap-1.5 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="font-headline-lg text-headline-lg tracking-tight">
              {s.current_stage ? `${STAGE_LABEL[s.current_stage]} attack` : "Case"} on customer{" "}
              <span className="font-mono text-[18px]">{shortToken(c.customer ?? c.anchor_entity)}</span>
            </h1>
            <BandPill band={c.band} />
            <span className="inline-flex items-center gap-1 px-2 h-[22px] rounded-lg text-[11px] font-medium bg-surface-container text-primary-container">
              <span className="w-1.5 h-1.5 rounded-full bg-primary-container" />{c.status.replace("_", " ").toLowerCase()}
            </span>
          </div>
          <div className="flex items-center gap-2 text-body-sm text-on-surface-variant flex-wrap">
            <span>Anchor <span className="font-code-sm text-code-sm text-on-surface">{c.anchor_entity}</span></span>
            <span>·</span><span>Opened {istDateTime(c.opened_at)}</span>
            <span>·</span><span>Updated {istDateTime(c.updated_at)}</span>
            <span>·</span><span>{c.entities.length} entities</span>
            {c.pattern_hits.map((p) => <span key={p} className="font-code-xs text-code-xs px-1.5 py-0.5 rounded-lg bg-surface-container text-on-surface">{p}</span>)}
            {c.floors.map((f) => <span key={f} className="font-code-xs text-code-xs px-1.5 py-0.5 rounded-lg bg-risk-critical-fill text-risk-critical">{f}</span>)}
          </div>
          <div className="mt-1 flex items-center gap-2">
            <ActionsBanner actions={c.latest_actions} />
            {onManual && (
              <button onClick={onManual} className="h-8 px-2.5 rounded-lg border border-outline-variant bg-surface-container-lowest hover:bg-surface-container-low text-on-surface font-label-md text-label-md flex items-center gap-1">
                <span className="material-symbols-outlined !text-[16px]">gavel</span> Manual action
              </button>
            )}
          </div>
        </div>
        <div className="flex items-stretch gap-6 shrink-0">
          <div className="text-right">
            <div className="font-label-caps text-label-caps uppercase text-on-surface-variant">P(attack)</div>
            <div data-testid="p-attack" className={`text-[40px] leading-[44px] font-semibold tnum ${band.text}`}>{(c.p_attack * 100).toFixed(1)}%</div>
            <div className="font-code-xs text-code-xs text-on-surface-variant">log-odds {c.log_odds.toFixed(3)}</div>
          </div>
          <div className="w-px bg-outline-variant" />
          <div className="text-right">
            <div className="font-label-caps text-label-caps uppercase text-on-surface-variant">Amount at risk</div>
            <div className="text-[26px] leading-[44px] font-semibold tnum text-on-surface">{c.amount_at_risk_paise ? inr(c.amount_at_risk_paise) : "—"}</div>
            <PaymentChip state={c.payment_state} />
          </div>
        </div>
      </div>
    </div>
  );
}
