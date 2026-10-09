// Timeline tab (PRD §11.1): evidence cards (detector icon, reasons, ATT&CK badge, p, contribution) with decision and
// challenge cards interleaved by time. Each evidence card has id="ev-<evidence_id>" so citation chips can scroll to it.
import type { ChallengeInfo, Decision, Evidence, Timeline } from "../types/contracts";
import { ACTION_LABEL, DETECTOR, STAGE_LABEL, reasonText, signed } from "../lib/labels";
import { inr, istTime, shortToken } from "../lib/format";
import { BandPill } from "./Risk";

type Item = { t: number; order: number; kind: "evidence"; e: Evidence } | { t: number; order: number; kind: "decision"; d: Decision }
  | { t: number; order: number; kind: "challenge"; c: ChallengeInfo };

const CH_STYLE: Record<string, string> = {
  pending: "bg-surface-container text-primary-container", passed: "bg-risk-low-fill text-risk-low",
  failed: "bg-risk-critical-fill text-risk-critical", timeout: "bg-risk-medium-fill text-risk-medium",
  denied_by_customer: "bg-risk-critical-fill text-risk-critical",
};

function EvidenceCard({ e, highlight }: { e: Evidence; highlight?: boolean }) {
  const det = DETECTOR[e.detector];
  const strong = e.contribution > 1;
  return (
    <div id={`ev-${e.evidence_id}`} data-testid="evidence-card"
      className={"bg-surface-container-lowest border rounded-lg transition-shadow " + (highlight ? "ring-2 ring-brand border-brand" : strong ? "border-risk-critical-border" : "border-outline-variant")}>
      <div className="px-3 py-2 flex items-start justify-between gap-3 border-b border-outline-variant">
        <div className="flex items-center gap-2 min-w-0">
          <span className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0" style={{ background: det.color + "18", color: det.color }}>
            <span className="material-symbols-outlined">{det.icon}</span>
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-headline-sm text-headline-sm">{det.label}</span>
              <span className="font-label-caps text-label-caps uppercase text-on-surface-variant">{STAGE_LABEL[e.stage]}</span>
              {e.attack_technique && (
                <span title="MITRE ATT&CK technique" className="font-code-xs text-code-xs px-1.5 py-0.5 rounded-lg bg-inverse-surface text-inverse-on-surface">{e.attack_technique}</span>
              )}
              {e.degraded && <span className="text-[11px] px-1.5 rounded-lg bg-risk-medium-fill text-risk-medium">degraded model</span>}
            </div>
            <div className="font-code-xs text-code-xs text-on-surface-variant">{e.evidence_id} · event {e.event_id}</div>
          </div>
        </div>
        <div className="flex items-center gap-4 shrink-0 text-right">
          <div><div className="font-label-caps text-label-caps uppercase text-on-surface-variant">p</div>
            <div className="font-tabular-metric text-tabular-metric tnum">{e.p.toFixed(3)}</div></div>
          <div><div className="font-label-caps text-label-caps uppercase text-on-surface-variant">Reliability</div>
            <div className="font-tabular-metric text-tabular-metric tnum">{e.reliability.toFixed(2)}</div></div>
          <div><div className="font-label-caps text-label-caps uppercase text-on-surface-variant">Contribution</div>
            <div data-testid="contribution" className={"font-tabular-metric text-tabular-metric tnum font-semibold " + (e.contribution > 0 ? "text-risk-critical" : "text-risk-low")}>
              {signed(e.contribution)}</div></div>
        </div>
      </div>
      <div className="px-3 py-2 flex flex-col gap-1.5">
        <ul className="flex flex-col gap-0.5">
          {e.reasons.map((r, i) => (
            <li key={i} className="text-body-sm"><span className="font-medium">{reasonText(r.code)}</span>
              {r.detail && <span className="text-on-surface-variant"> — {r.detail}</span>}
              <span className="ml-2 font-code-xs text-code-xs text-on-surface-variant">{r.code}</span></li>
          ))}
        </ul>
        {e.amount_paise != null && <div className="text-body-sm">Amount <span className="font-semibold tnum">{inr(e.amount_paise)}</span></div>}
        {e.shap && e.shap.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {e.shap.map((s) => (
              <span key={s.feature} className="font-code-xs text-code-xs px-1.5 py-0.5 rounded-lg border border-outline-variant">
                {s.feature}={Number.isInteger(s.value) ? s.value : s.value.toFixed(2)} <span className={s.shap >= 0 ? "text-risk-critical" : "text-risk-low"}>{signed(s.shap)}</span>
              </span>
            ))}
          </div>
        )}
        <div className="flex flex-wrap gap-1">
          {e.entities.map((t) => <span key={t} title={t} className="font-code-xs text-[10px] px-1.5 py-0.5 rounded-lg bg-surface-container text-on-surface-variant">{shortToken(t)}</span>)}
        </div>
      </div>
    </div>
  );
}

function DecisionCard({ d }: { d: Decision }) {
  return (
    <div className="bg-surface-container-low border border-dashed border-outline-variant rounded-lg px-3 py-2 flex items-center gap-3 flex-wrap" data-testid="decision-card">
      <span className="material-symbols-outlined text-on-surface-variant">{d.actor === "engine" ? "policy" : "gavel"}</span>
      <span className="font-label-md text-label-md">Decision</span>
      <BandPill band={d.band} />
      <span className="font-code-xs text-code-xs text-on-surface-variant">rule {d.policy_rule} · P {(d.p_attack * 100).toFixed(1)}%</span>
      <span className="text-body-sm font-medium">{d.actions.map((a) => ACTION_LABEL[a]).join(" · ")}</span>
      {d.actor !== "engine" && <span className="text-body-xs text-on-surface-variant">by {d.actor}{d.override_reason ? ` — “${d.override_reason}”` : ""}</span>}
      <span className="ml-auto font-code-xs text-code-xs text-on-surface-variant">{d.decision_id}</span>
    </div>
  );
}

function ChallengeCard({ c }: { c: ChallengeInfo }) {
  return (
    <div className="bg-surface-container-lowest border border-outline-variant rounded-lg px-3 py-2 flex items-center gap-3" data-testid="challenge-card">
      <span className="material-symbols-outlined text-on-surface-variant">{c.method === "device_push" ? "smartphone" : "sms"}</span>
      <span className="font-label-md text-label-md">Step-up challenge</span>
      <span className="text-body-sm">{c.method === "device_push" ? "Push to registered device" : c.method === "sms_otp" ? "SMS one-time code" : "Authenticator code"}</span>
      <span className={`text-[11px] font-semibold px-2 h-[22px] inline-flex items-center rounded-lg ${CH_STYLE[c.status]}`}>{c.status.replace(/_/g, " ")}</span>
      <span className="ml-auto font-code-xs text-code-xs text-on-surface-variant">{c.challenge_id}</span>
    </div>
  );
}

export function TimelineTab({ tl, highlight }: { tl: Timeline | undefined; highlight?: string | null }) {
  if (!tl) return <div className="p-6 text-on-surface-variant">Loading timeline…</div>;
  const items: Item[] = [
    ...tl.evidence.map((e) => ({ t: new Date(e.ts).getTime(), order: 0, kind: "evidence" as const, e })),
    ...tl.decisions.map((d) => ({ t: new Date(d.created_at).getTime(), order: 1, kind: "decision" as const, d })),
    ...tl.challenges.map((c) => ({ t: new Date(c.created_at).getTime(), order: 2, kind: "challenge" as const, c })),
  ].sort((a, b) => a.t - b.t || a.order - b.order);
  if (!items.length) return <div className="p-6 text-on-surface-variant">No evidence in this case yet.</div>;
  return (
    <ol className="flex flex-col gap-2" data-testid="timeline">
      {items.map((it, i) => (
        <li key={i} className="grid grid-cols-[88px_16px_1fr] gap-2">
          <div className="text-right pt-2">
            <div className="font-code-sm text-code-sm tnum">{istTime(new Date(it.t).toISOString(), true)}</div>
            <div className="font-label-caps text-[10px] uppercase text-on-surface-variant">IST</div>
          </div>
          <div className="flex flex-col items-center">
            <span className={"mt-3 w-2.5 h-2.5 rounded-full " + (it.kind === "evidence" ? "bg-primary-container" : "bg-outline-variant")} />
            <span className="flex-1 w-px bg-outline-variant" />
          </div>
          <div className="pb-1">
            {it.kind === "evidence" ? <EvidenceCard e={it.e} highlight={highlight === it.e.evidence_id} />
              : it.kind === "decision" ? <DecisionCard d={it.d} /> : <ChallengeCard c={it.c} />}
          </div>
        </li>
      ))}
    </ol>
  );
}
