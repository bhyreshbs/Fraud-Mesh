// Severity badge, stage dots and payment-state chip in the DESIGN.md risk palette.
import { STAGE_ORDER, type Band, type PaymentState, type Stage } from "../types/contracts";

export const BAND_STYLE: Record<Band, { text: string; fill: string; dot: string; bar: string; label: string }> = {
  CRITICAL: { text: "text-risk-critical", fill: "bg-risk-critical-fill", dot: "bg-risk-critical", bar: "#D03B29", label: "Critical" },
  HIGH: { text: "text-risk-high", fill: "bg-risk-high-fill", dot: "bg-risk-high", bar: "#D96B35", label: "High" },
  MEDIUM: { text: "text-risk-medium", fill: "bg-risk-medium-fill", dot: "bg-risk-medium", bar: "#DE9A2B", label: "Medium" },
  LOW: { text: "text-risk-low", fill: "bg-risk-low-fill", dot: "bg-risk-low", bar: "#3A8A5B", label: "Low" },
};

export function BandPill({ band }: { band: Band }) {
  const s = BAND_STYLE[band];
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 h-[22px] rounded-lg text-[11px] font-medium ${s.fill} ${s.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

export function RiskMeter({ p, band }: { p: number; band: Band }) {
  const s = BAND_STYLE[band];
  return (
    <div className="flex items-center gap-2">
      <span className={`font-tabular-metric text-tabular-metric font-semibold tnum w-12 ${s.text}`}>{(p * 100).toFixed(1)}%</span>
      <div className="w-16 h-1.5 bg-surface-container rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${Math.max(2, p * 100)}%`, background: s.bar }} />
      </div>
    </div>
  );
}

export const STAGE_SHORT: Record<Stage, string> = {
  S0_RECON: "Recon", S1_INITIAL_ACCESS: "Initial access", S2_CONTROL_TAKEOVER: "Control takeover",
  S3_IDENTITY_MANIPULATION: "Identity manipulation", S4_ESCALATION: "Escalation", S5_POSITIONING: "Positioning",
  S6_MONETIZATION: "Monetization",
};

export function StageDots({ reached }: { reached: Stage[] }) {
  return (
    <div className="flex items-center gap-1" aria-label={`stages reached: ${reached.join(", ") || "none"}`}>
      {STAGE_ORDER.map((s, i) => {
        const on = reached.includes(s);
        return (
          <span key={s} title={`S${i} ${STAGE_SHORT[s]}`}
            className={"w-4 h-4 rounded-lg text-[9px] font-semibold flex items-center justify-center font-mono " +
              (on ? "bg-primary-container text-on-primary" : "bg-surface-container text-on-surface-variant/60")}>
            {i}
          </span>
        );
      })}
    </div>
  );
}

export function PaymentChip({ state }: { state: PaymentState }) {
  const style = state === "blocked" ? "bg-risk-critical-fill text-risk-critical border-risk-critical-border"
    : state === "held" ? "bg-risk-high-fill text-risk-high border-risk-high-border"
      : "bg-surface-container-lowest text-on-surface-variant border-outline-variant";
  return <span className={`inline-flex items-center px-2 h-[22px] rounded-lg text-[11px] font-medium border capitalize ${style}`}>{state}</span>;
}
