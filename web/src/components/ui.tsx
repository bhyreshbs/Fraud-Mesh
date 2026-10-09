// Shared building blocks of the "Warm Neumorphic Glass" design: page header, KPI tile, panel, segmented tabs.
import type { ReactNode } from "react";

export function PageHeader({ eyebrow, meta, title, subtitle, actions }: {
  eyebrow?: string; meta?: ReactNode; title: string; subtitle?: ReactNode; actions?: ReactNode;
}) {
  return (
    <div className="flex items-end justify-between gap-6 flex-wrap">
      <div className="max-w-3xl">
        {(eyebrow || meta) && (
          <div className="flex items-center gap-3 mb-2">
            {eyebrow && <span className="fm-eyebrow">{eyebrow}</span>}
            {meta && <span className="font-mono text-[12px] text-on-surface-variant flex items-center gap-1.5">{meta}</span>}
          </div>
        )}
        <h1 className="text-[34px] leading-[42px] font-semibold tracking-[-0.025em] text-on-surface">{title}</h1>
        {subtitle && <p className="mt-1.5 text-body-md text-on-surface-variant">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-3 flex-wrap">{actions}</div>}
    </div>
  );
}

const TONE: Record<string, { value: string; icon: string }> = {
  critical: { value: "text-risk-critical", icon: "bg-risk-critical-fill text-risk-critical" },
  high: { value: "text-on-surface", icon: "bg-primary-fixed text-primary" },
  medium: { value: "text-on-surface", icon: "bg-risk-medium-fill text-risk-medium" },
  low: { value: "text-on-surface", icon: "bg-risk-low-fill text-risk-low" },
  brand: { value: "text-on-surface", icon: "bg-primary-fixed text-primary" },
};

export function Kpi({ label, value, unit, sub, icon, tone = "brand", testid, foot }: {
  label: string; value: ReactNode; unit?: string; sub?: ReactNode; icon?: string; tone?: keyof typeof TONE; testid?: string; foot?: ReactNode;
}) {
  const t = TONE[tone];
  return (
    <div className="fm-card relative overflow-hidden p-5 flex flex-col gap-1 min-h-[150px]" data-testid={testid}>
      <div className="flex items-start justify-between gap-2">
        <span className="font-mono text-[11px] tracking-[0.08em] uppercase text-on-surface-variant">{label}</span>
        {icon && <span className={`w-10 h-10 rounded-xl flex items-center justify-center shadow-porcelain-sm ${t.icon}`}>
          <span className="material-symbols-outlined !text-[20px]">{icon}</span></span>}
      </div>
      <div className={`text-[34px] leading-[40px] font-semibold tracking-[-0.02em] tnum ${t.value}`}>
        {value}{unit && <span className="text-[16px] font-medium text-on-surface-variant ml-1">{unit}</span>}</div>
      {sub && <div className="text-body-sm text-on-surface-variant">{sub}</div>}
      {foot && <div className="mt-auto pt-2 text-body-xs text-on-surface-variant">{foot}</div>}
    </div>
  );
}

export function Panel({ title, subtitle, right, children, testid, className = "" }: {
  title?: ReactNode; subtitle?: ReactNode; right?: ReactNode; children: ReactNode; testid?: string; className?: string;
}) {
  return (
    <section className={`fm-card ${className}`} data-testid={testid}>
      {(title || right) && (
        <div className="px-6 pt-5 pb-3 flex items-start justify-between gap-3">
          <div>
            {title && <div className="text-[19px] font-semibold tracking-[-0.015em] text-on-surface">{title}</div>}
            {subtitle && <div className="text-body-sm text-on-surface-variant mt-0.5">{subtitle}</div>}
          </div>
          {right}
        </div>
      )}
      {children}
    </section>
  );
}

export function SegTabs<T extends string>({ value, options, onChange, testid }: {
  value: T; options: { value: T; label: ReactNode }[]; onChange: (v: T) => void; testid?: string;
}) {
  return (
    <div className="fm-sunken inline-flex p-1 gap-1" data-testid={testid}>
      {options.map((o) => (
        <button key={o.value} onClick={() => onChange(o.value)} aria-selected={value === o.value} role="tab"
          className={"px-4 py-1.5 rounded-[0.7rem] text-body-sm transition-all " +
            (value === o.value ? "bg-porcelain shadow-porcelain-sm text-primary font-semibold" : "text-on-surface-variant hover:text-on-surface")}>
          {o.label}</button>
      ))}
    </div>
  );
}

export function LiveDot({ on = true }: { on?: boolean }) {
  return <span className={"inline-block w-2 h-2 rounded-full " + (on ? "bg-primary-container fm-live-dot" : "bg-outline")} />;
}
