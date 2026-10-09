// /overview — Stitch "Live Operations Dashboard": KPIs, case velocity, priority cases, risk distribution, detector health.
// Sources: GET /v1/cases, /v1/metrics/summary, /v1/detectors, /v1/twin/overview (live over the WebSocket stream).
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Band } from "../types/contracts";
import { hasRole, useAuth } from "../lib/auth";
import { inr, pct, shortCaseId, shortToken } from "../lib/format";
import { attackVector, DETECTOR } from "../lib/labels";
import { useCases, useDetectors, useMetrics, useTwinOverview } from "../lib/queries";
import { BAND_STYLE } from "../components/Risk";
import { Kpi, PageHeader, Panel, SegTabs } from "../components/ui";

const BAND_COLOR: Record<Band, string> = { CRITICAL: "#D03B29", HIGH: "#D96B35", MEDIUM: "#DE9A2B", LOW: "#B8A99A" };
type Win = "24h" | "7d" | "14d";
const WIN_H: Record<Win, number> = { "24h": 24, "7d": 168, "14d": 336 };

export function Overview() {
  const { session } = useAuth();
  const cases = useCases();
  const metrics = useMetrics();
  const detectors = useDetectors();
  const twin = useTwinOverview();
  const [win, setWin] = useState<Win>("7d");
  const items = cases.data?.items ?? [];
  const open = items.filter((c) => c.status === "OPEN" || c.status === "INVESTIGATING");
  const escalated = open.filter((c) => c.band === "HIGH" || c.band === "CRITICAL");
  const critical = escalated.filter((c) => c.band === "CRITICAL").length;
  const latest = items.reduce((m, c) => Math.max(m, new Date(c.updated_at).getTime()), 0);
  const recent = items.filter((c) => latest - new Date(c.updated_at).getTime() < 2 * 3600_000).length;
  const bench = metrics.data?.benchmark;

  const series = useMemo(() => {
    if (!latest) return [];
    const hours = WIN_H[win], step = hours <= 24 ? 1 : hours <= 168 ? 6 : 12;
    const buckets = Array.from({ length: Math.ceil(hours / step) }, (_, i) => ({
      t: latest - (hours - i * step) * 3600_000, all: 0, escalated: 0 }));
    for (const c of items) {
      const k = Math.floor((new Date(c.updated_at).getTime() - (latest - hours * 3600_000)) / (step * 3600_000));
      if (k >= 0 && k < buckets.length) {
        buckets[k].all += 1;
        if (c.band === "HIGH" || c.band === "CRITICAL") buckets[k].escalated += 1;
      }
    }
    return buckets.map((b) => ({ ...b, label: new Date(b.t).toLocaleString("en-IN", { timeZone: "Asia/Kolkata", day: "2-digit", month: "short", hour: "2-digit", hour12: false }) }));
  }, [items, latest, win]);

  const byBand = (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Band[]).map((b) => ({ band: b, n: items.filter((c) => c.band === b).length }));
  const priority = [...escalated].sort((a, b) => (a.band === b.band ? 0 : a.band === "CRITICAL" ? -1 : 1) ||
    b.updated_at.localeCompare(a.updated_at) || b.p_attack - a.p_attack).slice(0, 3);

  return (
    <div className="px-8 py-7 flex flex-col gap-7" data-testid="overview">
      <div className="fm-card px-7 py-6">
        <PageHeader eyebrow="Live operations" meta={<><span className="w-1.5 h-1.5 rounded-full bg-primary-container" />{items.length} cases in the mesh</>}
          title="Correlation Defense Grid"
          subtitle="Fraud, identity, KYC and cyber signals fused into one explainable case per attack, acted on before money moves."
          actions={<>
            <Link to="/queue" className="fm-btn"><span className="material-symbols-outlined !text-[18px]">inbox</span>Case Queue</Link>
            {hasRole(session, "admin") && <Link to="/demo" className="fm-btn-primary"><span className="material-symbols-outlined !text-[18px]">play_arrow</span>Run a scenario</Link>}
          </>} />
      </div>

      <div className="grid grid-cols-4 gap-6">
        <Kpi label="Active cases" value={open.length} icon="shield_person" testid="kpi-active"
          sub={<span className="text-primary-container">● {recent} updated in the last 2 h</span>} foot={`${open.length - escalated.length} below HIGH, logged only`} />
        <Kpi label="Escalated risk" value={escalated.length} icon="warning" tone="critical" testid="kpi-escalated"
          sub={<span className="text-risk-critical">● payments held or blocked</span>} foot={`${critical} critical · ${escalated.length - critical} high`} />
        <Kpi label="Fraud prevented" value={inr(twin.data?.money_protected_paise ?? metrics.data?.live.money_protected_paise ?? 0)} icon="savings" testid="kpi-prevented"
          sub="money kept in held / blocked cases" foot={`${twin.data?.payments_blocked ?? 0} blocked · ${twin.data?.payments_held ?? 0} held`} />
        <Kpi label="Txn model precision" value={bench ? pct(bench.txn_pr_auc, 2) : "—"} icon="verified" tone="low" testid="kpi-precision"
          sub="PR-AUC on held-out bank events" foot={bench ? `alert compression ${bench.alert_compression.toFixed(1)} : 1 · ${bench.benign_flagged_high} genuine flagged HIGH` : "run benchmark.run"} />
      </div>

      <div className="grid grid-cols-[1.6fr_1fr] gap-6">
        <Panel title="Case velocity" subtitle="Cases updated per period, all vs escalated (HIGH + CRITICAL)"
          right={<SegTabs value={win} onChange={setWin} options={[{ value: "24h", label: "24h" }, { value: "7d", label: "7d" }, { value: "14d", label: "14d" }]} />}>
          <div className="px-4 pb-4">
            <ResponsiveContainer width="100%" height={440}>
              <AreaChart data={series} margin={{ top: 10, right: 16, bottom: 0, left: -8 }}>
                <defs>
                  <linearGradient id="fmEsc" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#D96B35" stopOpacity={0.35} /><stop offset="100%" stopColor="#D96B35" stopOpacity={0} /></linearGradient>
                  <linearGradient id="fmAll" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#B8A99A" stopOpacity={0.3} /><stop offset="100%" stopColor="#B8A99A" stopOpacity={0} /></linearGradient>
                </defs>
                <CartesianGrid stroke="#E6D9CA" strokeDasharray="3 4" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#756D64" }} interval="preserveStartEnd" minTickGap={40} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#756D64" }} width={36} />
                <Tooltip contentStyle={{ fontSize: 12, borderRadius: 12, border: "1px solid #E6D9CA", background: "#FFFEFC" }} />
                <Area type="monotone" dataKey="all" name="all cases" stroke="#8A7268" strokeWidth={1.5} fill="url(#fmAll)" isAnimationActive={false} />
                <Area type="monotone" dataKey="escalated" name="escalated" stroke="#D96B35" strokeWidth={2.5} fill="url(#fmEsc)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Priority cases" subtitle="Highest-risk correlated attacks right now"
          right={<span className="fm-pill">{critical} critical</span>} testid="priority-cases">
          <div className="px-5 pb-5 flex flex-col gap-3">
            {priority.length === 0 && <div className="fm-sunken p-4 text-body-sm text-on-surface-variant">No escalated cases. Run a scenario from the Demo Simulator.</div>}
            {priority.map((c) => {
              const v = attackVector(c.stages_reached);
              return (
                <div key={c.case_id} className="fm-tint p-4">
                  <div className="flex items-center gap-2">
                    <span className={"font-mono text-[11px] font-semibold px-2 py-0.5 rounded-md text-white " + (c.band === "CRITICAL" ? "bg-risk-critical" : "bg-primary-container")}>{c.band}</span>
                    <span className="font-semibold text-on-surface">{v.label}</span>
                  </div>
                  <div className="text-body-sm text-on-surface-variant mt-1">
                    <span className="font-mono">{shortCaseId(c.case_id)}</span> · {shortToken(c.customer)} · {c.stages_reached.length} stages · {pct(c.p_attack)}
                    {c.amount_at_risk_paise > 0 && <> · <span className="font-mono text-on-surface">{inr(c.amount_at_risk_paise)}</span> at risk</>}
                  </div>
                  <div className="flex gap-2 mt-3">
                    <Link to={`/investigations/${c.case_id}`} className="fm-btn-primary !h-9 !px-3.5">Investigate</Link>
                    <Link to={`/twin?case=${c.case_id}`} className="fm-btn !h-9 !px-3.5">Replay in twin</Link>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-[1fr_1.4fr] gap-6">
        <Panel title="Case risk distribution" subtitle={`${items.length} cases across ${(twin.data?.entities.cust ?? 0).toLocaleString("en-IN")} monitored customers`}>
          <div className="px-6 pb-6 flex items-center gap-6">
            <div className="relative w-48 h-48">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={byBand} dataKey="n" nameKey="band" innerRadius={62} outerRadius={88} paddingAngle={2} stroke="none" isAnimationActive={false}>
                    {byBand.map((b) => <Cell key={b.band} fill={BAND_COLOR[b.band]} />)}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-[30px] font-semibold tnum">{items.length}</span>
                <span className="font-mono text-[11px] tracking-[0.1em] text-on-surface-variant">CASES</span>
              </div>
            </div>
            <ul className="flex-1 flex flex-col gap-3">
              {byBand.map((b) => (
                <li key={b.band} className="flex items-center gap-3 text-body-sm">
                  <span className="w-3 h-3 rounded-full" style={{ background: BAND_COLOR[b.band] }} />
                  <span className="flex-1">{BAND_STYLE[b.band].label}</span>
                  <span className="font-mono tnum">{items.length ? Math.round((100 * b.n) / items.length) : 0}%</span>
                  <span className="font-mono tnum text-on-surface-variant w-12 text-right">({b.n})</span>
                </li>
              ))}
            </ul>
          </div>
        </Panel>

        <Panel title="Detector engine health" subtitle="Seven detectors fused by reliability (α/β updated by analyst feedback)"
          right={<span className="fm-pill">{(detectors.data ?? []).length} / 7 active</span>} testid="detector-health">
          <div className="px-5 pb-5 grid grid-cols-2 gap-3">
            {(detectors.data ?? []).map((d) => (
              <Link to="/detectors" key={d.detector} className="fm-tint px-4 py-3 hover:shadow-porcelain-sm transition-shadow">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined !text-[18px]" style={{ color: DETECTOR[d.detector].color }}>{DETECTOR[d.detector].icon}</span>
                  <span className="font-semibold text-on-surface flex-1">{DETECTOR[d.detector].label}</span>
                  <span className="font-mono tnum">{pct(d.reliability)}</span>
                </div>
                <div className="flex items-center justify-between font-mono text-[11.5px] text-on-surface-variant mt-1">
                  <span>{d.family} · α {d.alpha.toFixed(0)} / β {d.beta.toFixed(0)}</span>
                  <span className="text-primary-container">● Active</span>
                </div>
              </Link>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
