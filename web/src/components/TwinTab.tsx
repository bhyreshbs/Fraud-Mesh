// Digital Twin tab: the case replayed into a virtual copy of the bank. Every prevention strategy runs on its own
// isolated copy; picking one shows what each step became under it. Data: GET /v1/cases/{id}/twin (engine/twin).
import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Stage } from "../types/contracts";
import type { Actor, CaseTwin, StepOutcome } from "../types/twin";
import { ApiError } from "../lib/api";
import { inr, istTime, pct, shortToken } from "../lib/format";
import { ACTION_LABEL, STAGE_LABEL } from "../lib/labels";
import { useTwin } from "../lib/queries";
import { BandPill } from "./Risk";
import { KIND_STYLE } from "./GraphTab";

const ACTOR: Record<Actor, { label: string; cls: string; icon: string }> = {
  attacker: { label: "Attacker", cls: "bg-risk-critical-fill text-risk-critical", icon: "person_alert" },
  customer: { label: "Customer", cls: "bg-[#E8EEFB] text-primary-container", icon: "person" },
  network: { label: "Network sensor", cls: "bg-[#F3E8FF] text-[#7C3AED]", icon: "lan" },
  insider: { label: "Support console", cls: "bg-[#EEF2FF] text-[#4338CA]", icon: "support_agent" },
  system: { label: "Telco / bank", cls: "bg-surface-container text-on-surface-variant", icon: "cell_tower" },
};
const OUTCOME: Record<StepOutcome, { label: string; cls: string }> = {
  happened: { label: "happened", cls: "bg-surface-container text-on-surface-variant" },
  completed: { label: "completed", cls: "bg-surface-container text-on-surface-variant" },
  prevented: { label: "PREVENTED", cls: "bg-risk-low-fill text-risk-low font-semibold" },
  held: { label: "HELD", cls: "bg-risk-medium-fill text-risk-medium font-semibold" },
  blocked: { label: "BLOCKED", cls: "bg-risk-low-fill text-risk-low font-semibold" },
  rejected: { label: "REJECTED", cls: "bg-risk-low-fill text-risk-low font-semibold" },
  lost: { label: "MONEY LOST", cls: "bg-risk-critical-fill text-risk-critical font-semibold" },
};
const stageName = (s: Stage | null | undefined) => (s ? STAGE_LABEL[s] : "—");
const mins = (m: number | null | undefined) => (m == null ? "—" : m < 1 ? "< 1 min" : `~${Math.round(m)} min`);
const lead = (s: number | null) => (s == null ? "—" : s >= 0 ? `${Math.floor(s / 60)} min before the transfer` : `${Math.round(-s / 60)} min after`);

function Section({ title, right, children, testid }: { title: string; right?: React.ReactNode; children: React.ReactNode; testid?: string }) {
  return (
    <section className="bg-surface-container-lowest border border-outline-variant rounded-lg" data-testid={testid}>
      <div className="h-10 px-3 flex items-center justify-between border-b border-outline-variant">
        <span className="font-headline-sm text-headline-sm">{title}</span>{right}
      </div>
      {children}
    </section>
  );
}

export function TwinTab({ caseId }: { caseId: string }) {
  const q = useTwin(caseId);
  const [selected, setSelected] = useState<string | null>(null);
  if (q.isError) return <div className="p-6 text-risk-critical">{(q.error as ApiError).message}</div>;
  if (!q.data) return <div className="p-6 text-on-surface-variant">Building the digital twin…</div>;
  return <TwinView t={q.data} selected={selected ?? q.data.live_policy} onSelect={setSelected} />;
}

export function TwinView({ t, selected, onSelect }: { t: CaseTwin; selected: string; onSelect: (id: string) => void }) {
  const pol = t.policies.find((p) => p.policy_id === selected) ?? t.policies[t.policies.length - 1];
  const worst = Math.max(...t.policies.map((p) => p.money_lost_paise + p.money_protected_paise), 1);
  const risk = t.steps.map((s) => ({ i: s.index + 1, label: `${s.index + 1}. ${istTime(s.ts)}`, p: s.p, money: s.forecast_p_money }));
  const eipStep = t.steps.find((s) => s.ts === t.earliest_intervention);
  const now = t.prediction;

  return (
    <div className="flex flex-col gap-3" data-testid="twin-tab">
      <div className="flex items-center gap-3 flex-wrap bg-surface-container-lowest border border-outline-variant rounded-lg px-3 py-2">
        <span className="material-symbols-outlined text-primary-container">hub</span>
        <span className="text-body-sm">Replays this case's {t.steps.length} events into a <b>virtual copy of the bank</b> and runs
          each prevention strategy on an <b>isolated copy</b> of the same starting state.</span>
        <span className="ml-auto text-body-xs text-on-surface-variant">Simulated outcomes, not guarantees · see assumptions below</span>
      </div>

      <Section title="Prevention strategies compared" testid="twin-strategies"
        right={<span className="text-body-xs text-on-surface-variant">Best here: <b>{t.policies.find((p) => p.policy_id === t.best_policy)?.label}</b></span>}>
        <div className="grid grid-cols-[1fr_360px]">
          <table className="w-full text-body-sm tnum">
            <thead><tr className="h-8 text-left text-label-caps font-label-caps uppercase text-on-surface-variant border-b border-outline-variant">
              <th className="px-3">Strategy</th><th className="px-2 text-right">Money lost</th><th className="px-2 text-right">Protected</th>
              <th className="px-2">Attacker stopped</th><th className="px-2 text-right">Friction</th></tr></thead>
            <tbody>
              {t.policies.map((p) => (
                <tr key={p.policy_id} onClick={() => onSelect(p.policy_id)} data-testid={`policy-${p.policy_id}`}
                  className={"h-10 border-b border-outline-variant last:border-0 cursor-pointer " +
                    (p.policy_id === selected ? "bg-[#E8EEFB]" : "hover:bg-surface-container-low")}>
                  <td className="px-3" title={p.description}>
                    <span className="font-medium">{p.label}</span>
                    {p.policy_id === t.best_policy && <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-lg bg-risk-low-fill text-risk-low font-semibold">BEST</span>}
                    {p.policy_id === t.live_policy && <span className="ml-1.5 text-[10px] px-1.5 py-0.5 rounded-lg bg-surface-container text-primary-container">LIVE</span>}
                  </td>
                  <td className={"px-2 text-right font-semibold " + (p.money_lost_paise ? "text-risk-critical" : "text-on-surface-variant")}>{inr(p.money_lost_paise)}</td>
                  <td className={"px-2 text-right " + (p.money_protected_paise ? "text-risk-low font-semibold" : "text-on-surface-variant")}>{inr(p.money_protected_paise)}</td>
                  <td className="px-2 text-body-xs">{p.stopped_at ? <>{istTime(p.stopped_at)} · {stageName(p.stopped_stage)}<div className="text-on-surface-variant">{lead(p.lead_time_s)}</div></>
                    : p.money_lost_paise ? <span className="text-risk-critical">no — money moved</span> : p.money_protected_paise ? "money held / blocked" : "—"}</td>
                  <td className="px-2 text-right">{p.customer_friction}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="border-l border-outline-variant p-2">
            <ResponsiveContainer width="100%" height={40 + t.policies.length * 34}>
              <BarChart layout="vertical" data={t.policies.map((p) => ({ name: p.label, lost: p.money_lost_paise / 100, protected: p.money_protected_paise / 100 }))}
                margin={{ top: 4, right: 12, bottom: 4, left: 4 }}>
                <CartesianGrid stroke="#E2E5E9" horizontal={false} />
                <XAxis type="number" domain={[0, worst / 100]} tick={{ fontSize: 10 }} tickFormatter={(v) => `₹${(v / 100000).toFixed(1)}L`} />
                <YAxis type="category" dataKey="name" width={120} tick={{ fontSize: 10 }} />
                <Tooltip formatter={(v) => `₹${Number(v).toLocaleString("en-IN")}`} contentStyle={{ fontSize: 12, borderRadius: 4 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Bar dataKey="lost" stackId="m" fill="#B42318" name="lost" isAnimationActive={false} />
                <Bar dataKey="protected" stackId="m" fill="#1E6B45" name="protected" isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </Section>

      <div className="grid grid-cols-[1fr_340px] gap-3">
        <Section title={`The attack in the twin — under “${pol.label}”`} testid="twin-steps"
          right={<span className="text-body-xs text-on-surface-variant">click a strategy above to replay it</span>}>
          <ol className="flex flex-col">
            {t.steps.map((s, k) => {
              const outcome = pol.steps[k] ?? "happened";
              const a = ACTOR[s.actor];
              const acts = pol.interventions.filter((iv) => iv.ts === s.ts);
              return (
                <li key={s.event_id} className={"px-3 py-2 border-b border-outline-variant last:border-0 " + (outcome === "prevented" || outcome === "rejected" ? "opacity-60" : "")}
                  data-testid="twin-step">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-code-xs text-code-xs text-on-surface-variant w-12">{istTime(s.ts)}</span>
                    <span className={`inline-flex items-center gap-1 text-[11px] px-1.5 py-0.5 rounded-lg ${a.cls}`}>
                      <span className="material-symbols-outlined !text-[13px]">{a.icon}</span>{a.label}</span>
                    <span className="text-[11px] text-on-surface-variant">{stageName(s.stage)}</span>
                    <span className="font-medium text-body-sm">{s.summary}</span>
                    <span className="ml-auto flex items-center gap-1.5"><span className="font-code-xs text-code-xs">{pct(s.p)}</span><BandPill band={s.band} />
                      <span className={`text-[10px] px-1.5 py-0.5 rounded-lg ${OUTCOME[outcome].cls}`} data-testid="step-outcome">{OUTCOME[outcome].label}</span></span>
                  </div>
                  {s.changes.length > 0 && <div className="ml-14 mt-0.5 text-body-xs text-on-surface-variant">state: {s.changes.join(" · ")}</div>}
                  {acts.map((iv, j) => (
                    <div key={j} className="ml-14 mt-0.5 text-body-xs"><span className="text-primary-container font-medium">
                      ↳ {ACTION_LABEL[iv.action as keyof typeof ACTION_LABEL] ?? iv.action}</span>: {iv.effect}</div>
                  ))}
                  {s.forecast_next && (
                    <div className="ml-14 mt-0.5 text-[11px] text-[#7C3AED]">forecast: next {stageName(s.forecast_next)} ({pct(s.forecast_probability ?? 0, 0)})
                      {s.forecast_p_money != null && <> · reaches the money {pct(s.forecast_p_money, 0)} · {mins(s.forecast_minutes_to_money)}</>}</div>
                  )}
                </li>
              );
            })}
          </ol>
        </Section>

        <div className="flex flex-col gap-3">
          <Section title="Forecast now" testid="twin-forecast">
            <div className="p-3 flex flex-col gap-2 text-body-sm">
              <div>Attack has reached <b>{stageName(now.from_stage)}</b>{now.from_stage === "S6_MONETIZATION" &&
                <span className="text-on-surface-variant">: the money stage. Similar attacks then come back for another transfer:</span>}</div>
              {now.from_stage === null && <div className="text-on-surface-variant">No attacker activity in this case.</div>}
              {now.next_stages.map((n) => (
                <div key={n.stage} className="flex items-center gap-2">
                  <span className="w-36">{stageName(n.stage)}</span>
                  <div className="flex-1 h-2 bg-surface-container rounded"><div className="h-2 rounded bg-[#7C3AED]" style={{ width: `${n.probability * 100}%` }} /></div>
                  <span className="w-12 text-right tnum font-code-xs text-code-xs">{pct(n.probability, 0)}</span>
                </div>
              ))}
              {now.p_reach_monetization != null && now.from_stage !== "S6_MONETIZATION" &&
                <div>Reaches the money: <b>{pct(now.p_reach_monetization, 0)}</b>, typically {mins(now.expected_minutes_to_monetization)}</div>}
              <div className="text-body-xs text-on-surface-variant">{now.note}</div>
            </div>
          </Section>
          <Section title="Virtual entities" testid="twin-entities">
            <ul className="p-2 flex flex-col gap-1.5 max-h-[340px] overflow-auto">
              {t.entities.filter((e) => e.tags.length).map((e) => (
                <li key={e.entity} className="text-body-xs">
                  <span className="inline-block w-2 h-2 rounded-full mr-1.5" style={{ background: KIND_STYLE[e.kind as keyof typeof KIND_STYLE]?.color ?? "#6B7280" }} />
                  <span className="font-code-xs text-code-xs">{shortToken(e.entity)}</span>
                  <span className="ml-1 flex-wrap">{e.tags.map((tag) => <span key={tag} className="ml-1 px-1.5 py-0.5 rounded-lg bg-surface-container">{tag}</span>)}</span>
                </li>
              ))}
              {!t.entities.some((e) => e.tags.length) && <li className="text-body-xs text-on-surface-variant p-1">No entity changed state.</li>}
            </ul>
          </Section>
        </div>
      </div>

      <Section title="Risk evolution and forecast" testid="twin-risk"
        right={eipStep && <span className="text-body-xs text-on-surface-variant">earliest intervention: step {eipStep.index + 1} ({istTime(eipStep.ts)})</span>}>
        <div className="p-2">
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={risk} margin={{ top: 8, right: 24, bottom: 4, left: 0 }}>
              <CartesianGrid stroke="#E2E5E9" vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 10 }} />
              <YAxis domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} tick={{ fontSize: 10 }} width={40} />
              {[0.2, 0.5, 0.8].map((y) => <ReferenceLine key={y} y={y} stroke="#C3C6D5" strokeDasharray="3 3" />)}
              {eipStep && <ReferenceLine x={`${eipStep.index + 1}. ${istTime(eipStep.ts)}`} stroke="#1E6B45" strokeWidth={2} label={{ value: "intervene", fontSize: 10, fill: "#1E6B45", position: "top" }} />}
              <Tooltip formatter={(v) => pct(Number(v))} contentStyle={{ fontSize: 12, borderRadius: 4 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line type="stepAfter" dataKey="p" name="attack probability (engine)" stroke="#2457C5" strokeWidth={2} isAnimationActive={false} />
              <Line type="monotone" dataKey="money" name="forecast: reaches the money" stroke="#7C3AED" strokeDasharray="5 4" isAnimationActive={false} connectNulls />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Section>

      <Section title="Assumptions">
        <ul className="p-3 list-disc pl-6 text-body-xs text-on-surface-variant flex flex-col gap-1">
          {t.assumptions.map((a) => <li key={a}>{a}</li>)}
        </ul>
      </Section>
    </div>
  );
}

