// /twin — the Digital Twin: the virtual bank's size and state (GET /v1/twin/overview, refreshed live over the case
// stream), the riskiest cases, and the selected case replayed into the twin with every strategy compared.
import { useState } from "react";
import { Link } from "react-router-dom";
import type { Band } from "../types/contracts";
import { ApiError } from "../lib/api";
import { inr, istTime, pct, shortCaseId, shortToken } from "../lib/format";
import { useTwin, useTwinOverview } from "../lib/queries";
import { BandPill, BAND_STYLE } from "../components/Risk";
import { TwinView } from "../components/TwinTab";

const KIND_LABEL: Record<string, string> = { cust: "Customers", acct: "Accounts", dev: "Devices", ip: "IP networks", phone: "Phones", cid: "Staff / cloud identities" };

function Tile({ label, value, sub, testid }: { label: string; value: string; sub?: string; testid?: string }) {
  return (
    <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-3" data-testid={testid}>
      <div className="font-label-caps text-label-caps uppercase text-on-surface-variant">{label}</div>
      <div className="text-[22px] font-semibold tnum mt-1">{value}</div>
      {sub && <div className="text-body-xs text-on-surface-variant">{sub}</div>}
    </div>
  );
}

function CaseTwinPanel({ caseId }: { caseId: string }) {
  const q = useTwin(caseId);
  const [selected, setSelected] = useState<string | null>(null);
  if (q.isError) return <div className="p-4 text-risk-critical">{(q.error as ApiError).message}</div>;
  if (!q.data) return <div className="p-4 text-on-surface-variant">Replaying the case into the twin…</div>;
  return <TwinView t={q.data} selected={selected ?? q.data.live_policy} onSelect={setSelected} />;
}

export function Twin() {
  const q = useTwinOverview();
  const [picked, setPicked] = useState<string | null>(null);
  const ov = q.data;
  const current = picked ?? ov?.hottest_cases[0]?.case_id ?? null;
  const total = ov ? Object.values(ov.cases_by_band).reduce((a, b) => a + b, 0) : 0;

  return (
    <div className="p-space-base flex flex-col gap-3" data-testid="twin-page">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="font-headline-lg text-headline-lg tracking-tight">Digital twin</h1>
          <p className="text-body-sm text-on-surface-variant">A virtual copy of the bank built from every event FraudMesh has seen: customers, accounts,
            devices, networks and payees, their links and their current risk. Pick a case to replay it and compare prevention strategies.</p>
        </div>
        {q.isFetching && <span className="text-body-xs text-on-surface-variant">updating…</span>}
      </div>
      {q.isError && <div className="text-risk-critical text-body-sm">{(q.error as ApiError).message}</div>}

      {ov && (
        <>
          <div className="grid grid-cols-6 gap-3" data-testid="twin-entities-count">
            {Object.entries(KIND_LABEL).map(([k, label]) => <Tile key={k} label={label} value={(ov.entities[k] ?? 0).toLocaleString("en-IN")} />)}
          </div>
          <div className="grid grid-cols-5 gap-3">
            <Tile label="Cases in the twin" value={total.toLocaleString("en-IN")}
              sub={(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Band[]).map((b) => `${ov.cases_by_band[b]} ${BAND_STYLE[b].label.toLowerCase()}`).join(" · ")} />
            <Tile label="Known fraud seeds" value={String(ov.fraud_seeds)} sub="confirmed mule devices / accounts" />
            <Tile label="Payments held / blocked" value={`${ov.payments_held} / ${ov.payments_blocked}`} sub={`${ov.active_interventions} cases under an active intervention`} />
            <Tile label="Money protected" value={inr(ov.money_protected_paise)} sub="in held or blocked cases" testid="twin-protected" />
            <Tile label="Money still at risk" value={inr(ov.money_at_risk_paise)} sub="open cases above LOW, payments normal" />
          </div>

          <div className="grid grid-cols-[300px_1fr] gap-3 items-start">
            <section className="bg-surface-container-lowest border border-outline-variant rounded-lg">
              <div className="h-10 px-3 flex items-center border-b border-outline-variant font-headline-sm text-headline-sm">Riskiest cases</div>
              <ul data-testid="twin-cases">
                {ov.hottest_cases.map((c) => (
                  <li key={c.case_id}>
                    <button onClick={() => setPicked(c.case_id)}
                      className={"w-full text-left px-3 py-2 border-b border-outline-variant last:border-0 " + (c.case_id === current ? "bg-[#E8EEFB]" : "hover:bg-surface-container-low")}>
                      <div className="flex items-center gap-2"><span className="font-code-sm text-code-sm">{shortCaseId(c.case_id)}</span>
                        <BandPill band={c.band} /><span className="ml-auto font-code-xs text-code-xs">{pct(c.p_attack)}</span></div>
                      <div className="text-body-xs text-on-surface-variant">{shortToken(c.customer)} · {c.stages} stages · {c.payment_state}
                        {c.amount_at_risk_paise > 0 && <> · {inr(c.amount_at_risk_paise)}</>} · {istTime(c.last_event_ts)}</div>
                    </button>
                  </li>
                ))}
                {ov.hottest_cases.length === 0 && <li className="p-3 text-body-sm text-on-surface-variant">No cases yet: run a scenario from Demo control.</li>}
              </ul>
            </section>
            <div className="flex flex-col gap-2">
              {current && <div className="text-body-sm">Case <Link className="text-primary-container hover:underline font-code-sm" to={`/cases/${current}`}>{current}</Link> in the twin</div>}
              {current ? <CaseTwinPanel key={current} caseId={current} /> : null}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
