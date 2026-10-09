// /investigations[/:id] — Stitch "Investigations": KPI tiles, dossier list of escalated cases (left) and the full case
// workbench (right: entity graph, attack timeline, explanation, replay, digital twin, Investigator AI). Data: /v1/cases.
import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { BAND_ORDER, type CaseSummary } from "../types/contracts";
import { inr, istWhen, isRecent, pct, shortCaseId, shortToken } from "../lib/format";
import { attackVector } from "../lib/labels";
import { useCases } from "../lib/queries";
import { useStream } from "../lib/stream";
import { BandPill } from "../components/Risk";
import { Kpi, PageHeader, SegTabs } from "../components/ui";
import { CaseView } from "./CasePage";

type Filter = "all" | "critical" | "investigating" | "held";

function Dossier({ c, selected, onClick, fresh }: { c: CaseSummary; selected: boolean; onClick: () => void; fresh: boolean }) {
  const v = attackVector(c.stages_reached);
  return (
    <button onClick={onClick} data-testid="dossier"
      className={"text-left w-full p-4 rounded-2xl transition-all " + (fresh ? "fm-slide-in " : "") +
        (selected ? "fm-card !border-primary-container/60 ring-2 ring-primary-container/30" : "fm-card-sm hover:shadow-porcelain")}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex flex-col gap-1.5">
          <div className="flex items-center gap-2"><span className="font-mono text-[12.5px] font-semibold">{shortCaseId(c.case_id)}</span><BandPill band={c.band} />
            {isRecent(c.updated_at) && <span className="fm-pill !bg-risk-critical !text-white !border-transparent">LIVE</span>}</div>
          <span className="font-mono text-[10.5px] uppercase tracking-[0.06em] px-2 py-0.5 rounded-md bg-risk-critical-fill text-risk-critical self-start">{v.label}</span>
        </div>
        <span className="fm-sunken px-2.5 py-1 text-center"><span className="block font-mono font-semibold text-[15px] leading-tight tnum">{Math.round(c.p_attack * 100)}</span>
          <span className="block font-mono text-[9.5px] text-on-surface-variant">/100</span></span>
      </div>
      <div className="mt-2 font-mono text-[12px] text-on-surface-variant">{shortToken(c.customer)} · {c.stages_reached.length} stages · {c.payment_state}</div>
      <div className="mt-2 flex items-center justify-between text-[12px]">
        <span className="font-mono text-on-surface">{c.amount_at_risk_paise ? inr(c.amount_at_risk_paise) : "no transfer yet"}</span>
        <span className="font-mono text-on-surface-variant">{istWhen(c.updated_at)}</span>
      </div>
    </button>
  );
}

export function Investigations() {
  const { id } = useParams();
  const navigate = useNavigate();
  const q = useCases();
  const { fresh } = useStream();
  const [filter, setFilter] = useState<Filter>("all");
  const all = q.data?.items ?? [];
  const escalated = all.filter((c) => c.band !== "LOW");
  const list = useMemo(() => escalated
    .filter((c) => filter === "all" || (filter === "critical" ? c.band === "CRITICAL" : filter === "investigating" ? c.status === "INVESTIGATING" : c.payment_state !== "normal"))
    .sort((a, b) => BAND_ORDER.indexOf(b.band) - BAND_ORDER.indexOf(a.band) || b.updated_at.localeCompare(a.updated_at) || b.p_attack - a.p_attack),
  [escalated, filter]);
  const current = id && (!q.data || all.some((c) => c.case_id === id)) ? id : list[0]?.case_id;   // a reset case falls back
  const contained = escalated.filter((c) => c.payment_state !== "normal").length;
  const atRisk = escalated.reduce((s, c) => s + c.amount_at_risk_paise, 0);
  const meanP = escalated.length ? escalated.reduce((s, c) => s + c.p_attack, 0) / escalated.length : 0;

  return (
    <div className="px-8 py-7 flex flex-col gap-7" data-testid="investigations">
      <PageHeader meta={<>{escalated.length} escalated dossiers</>} title="Investigations"
        subtitle="Entity graph, timeline, score breakdown, replay and twin for each escalated case." />
      <div className="grid grid-cols-4 gap-6">
        <Kpi label="Active investigations" value={escalated.length} icon="folder_open" sub={`${all.filter((c) => c.status === "INVESTIGATING").length} confirmed by the customer ("Not me")`} />
        <Kpi label="Critical" value={escalated.filter((c) => c.band === "CRITICAL").length} icon="account_balance" tone="critical" sub={<>{inr(atRisk)} <span className="text-on-surface-variant">total exposure</span></>} />
        <Kpi label="Mean attack probability" value={pct(meanP, 1)} icon="query_stats" tone="high" sub="fused over every escalated case" />
        <Kpi label="Containment rate" value={escalated.length ? pct(contained / escalated.length, 1) : "—"} icon="lock" tone="low"
          sub={`${contained} of ${escalated.length} with payments held or blocked`} />
      </div>
      <div className="flex items-center gap-3">
        <SegTabs value={filter} onChange={setFilter} options={[
          { value: "all", label: `All (${escalated.length})` }, { value: "critical", label: "Critical" },
          { value: "investigating", label: "Confirmed by customer" }, { value: "held", label: "Payments held / blocked" }]} />
      </div>
      <div className="grid grid-cols-[340px_1fr] gap-6 items-start">
        <aside className="flex flex-col gap-3 max-h-[calc(100vh-120px)] overflow-y-auto pr-1 sticky top-24" data-testid="dossiers">
          <div className="flex items-center justify-between px-1">
            <span className="text-[17px] font-semibold">Active dossiers</span>
            <span className="font-mono text-[11px] text-on-surface-variant">band, then most recent</span>
          </div>
          {list.map((c) => <Dossier key={c.case_id} c={c} selected={c.case_id === current} fresh={fresh.has(c.case_id)}
            onClick={() => navigate(`/investigations/${c.case_id}`)} />)}
          {list.length === 0 && <div className="fm-sunken p-4 text-body-sm text-on-surface-variant">No dossiers in this filter.</div>}
        </aside>
        <div className="min-w-0">{current ? <CaseView key={current} id={current} embedded /> :
          <div className="fm-card p-8 text-on-surface-variant">Select a dossier.</div>}</div>
      </div>
    </div>
  );
}
