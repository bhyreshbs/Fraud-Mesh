// /queue — Stitch "Case Queue" (warm neumorphic): KPI tiles, filter bar with segmented tabs, ledger table, focused case.
// Data: GET /v1/cases (analyst+) kept live by useStream(); new / updated rows slide in.
import { useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { BAND_ORDER, type Band, type CaseSummary } from "../types/contracts";
import { inr, istTime, istWhen, isRecent, pct, shortCaseId, shortToken } from "../lib/format";
import { useCases } from "../lib/queries";
import { useStream } from "../lib/stream";
import { attackVector, STAGE_LABEL } from "../lib/labels";
import { BandPill, PaymentChip, StageDots } from "../components/Risk";
import { Kpi, LiveDot, PageHeader, Panel, SegTabs } from "../components/ui";

type Tab = "active" | "critical" | "high" | "medium" | "low";
const rank = (b: Band) => BAND_ORDER.indexOf(b);
const PAGE = 25;

export function Queue() {
  const q = useCases();
  const { status, fresh } = useStream();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [search, setSearch] = useState(params.get("q") ?? "");
  const [tab, setTab] = useState<Tab>(params.get("band") ? (params.get("band")!.toLowerCase() as Tab) : "active");
  const [page, setPage] = useState(0);

  const all = q.data?.items ?? [];
  const n = (b: Band) => all.filter((c) => c.band === b).length;
  const active = all.filter((c) => c.status === "OPEN" || c.status === "INVESTIGATING");
  const rows = useMemo(() => all
    .filter((c) => (tab === "active" ? c.band !== "LOW" : c.band === tab.toUpperCase()))
    .filter((c) => !search || (c.case_id + " " + (c.customer ?? "")).toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => rank(b.band) - rank(a.band) || b.updated_at.localeCompare(a.updated_at) || b.p_attack - a.p_attack), [all, tab, search]);
  const shown = rows.slice(page * PAGE, page * PAGE + PAGE);
  const pages = Math.max(1, Math.ceil(rows.length / PAGE));
  const focus: CaseSummary | undefined = rows[0];
  const exposure = (b: Band[]) => all.filter((c) => b.includes(c.band)).reduce((s, c) => s + c.amount_at_risk_paise, 0);

  return (
    <div className="px-8 py-7 flex flex-col gap-7 text-on-surface" data-testid="queue">
      <PageHeader meta={<><LiveDot on={status === "live"} /> {status === "live" ? "Streaming over WebSocket" : status}
        {q.dataUpdatedAt ? ` · loaded ${istTime(new Date(q.dataUpdatedAt).toISOString(), true)} IST` : ""}</>}
        title="Case Queue" subtitle="One row per attack, highest band first, then most recent."
        actions={<Link to="/investigations" className="fm-btn-primary"><span className="material-symbols-outlined !text-[18px]">manage_search</span>Open investigations</Link>} />

      <div className="grid grid-cols-4 gap-6">
        <Kpi label="Active cases" value={active.length} icon="layers" sub={`${active.length - n("LOW")} above LOW`} />
        <Kpi label="Critical" value={n("CRITICAL")} icon="crisis_alert" tone="critical" sub={<>{inr(exposure(["CRITICAL"]))} <span className="text-on-surface-variant">exposure</span></>}
          foot="Payments blocked, sessions revoked" />
        <Kpi label="High" value={n("HIGH")} icon="pan_tool" tone="high" sub={<>{inr(exposure(["HIGH"]))} <span className="text-on-surface-variant">exposure</span></>}
          foot="Payments held, trusted step-up sent" />
        <Kpi label="Medium" value={n("MEDIUM")} icon="how_to_reg" tone="medium" sub="Step-up verification requested" foot={`${n("LOW")} LOW cases logged only`} />
      </div>

      <Panel>
        <div className="p-5 flex flex-col gap-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative w-96">
              <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline !text-[18px]">search</span>
              <input value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }} placeholder="Search by case ID or customer token…"
                className="w-full h-10 pl-10 pr-3 text-body-sm placeholder:text-outline" data-testid="queue-search" />
            </div>
            <span className="ml-auto font-mono text-[12px] text-on-surface-variant">Sort: band, then most recent · times in IST</span>
          </div>
          <SegTabs value={tab} onChange={(t) => { setTab(t); setPage(0); }} testid="band-tabs" options={[
            { value: "active", label: <>All active <span className="font-mono">({all.length - n("LOW")})</span></> },
            { value: "critical", label: <>Critical <span className="font-mono">({n("CRITICAL")})</span></> },
            { value: "high", label: <>High <span className="font-mono">({n("HIGH")})</span></> },
            { value: "medium", label: <>Medium <span className="font-mono">({n("MEDIUM")})</span></> },
            { value: "low", label: <>Low <span className="font-mono">({n("LOW")})</span></> },
          ]} />
        </div>
      </Panel>

      <Panel>
        <table className="w-full text-left text-body-sm" data-testid="queue-table">
          <thead>
            <tr className="font-mono text-[11px] tracking-[0.08em] uppercase text-on-surface-variant bg-surface-container-low/70">
              <th className="pl-6 py-3.5 rounded-tl-[1.25rem]">Case ID</th><th className="px-3">Risk level</th><th className="px-3">Customer</th>
              <th className="px-3">Attack vector</th><th className="px-3">Stages</th><th className="px-3 text-right">Exposure</th>
              <th className="px-3">State</th><th className="px-3 pr-6 text-right rounded-tr-[1.25rem]">Updated (IST)</th>
            </tr>
          </thead>
          <tbody>
            {q.isLoading && <tr><td colSpan={8} className="px-6 py-10 text-on-surface-variant">Loading cases…</td></tr>}
            {!q.isLoading && shown.length === 0 && <tr><td colSpan={8} className="px-6 py-10 text-on-surface-variant">No cases match.</td></tr>}
            {shown.map((c) => {
              const v = attackVector(c.stages_reached);
              return (
                <tr key={c.case_id} onClick={() => navigate(`/cases/${c.case_id}`)} data-testid="case-row"
                  className={"fm-row h-[68px] border-t border-taupe/20 cursor-pointer transition-all " + (fresh.has(c.case_id) ? "fm-slide-in" : "")}>
                  <td className="pl-6 font-mono text-[13px] font-semibold">{shortCaseId(c.case_id)}
                    {isRecent(c.updated_at) && <span className="ml-2 align-middle fm-pill !bg-risk-critical !text-white !border-transparent" data-testid="live-badge">LIVE</span>}</td>
                  <td className="px-3"><div className="flex items-center gap-2"><BandPill band={c.band} /><span className="font-mono text-[12px] text-on-surface-variant">{pct(c.p_attack)}</span></div></td>
                  <td className="px-3"><div className="flex items-center gap-2.5">
                    <span className="w-8 h-8 rounded-lg bg-surface-container shadow-porcelain-sm flex items-center justify-center font-mono text-[11px] font-semibold text-on-surface-variant">
                      {(c.customer ?? "?").replace(/^cust:/, "").slice(0, 2).toUpperCase()}</span>
                    <span className="font-mono text-[12.5px]">{shortToken(c.customer)}</span></div></td>
                  <td className="px-3"><span className="flex items-center gap-2"><span className="material-symbols-outlined !text-[18px] text-primary-container">{v.icon}</span>{v.label}</span></td>
                  <td className="px-3"><div className="flex flex-col gap-1"><StageDots reached={c.stages_reached} />
                    <span className="text-[11px] text-on-surface-variant">{c.current_stage ? STAGE_LABEL[c.current_stage] : ""}</span></div></td>
                  <td className={"px-3 text-right font-mono " + (c.band === "CRITICAL" ? "text-risk-critical font-semibold" : "")}>{c.amount_at_risk_paise ? inr(c.amount_at_risk_paise) : "—"}</td>
                  <td className="px-3"><PaymentChip state={c.payment_state} /></td>
                  <td className="px-3 pr-6 text-right font-mono text-[12px] text-on-surface-variant whitespace-nowrap">{istWhen(c.updated_at)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        <div className="px-6 py-4 flex items-center justify-between text-body-sm text-on-surface-variant">
          <span>Showing <b className="text-on-surface">{rows.length ? page * PAGE + 1 : 0}–{Math.min(rows.length, (page + 1) * PAGE)}</b> of <b className="text-on-surface">{rows.length}</b> cases</span>
          <div className="flex items-center gap-2">
            <button className="fm-btn !h-9 !px-3" disabled={page === 0} onClick={() => setPage((p) => p - 1)}><span className="material-symbols-outlined !text-[18px]">chevron_left</span></button>
            <span className="font-mono text-[12px] px-2">{page + 1} / {pages}</span>
            <button className="fm-btn !h-9 !px-3" disabled={page + 1 >= pages} onClick={() => setPage((p) => p + 1)}><span className="material-symbols-outlined !text-[18px]">chevron_right</span></button>
          </div>
        </div>
      </Panel>

      {focus && (
        <Panel testid="focused-case">
          <div className="px-6 py-5 flex items-center gap-4 flex-wrap">
            <span className="w-11 h-11 rounded-xl bg-primary-fixed text-primary flex items-center justify-center shadow-porcelain-sm"><span className="material-symbols-outlined">hub</span></span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2"><span className="text-[19px] font-semibold">Focused case: {shortCaseId(focus.case_id)}</span><BandPill band={focus.band} /></div>
              <div className="text-body-sm text-on-surface-variant">{attackVector(focus.stages_reached).label} · {focus.stages_reached.length} kill-chain stages ·
                customer <span className="font-mono">{shortToken(focus.customer)}</span></div>
            </div>
            <Link to={`/twin?case=${focus.case_id}`} className="fm-btn">Replay in digital twin</Link>
            <Link to={`/cases/${focus.case_id}`} className="fm-btn-primary">Open workbench <span className="material-symbols-outlined !text-[18px]">arrow_forward</span></Link>
          </div>
          <div className="px-6 pb-6 grid grid-cols-3 gap-4">
            <div className="fm-tint p-4"><div className="font-mono text-[11px] tracking-[0.08em] uppercase text-on-surface-variant">Fused attack probability</div>
              <div className="text-[22px] font-semibold mt-1 tnum">{pct(focus.p_attack, 2)}</div>
              <div className="text-body-sm text-on-surface-variant">reliability-weighted log-odds of every signal in the case</div></div>
            <div className="fm-tint p-4"><div className="font-mono text-[11px] tracking-[0.08em] uppercase text-on-surface-variant">Current stage</div>
              <div className="text-[22px] font-semibold mt-1">{focus.current_stage ? STAGE_LABEL[focus.current_stage] : "—"}</div>
              <div className="text-body-sm text-on-surface-variant">{focus.stages_reached.map((s) => s.slice(0, 2)).join(" → ")}</div></div>
            <div className="fm-tint p-4"><div className="font-mono text-[11px] tracking-[0.08em] uppercase text-on-surface-variant">Automated action</div>
              <div className="text-[22px] font-semibold mt-1 capitalize">{focus.payment_state === "normal" ? "Monitoring" : `Payments ${focus.payment_state}`}</div>
              <div className="text-body-sm text-on-surface-variant">{focus.latest_actions.join(", ").replace(/_/g, " ").toLowerCase() || "allow"}</div></div>
          </div>
        </Panel>
      )}
    </div>
  );
}
