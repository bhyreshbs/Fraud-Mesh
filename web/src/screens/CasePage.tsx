// /cases/:id (and the right side of /investigations) — Stitch "Investigations" workbench: header, stage strip, risk chart, tabs, feedback bar (PRD §11.1).
import { useState } from "react";
import { useParams } from "react-router-dom";
import { ApiError } from "../lib/api";
import { hasRole, useAuth } from "../lib/auth";
import { useCase, useExplanation, useGraph, useTimeline } from "../lib/queries";
import { CaseHeader } from "../components/CaseHeader";
import { StageStrip } from "../components/StageStrip";
import { RiskChart } from "../components/RiskChart";
import { TimelineTab } from "../components/TimelineTab";
import { GraphTab } from "../components/GraphTab";
import { AskTab, ExplanationTab, ReplayTab } from "../components/CaseTabs";
import { TwinTab } from "../components/TwinTab";
import { FeedbackBar, ManualActionDialog } from "../components/CaseActions";

const TABS = ["Timeline", "Graph", "Explanation", "Replay", "Twin", "Ask"] as const;
type Tab = (typeof TABS)[number];
const TAB_ICON: Record<Tab, string> = { Timeline: "timeline", Graph: "hub", Explanation: "waterfall_chart", Replay: "replay",
  Twin: "deployed_code", Ask: "forum" };

export function CasePage() {
  const { id = "" } = useParams();
  return <CaseView id={id} />;
}

export function CaseView({ id, embedded = false }: { id: string; embedded?: boolean }) {
  const { session } = useAuth();
  const [tab, setTab] = useState<Tab>("Timeline");
  const [highlight, setHighlight] = useState<string | null>(null);
  const [manual, setManual] = useState(false);
  const detail = useCase(id);
  const tl = useTimeline(id);
  const ex = useExplanation(id);
  const graph = useGraph(id);

  const showEvidence = (evId: string) => {
    if (!evId.startsWith("ev_")) return;
    setTab("Timeline");
    setHighlight(evId);
    setTimeout(() => document.getElementById(`ev-${evId}`)?.scrollIntoView({ behavior: "smooth", block: "center" }), 50);
    setTimeout(() => setHighlight(null), 2500);
  };

  if (detail.isLoading) return <div className="p-8 text-on-surface-variant">Loading case…</div>;
  if (detail.isError) {
    const e = detail.error as ApiError;
    return <div className="p-8"><div className="px-4 py-3 rounded-xl bg-risk-critical-fill border border-risk-critical-border text-risk-critical text-body-sm">
      {e.code === "NOT_FOUND" ? "Case not found (or not in your queues)." : `${e.code}: ${e.message}`}</div></div>;
  }
  const { case: c, summary } = detail.data!;
  const counts: Partial<Record<Tab, number>> = { Timeline: tl.data?.evidence.length, Graph: graph.data?.nodes.length };

  return (
    <div className={"flex flex-col " + (embedded ? "" : "min-h-[calc(100vh-80px)]")} data-testid="case-view">
      <div className={embedded ? "" : "px-8 pt-7"}>
        <CaseHeader c={c} s={summary} onManual={hasRole(session, "lead") ? () => setManual(true) : undefined} />
      </div>
      <div className={(embedded ? "pt-5" : "px-8 py-6") + " flex flex-col gap-5 flex-1"}>
        <StageStrip c={c} onEvidence={showEvidence} />
        <RiskChart ex={ex.data} />
        <div className="fm-sunken inline-flex self-start p-1 gap-1" role="tablist">
          {TABS.map((t) => (
            <button key={t} onClick={() => setTab(t)} role="tab" aria-selected={tab === t}
              className={"h-9 px-4 rounded-[0.7rem] text-body-sm flex items-center gap-1.5 transition-all " +
                (tab === t ? "bg-porcelain shadow-porcelain-sm text-primary font-semibold" : "text-on-surface-variant hover:text-on-surface")}>
              <span className="material-symbols-outlined !text-[17px]">{TAB_ICON[t]}</span>{t}
              {counts[t] != null && <span className="font-mono text-[11px] px-1.5 rounded-full bg-surface-container">{counts[t]}</span>}
            </button>
          ))}
        </div>
        {tab === "Timeline" && <TimelineTab tl={tl.data} highlight={highlight} />}
        {tab === "Graph" && <GraphTab g={graph.data} tl={tl.data} onEvidence={showEvidence} />}
        {tab === "Explanation" && <ExplanationTab ex={ex.data} onCite={showEvidence} />}
        {tab === "Replay" && <ReplayTab caseId={id} />}
        {tab === "Twin" && <TwinTab caseId={id} />}
        {tab === "Ask" && <AskTab caseId={id} onCite={showEvidence} />}
      </div>
      <FeedbackBar caseId={id} />
      {manual && <ManualActionDialog caseId={id} onClose={() => setManual(false)} />}
    </div>
  );
}
