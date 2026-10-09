// /cases/:id — Stitch "Case Investigation" screen: header, stage strip, risk chart, tabs, feedback bar (PRD §11.1).
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

export function CasePage() {
  const { id = "" } = useParams();
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

  if (detail.isLoading) return <div className="p-6 text-on-surface-variant">Loading case…</div>;
  if (detail.isError) {
    const e = detail.error as ApiError;
    return <div className="p-6"><div className="px-3 py-2.5 rounded-lg bg-risk-critical-fill border border-risk-critical-border text-risk-critical text-body-sm">
      {e.code === "NOT_FOUND" ? "Case not found (or not in your queues)." : `${e.code}: ${e.message}`}</div></div>;
  }
  const { case: c, summary } = detail.data!;
  const counts: Partial<Record<Tab, number>> = { Timeline: tl.data?.evidence.length, Graph: graph.data?.nodes.length };

  return (
    <div className="flex flex-col min-h-[calc(100vh-56px)]">
      <CaseHeader c={c} s={summary} onManual={hasRole(session, "lead") ? () => setManual(true) : undefined} />
      <div className="p-space-base flex flex-col gap-3 flex-1">
        <StageStrip c={c} onEvidence={showEvidence} />
        <RiskChart ex={ex.data} />
        <div className="flex items-center gap-1 border-b border-outline-variant">
          {TABS.map((t) => (
            <button key={t} onClick={() => setTab(t)} role="tab" aria-selected={tab === t}
              className={"h-10 px-3 -mb-px border-b-2 text-body-md flex items-center gap-1.5 " +
                (tab === t ? "border-primary-container text-primary-container font-semibold" : "border-transparent text-on-surface-variant hover:text-on-surface")}>
              {t}{counts[t] != null && <span className="text-[11px] px-1.5 rounded-lg bg-surface-container">{counts[t]}</span>}
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
