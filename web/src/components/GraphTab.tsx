// Graph tab (PRD §11.1): Cytoscape cose layout, colour by kind, red ring on seeds, thick border on in-case entities;
// clicking a node lists the case evidence that involves it.
import { useMemo, useState } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type { Core, ElementDefinition, StylesheetStyle } from "cytoscape";
import type { EntityKind, GraphElements, Timeline } from "../types/contracts";
import { DETECTOR, STAGE_LABEL, reasonText } from "../lib/labels";
import { istTime } from "../lib/format";

export const KIND_STYLE: Record<EntityKind, { color: string; label: string }> = {
  cust: { color: "#2457C5", label: "Customer" }, acct: { color: "#0E7490", label: "Account" }, dev: { color: "#7C3AED", label: "Device" },
  ip: { color: "#B45309", label: "IP /24" }, phone: { color: "#BE185D", label: "Phone" }, email: { color: "#4B5563", label: "Email" },
  cid: { color: "#4338CA", label: "Cloud identity" }, res: { color: "#6B7280", label: "Cloud resource" }, mer: { color: "#047857", label: "Merchant" },
};

const STYLE: StylesheetStyle[] = [
  { selector: "node", style: { "background-color": "data(color)", label: "data(label)", "font-size": 10, "font-family": "JetBrains Mono",
    color: "#121c28", "text-valign": "bottom", "text-margin-y": 4, width: 26, height: 26, "border-width": 1, "border-color": "#ffffff" } },
  { selector: "node[?in_case]", style: { "border-width": 4, "border-color": "#121c28", width: 32, height: 32 } },
  { selector: "node[?seed]", style: { "border-width": 5, "border-color": "#B42318", "background-blacken": -0.1 } },
  { selector: "node:selected", style: { "overlay-color": "#2457C5", "overlay-opacity": 0.2 } },
  { selector: "edge", style: { width: "mapData(confidence, 0, 1, 1, 4)", "line-color": "#C3C6D5", "curve-style": "bezier",
    label: "data(edge_type)", "font-size": 8, color: "#737685", "text-rotation": "autorotate", "text-background-color": "#ffffff",
    "text-background-opacity": 1, "text-background-padding": "1px" } },
  { selector: "edge[edge_type = 'SHARES_DEVICE']", style: { "line-color": "#B42318", "line-style": "dashed" } },
];

export function GraphTab({ g, tl, onEvidence }: { g: GraphElements | undefined; tl: Timeline | undefined; onEvidence: (id: string) => void }) {
  const [selected, setSelected] = useState<string | null>(null);
  const elements = useMemo<ElementDefinition[]>(() => g ? [
    ...g.nodes.map((n) => ({ data: { id: n.id, label: n.label, kind: n.kind, seed: n.seed, in_case: n.in_case, color: KIND_STYLE[n.kind].color } })),
    ...g.edges.map((e) => ({ data: { id: e.id, source: e.source, target: e.target, edge_type: e.edge_type, confidence: e.confidence } })),
  ] : [], [g]);

  if (!g) return <div className="p-6 text-on-surface-variant">Loading graph…</div>;
  if (!g.nodes.length) {
    return <div className="p-6 text-on-surface-variant bg-surface-container-lowest border border-outline-variant rounded-lg">
      The engine returned no graph for this case.</div>;
  }
  const node = g.nodes.find((n) => n.id === selected);
  const related = (tl?.evidence ?? []).filter((e) => selected && e.entities.includes(selected));

  return (
    <div className="grid grid-cols-[1fr_320px] gap-3" data-testid="graph-tab">
      <div className="bg-surface-container-lowest border border-outline-variant rounded-lg overflow-hidden">
        <div className="h-10 px-3 flex items-center gap-3 border-b border-outline-variant flex-wrap">
          <span className="font-headline-sm text-headline-sm mr-2">Entity graph</span>
          {[...new Set(g.nodes.map((n) => n.kind))].map((k) => (
            <span key={k} className="flex items-center gap-1 text-body-xs text-on-surface-variant">
              <span className="w-2.5 h-2.5 rounded-full" style={{ background: KIND_STYLE[k].color }} />{KIND_STYLE[k].label}</span>
          ))}
          <span className="flex items-center gap-1 text-body-xs text-risk-critical"><span className="w-2.5 h-2.5 rounded-full border-2 border-risk-critical" />fraud seed</span>
          <span className="flex items-center gap-1 text-body-xs text-on-surface-variant"><span className="w-2.5 h-2.5 rounded-full border-2 border-on-surface" />in this case</span>
        </div>
        <CytoscapeComponent elements={elements} stylesheet={STYLE} style={{ width: "100%", height: "520px" }}
          layout={{ name: "cose", animate: false, padding: 30, nodeRepulsion: () => 9000, idealEdgeLength: () => 90 } as never}
          cy={(cy: Core) => { cy.removeAllListeners(); cy.on("tap", "node", (evt) => setSelected(evt.target.id())); cy.on("tap", (evt) => { if (evt.target === cy) setSelected(null); }); }} />
      </div>
      <aside className="bg-surface-container-lowest border border-outline-variant rounded-lg">
        <div className="h-10 px-3 flex items-center border-b border-outline-variant font-headline-sm text-headline-sm">
          {node ? "Entity" : "Select a node"}</div>
        {node ? (
          <div className="p-3 flex flex-col gap-2 text-body-sm">
            <div className="font-code-sm text-code-sm break-all">{node.id}</div>
            <div className="flex gap-1.5 flex-wrap">
              <span className="text-[11px] px-2 py-0.5 rounded-lg text-white" style={{ background: KIND_STYLE[node.kind].color }}>{KIND_STYLE[node.kind].label}</span>
              {node.seed && <span className="text-[11px] px-2 py-0.5 rounded-lg bg-risk-critical-fill text-risk-critical font-semibold">Confirmed fraud seed</span>}
              {node.in_case && <span className="text-[11px] px-2 py-0.5 rounded-lg bg-surface-container">In this case</span>}
            </div>
            <div className="font-label-caps text-label-caps uppercase text-on-surface-variant mt-2">Events in this case ({related.length})</div>
            {related.length === 0 && <div className="text-on-surface-variant">No case evidence touches this entity.</div>}
            {related.map((e) => (
              <button key={e.evidence_id} onClick={() => onEvidence(e.evidence_id)}
                className="text-left px-2 py-1.5 rounded-lg border border-outline-variant hover:bg-surface-container-low">
                <div className="flex items-center gap-1.5"><span className="material-symbols-outlined !text-[14px]" style={{ color: DETECTOR[e.detector].color }}>{DETECTOR[e.detector].icon}</span>
                  <span className="font-medium">{DETECTOR[e.detector].label}</span><span className="ml-auto font-code-xs text-code-xs">{istTime(e.ts)}</span></div>
                <div className="text-body-xs text-on-surface-variant">{STAGE_LABEL[e.stage]} · {e.reasons.map((r) => reasonText(r.code)).join(", ")}</div>
              </button>
            ))}
          </div>
        ) : <div className="p-3 text-body-sm text-on-surface-variant">Click a node to list the events that involve it.</div>}
      </aside>
    </div>
  );
}
