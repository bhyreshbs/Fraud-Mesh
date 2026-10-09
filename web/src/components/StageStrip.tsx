// Stage strip (PRD §11.1): seven boxes S0–S6, filled with time and evidence chip when reached; animates as stages arrive.
import { useEffect, useRef, useState } from "react";
import { STAGE_ORDER, type Case } from "../types/contracts";
import { STAGE_LABEL } from "../lib/labels";
import { istTime } from "../lib/format";

export function StageStrip({ c, onEvidence }: { c: Case; onEvidence?: (evidenceId: string) => void }) {
  const seen = useRef<Set<string> | null>(null);
  const [arrived, setArrived] = useState<Set<string>>(new Set());
  useEffect(() => {
    const now = new Set(Object.keys(c.stages));
    if (seen.current) {
      const fresh = [...now].filter((s) => !seen.current!.has(s));
      if (fresh.length) {
        setArrived(new Set(fresh));
        setTimeout(() => setArrived(new Set()), 1600);
      }
    }
    seen.current = now;
  }, [c.stages]);

  const reached = STAGE_ORDER.filter((s) => c.stages[s]).length;
  return (
    <section className="bg-surface-container-lowest border border-outline-variant rounded-lg">
      <div className="h-10 px-3 flex items-center justify-between border-b border-outline-variant">
        <span className="font-headline-sm text-headline-sm">Attack stages</span>
        <span className="font-label-caps text-label-caps uppercase text-on-surface-variant">{reached} of 7 reached</span>
      </div>
      <div className="grid grid-cols-7 gap-0" data-testid="stage-strip">
        {STAGE_ORDER.map((s, i) => {
          const hit = c.stages[s];
          return (
            <div key={s} className={"px-3 py-3 border-r last:border-r-0 border-outline-variant transition-colors duration-700 " +
              (hit ? "bg-[#FCE5D3]" : "") + (arrived.has(s) ? " !bg-primary-fixed" : "")}>
              <div className="flex items-center gap-2 mb-1">
                <span className={"w-6 h-6 rounded-full flex items-center justify-center text-[12px] font-semibold font-mono transition-all duration-500 " +
                  (hit ? "bg-primary-container text-on-primary" : "border border-outline-variant text-on-surface-variant") +
                  (arrived.has(s) ? " scale-125" : "")}>{i}</span>
                <span className={"text-[12px] font-semibold " + (hit ? "text-on-surface" : "text-on-surface-variant")}>{STAGE_LABEL[s]}</span>
              </div>
              {hit ? (
                <div className="flex flex-col gap-1">
                  <span className="font-code-xs text-code-xs text-on-surface tnum">{istTime(hit.ts, true)} IST</span>
                  <button onClick={() => onEvidence?.(hit.evidence_id)} title="Show in timeline"
                    className="self-start font-code-xs text-[10px] px-1.5 py-0.5 rounded-lg bg-surface-container text-primary-container hover:underline truncate max-w-full">
                    {hit.evidence_id}
                  </button>
                </div>
              ) : <span className="text-body-xs text-on-surface-variant/70">not reached</span>}
            </div>
          );
        })}
      </div>
    </section>
  );
}
