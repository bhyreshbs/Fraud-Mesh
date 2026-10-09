// /demo-panel — Demo side panel (Simulation & system): a single Reset button. Its action is intentionally not wired yet;
// what it resets will be defined next (it must not call POST /v1/demo/reset until then).
import { useState } from "react";
import { PageHeader, Panel } from "../components/ui";

export function DemoPanel() {
  const [clicked, setClicked] = useState(false);
  return (
    <div className="px-8 py-7 flex flex-col gap-7" data-testid="demo-panel">
      <PageHeader eyebrow="Demo" title="Demo" subtitle="Demo controls." />
      <Panel title="Reset" subtitle="Reset action to be configured.">
        <div className="px-6 pb-6 flex items-center gap-4">
          <button onClick={() => setClicked(true)} data-testid="demo-panel-reset" className="fm-btn-primary">
            <span className="material-symbols-outlined !text-[18px]">restart_alt</span>Reset
          </button>
          {clicked && <span className="text-body-sm text-on-surface-variant" data-testid="demo-panel-note">
            The Reset action is not configured yet. Nothing was changed.</span>}
        </div>
      </Panel>
    </div>
  );
}
