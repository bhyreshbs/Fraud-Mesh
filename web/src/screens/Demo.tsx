// /demo (admin) — demo control (PRD §11.1): scenario picker, speed, Run (POST /v1/demo/run/{id}), Reset (POST /v1/demo/reset).
import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { RunResponse, StatusOk } from "../types/contracts";
import { api, ApiError } from "../lib/api";
import { useStream } from "../lib/stream";

const SCENARIOS = [
  { id: "midnight_ato", title: "Midnight account takeover", text: "Credential stuffing, new-device login, SIM/SMS swap, deepfake KYC, support-console limit raise, mule-linked payee, ₹4,80,000 transfer, then Priya taps “Not me”. 27 scenario-minutes." },
  { id: "mule_fanin", title: "Mule fan-in", text: "Twelve customers pay one mule account within two hours; the mule forwards 90% onward." },
  { id: "benign_odd", title: "Benign but odd", text: "Priya logs in on a new phone in Mumbai, approves the push on her old phone, pays a known payee. Should never exceed MEDIUM." },
];

export function Demo() {
  const qc = useQueryClient();
  const { status } = useStream();
  const [scenario, setScenario] = useState("midnight_ato");
  const [speed, setSpeed] = useState(8);
  const [log, setLog] = useState<{ at: string; text: string; kind: "ok" | "bad" }[]>([]);
  const say = (text: string, kind: "ok" | "bad" = "ok") =>
    setLog((l) => [{ at: new Date().toLocaleTimeString("en-GB", { timeZone: "Asia/Kolkata", hour12: false }), text, kind }, ...l].slice(0, 20));

  const run = useMutation({
    mutationFn: () => api<RunResponse>(`/v1/demo/run/${scenario}`, { method: "POST", body: { speed } }),
    onSuccess: (r) => say(`Started ${scenario} at speed ${speed} (${r.run_id}). Watch the case queue build live.`),
    onError: (e) => say(`Run failed: ${(e as ApiError).code} ${(e as ApiError).message}`, "bad"),
  });
  const reset = useMutation({
    mutationFn: () => api<StatusOk>("/v1/demo/reset", { method: "POST" }),
    onSuccess: () => { say("Demo reset: tables truncated, users/factors reseeded, midnight_ato preload + fraud seeds loaded."); qc.invalidateQueries(); },
    onError: (e) => say(`Reset failed: ${(e as ApiError).code} ${(e as ApiError).message}`, "bad"),
  });
  const minutes = scenario === "midnight_ato" ? 27 : scenario === "mule_fanin" ? 115 : 6;

  return (
    <div className="p-space-base flex flex-col gap-3 max-w-4xl" data-testid="demo-page">
      <div>
        <h1 className="font-headline-lg text-headline-lg tracking-tight">Demo control</h1>
        <p className="text-body-sm text-on-surface-variant">Autopilot plays a scenario into the API exactly like the real senders: signed events, and
          step-ups answered through the bank app and phone routes. Reset first for a clean run.</p>
      </div>
      <section className="bg-surface-container-lowest border border-outline-variant rounded-lg">
        <div className="h-10 px-3 flex items-center border-b border-outline-variant font-headline-sm text-headline-sm">Scenario</div>
        <div className="p-3 grid gap-2">
          {SCENARIOS.map((s) => (
            <label key={s.id} className={"flex gap-3 p-2.5 rounded-lg border cursor-pointer " + (scenario === s.id ? "border-primary-container bg-[#F0F4FE]" : "border-outline-variant")}>
              <input type="radio" name="scenario" value={s.id} checked={scenario === s.id} onChange={() => setScenario(s.id)} data-testid={`scenario-${s.id}`} />
              <span><span className="font-headline-sm text-headline-sm">{s.title}</span> <span className="font-code-xs text-code-xs text-on-surface-variant">{s.id}</span>
                <span className="block text-body-sm text-on-surface-variant">{s.text}</span></span>
            </label>
          ))}
        </div>
        <div className="px-3 pb-3 flex items-center gap-3 flex-wrap">
          <label className="text-body-sm flex items-center gap-2">Speed
            <input type="number" min={1} max={1000} step={1} value={speed} onChange={(e) => setSpeed(Math.max(1, Number(e.target.value) || 1))}
              data-testid="speed" className="w-20 h-8 px-2 border border-outline-variant rounded-lg tnum" /> ×</label>
          <span className="text-body-xs text-on-surface-variant">≈ {(minutes / speed).toFixed(1)} wall-clock minutes for {minutes} scenario-minutes</span>
          <div className="ml-auto flex gap-2">
            <button onClick={() => { if (confirm("Reset the demo? This truncates all runtime data.")) reset.mutate(); }} disabled={reset.isPending}
              data-testid="reset" className="h-8 px-3 rounded-lg border border-risk-critical-border bg-risk-critical-fill text-risk-critical text-body-sm font-semibold disabled:opacity-50">
              {reset.isPending ? "Resetting…" : "Reset demo"}</button>
            <button onClick={() => run.mutate()} disabled={run.isPending || reset.isPending} data-testid="run"
              className="h-8 px-4 rounded-lg bg-primary-container hover:bg-primary text-on-primary text-body-sm font-semibold disabled:opacity-50 flex items-center gap-1">
              <span className="material-symbols-outlined !text-[16px]">play_arrow</span>Run scenario</button>
          </div>
        </div>
      </section>
      <div className="text-body-sm text-on-surface-variant">Live stream: <span className="font-medium">{status}</span> ·{" "}
        <Link to="/queue" className="text-primary-container hover:underline">open the case queue</Link></div>
      {log.length > 0 && (
        <ul className="bg-surface-container-lowest border border-outline-variant rounded-lg divide-y divide-outline-variant" data-testid="demo-log">
          {log.map((l, i) => (
            <li key={i} className={"px-3 py-2 text-body-sm " + (l.kind === "bad" ? "text-risk-critical" : "")}>
              <span className="font-code-xs text-code-xs text-on-surface-variant mr-2">{l.at}</span>{l.text}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
