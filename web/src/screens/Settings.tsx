// /settings — Stitch "Settings", read-only and real: GET /v1/engine/config (thresholds, policy.yaml, patterns.yaml, model
// manifest, twin forecast), the signed-in session and live service health. Nothing here pretends to be editable: policy
// and patterns are reviewed files and the model is SHA-256-pinned, so changes go through code review, not a toggle.
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import type { Health } from "../types/contracts";
import { api, API_BASE } from "../lib/api";
import { useAuth } from "../lib/auth";
import { ACTION_LABEL, STAGE_LABEL } from "../lib/labels";
import { useEngineConfig } from "../lib/queries";
import { PageHeader, Panel } from "../components/ui";

type Section = "account" | "policy" | "models" | "security" | "services";
const SECTIONS: { id: Section; icon: string; title: string; sub: string }[] = [
  { id: "account", icon: "account_circle", title: "General & account", sub: "Session, role and queues" },
  { id: "policy", icon: "tune", title: "Detection & policy", sub: "Bands, policy.yaml, patterns" },
  { id: "models", icon: "model_training", title: "Models", sub: "Artifacts, training data, metrics" },
  { id: "security", icon: "shield_lock", title: "Security & audit", sub: "Auth, signing, rate limits" },
  { id: "services", icon: "lan", title: "Connected services", sub: "API, database, stream" },
];

function KV({ k, v }: { k: string; v: React.ReactNode }) {
  return <div className="flex items-center justify-between gap-4 py-2.5 border-t border-taupe/20 first:border-0">
    <span className="text-body-sm text-on-surface-variant">{k}</span><span className="font-mono text-[13px] text-right">{v}</span></div>;
}

export function Settings() {
  const { session } = useAuth();
  const cfg = useEngineConfig();
  const health = useQuery({ queryKey: ["health"], queryFn: () => api<Health>("/v1/health") });
  const [sec, setSec] = useState<Section>("policy");
  const c = cfg.data;

  return (
    <div className="px-8 py-7 flex flex-col gap-7" data-testid="settings">
      <PageHeader meta={<><span className="w-1.5 h-1.5 rounded-full bg-risk-low" />read-only view of the live engine</>} title="Settings"
        subtitle="Thresholds, policy, models and services as the engine runs them now."
        actions={<div className="fm-card-sm px-4 py-2.5 flex items-center gap-3"><span className="material-symbols-outlined text-primary-container">policy</span>
          <div><div className="font-mono text-[11px] text-on-surface-variant">CONTRACT</div><div className="font-mono text-[13px] font-semibold">v{c?.contract_version ?? "—"}</div></div></div>} />
      <div className="grid grid-cols-[320px_1fr] gap-6 items-start">
        <div className="flex flex-col gap-6">
          <div className="fm-card p-3 flex flex-col gap-1">
            {SECTIONS.map((s) => (
              <button key={s.id} onClick={() => setSec(s.id)} data-testid={`settings-${s.id}`}
                className={"flex items-center gap-3 px-3 py-3 rounded-xl text-left transition-all " + (sec === s.id ? "fm-tint" : "hover:bg-surface-container-low")}>
                <span className={"w-10 h-10 rounded-xl flex items-center justify-center shadow-porcelain-sm " + (sec === s.id ? "bg-primary-container text-on-primary" : "bg-porcelain text-on-surface-variant")}>
                  <span className="material-symbols-outlined">{s.icon}</span></span>
                <span><span className="block font-semibold">{s.title}</span><span className="block font-mono text-[11.5px] text-on-surface-variant">{s.sub}</span></span>
              </button>
            ))}
          </div>
          <div className="fm-card p-5">
            <div className="font-mono text-[11px] tracking-[0.1em] text-on-surface-variant">AUTONOMOUS GUARD · <span className="text-risk-low">ENFORCING</span></div>
            <div className="mt-3 text-body-sm">Payments are held at <b>HIGH</b> and blocked at <b>CRITICAL</b>; every decision is written to the hash-chained audit log.</div>
          </div>
        </div>

        {sec === "account" && (
          <Panel title="General & account" subtitle="The signed-in session">
            <div className="px-6 pb-6">
              <KV k="User" v={session?.userId} /><KV k="Role" v={session?.role} />
              <KV k="Access token" v="JWT, 15 min, renewed with a rotating HttpOnly refresh cookie" />
              <KV k="Queues" v="default" /><KV k="Timezone" v="Asia/Kolkata (IST)" />
            </div>
          </Panel>
        )}

        {sec === "policy" && c && (
          <div className="flex flex-col gap-6">
            <Panel title="Risk bands" subtitle={`Fused attack probability thresholds · base rate π = ${c.base_rate}`} testid="bands">
              <div className="px-6 pb-6 flex flex-col gap-4">
                <div className="relative h-3 rounded-full overflow-hidden flex">
                  <div className="h-full bg-risk-low" style={{ width: `${c.thresholds.medium * 100}%` }} />
                  <div className="h-full bg-[#DE9A2B]" style={{ width: `${(c.thresholds.high - c.thresholds.medium) * 100}%` }} />
                  <div className="h-full bg-primary-container" style={{ width: `${(c.thresholds.critical - c.thresholds.high) * 100}%` }} />
                  <div className="h-full bg-risk-critical flex-1" />
                </div>
                <div className="grid grid-cols-4 gap-3 font-mono text-[12px]">
                  <span>LOW &lt; {c.thresholds.medium}</span><span>MEDIUM ≥ {c.thresholds.medium}</span><span>HIGH ≥ {c.thresholds.high}</span><span>CRITICAL ≥ {c.thresholds.critical}</span>
                </div>
                <div className="text-body-xs text-on-surface-variant">Try other thresholds safely in Metrics &amp; Analytics → Policy simulator, or per case in the Digital Twin.</div>
              </div>
            </Panel>
            <Panel title="Autonomous mitigation rules" subtitle="engine/policy/policy.yaml: evaluated top to bottom, first match wins" testid="policy-rules">
              <div className="px-6 pb-6 flex flex-col gap-3">
                {c.policy_rules.map((r) => (
                  <div key={r.id} className="fm-tint px-4 py-3 flex items-start gap-4">
                    <span className="font-mono text-[12px] font-semibold text-primary w-36 shrink-0">{r.id}</span>
                    <div className="flex-1">
                      <div className="text-body-sm text-on-surface-variant">when band = <b className="text-on-surface">{r.band ?? "any"}</b>
                        {r.reason_any.length > 0 && <> and reason in <span className="font-mono">{r.reason_any.join(", ")}</span></>}</div>
                      <div className="flex flex-wrap gap-1.5 mt-1.5">{r.actions.map((a) => <span key={a} className="fm-pill">{ACTION_LABEL[a as keyof typeof ACTION_LABEL] ?? a}</span>)}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
            <Panel title="Sequence patterns" subtitle="engine/fusion/patterns.yaml: each matches at most once per case and adds its bonus">
              <div className="px-6 pb-6 flex flex-col gap-3">
                {c.patterns.map((p) => (
                  <div key={p.id} className="fm-tint px-4 py-3">
                    <div className="flex items-center justify-between"><span className="font-semibold">{p.label}</span><span className="font-mono text-primary-container">+{p.bonus} log-odds</span></div>
                    <div className="font-mono text-[11.5px] text-on-surface-variant mt-1">{p.id} · {p.sequence.length ? p.sequence.map((s) => STAGE_LABEL[s as keyof typeof STAGE_LABEL] ?? s).join(" → ") : `${p.when_detector} sharing a ${p.shared_kind}`}
                      {p.within_min ? ` within ${p.within_min} min` : ""}</div>
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        )}

        {sec === "models" && c && (
          <div className="flex flex-col gap-6">
            {c.models.map((m) => (
              <Panel key={m.file} title={m.file} subtitle={`${m.model} · sha256 ${m.sha256.slice(0, 16)}…`}>
                <div className="px-6 pb-6">
                  <KV k="Headline test (bank events)" v={`PR-AUC ${m.pr_auc} · ROC-AUC ${m.roc_auc} · ECE ${m.ece}`} />
                  {m.training_data && <KV k="Training data" v={m.training_data.join(" + ")} />}
                  {m.split && <KV k="Split" v={m.split} />}
                  {m.per_domain && Object.entries(m.per_domain).map(([d, x]) => <KV key={d} k={`Test: ${d}`} v={`ROC ${x.roc_auc} · PR ${x.pr_auc} · ${x.n.toLocaleString("en-IN")} rows`} />)}
                  <KV k="Features" v={m.features.length} />
                </div>
              </Panel>
            ))}
            <Panel title="Digital twin forecast" subtitle="ml/artifacts/twin_transitions.json">
              <div className="px-6 pb-6"><KV k="Learned from" v={`${c.twin_forecast.attacks} labelled attacks (${c.twin_forecast.source ?? "—"})`} /></div>
            </Panel>
          </div>
        )}

        {sec === "security" && (
          <Panel title="Security & audit logging" subtitle="Controls enforced by the API on every request">
            <div className="px-6 pb-6">
              <KV k="Event ingestion" v="HMAC-SHA256 signed (X-FM-Source / Timestamp / Signature); tampered → 401" />
              <KV k="Personal data" v="phone, email, IP, device and account stored only as HMAC tokens" />
              <KV k="Passwords" v="Argon2id" /><KV k="Login rate limit" v="5 / min per IP" /><KV k="Ingestion rate limit" v="100 / s per source" />
              <KV k="Audit log" v="hash-chained; the app role can only INSERT and SELECT it" />
              <KV k="Investigator AI" v="fixed tools + templates; every sentence must cite real evidence IDs" />
            </div>
          </Panel>
        )}

        {sec === "services" && (
          <Panel title="Connected services & endpoints" subtitle="Live status from GET /v1/health">
            <div className="px-6 pb-6 grid grid-cols-2 gap-4">
              {[["FastAPI", API_BASE, true], ["PostgreSQL 16", "events, cases, evidence, audit", !!health.data?.db],
                ["Engine pipeline", "graph · features · 7 detectors · fusion · policy", !!health.data?.pipeline_ready],
                ["WebSocket stream", API_BASE.replace(/^http/, "ws") + "/v1/stream", true]].map(([name, where, ok]) => (
                <div key={name as string} className="fm-tint p-4">
                  <div className="flex items-center gap-2 font-semibold"><span className={"w-2 h-2 rounded-full " + (ok ? "bg-risk-low" : "bg-risk-critical")} />{name}</div>
                  <div className="fm-sunken px-3 py-2 mt-2 font-mono text-[12px] truncate">{where as string}</div>
                </div>
              ))}
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}
