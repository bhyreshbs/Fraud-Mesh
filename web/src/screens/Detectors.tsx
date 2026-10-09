// /detectors — Stitch "Detection Engine": the seven detectors as cards (reliability = Beta(α, β) mean, updated by analyst
// feedback), a selected-detector deep dive (models: per-dataset held-out metrics from ml/artifacts/manifest.json; rules:
// reason codes) and the latest escalated cases. Data: /v1/detectors, /v1/engine/config, /v1/cases.
import { useState } from "react";
import { Link } from "react-router-dom";
import type { DetectorId } from "../types/contracts";
import type { ModelArtifact } from "../types/twin";
import { ApiError } from "../lib/api";
import { inr, istTime, pct, shortCaseId } from "../lib/format";
import { attackVector, DETECTOR, reasonText } from "../lib/labels";
import { useCases, useDetectors, useEngineConfig, useMetrics } from "../lib/queries";
import { BandPill } from "../components/Risk";
import { Kpi, PageHeader, Panel, SegTabs } from "../components/ui";

type Kind = "model" | "graph" | "rules";
const INFO: Record<DetectorId, { kind: Kind; stage: string; what: string; reasons: string[]; artifact?: string }> = {
  txn: { kind: "model", stage: "S6 Monetization", artifact: "txn_v1.joblib",
    what: "LightGBM on 11 transaction features (amount vs usual, new payee, payee fan-in, near-limit transfers…), isotonic-calibrated, SHAP reasons.",
    reasons: ["AMOUNT_HIGH_VS_MEDIAN", "NEW_PAYEE", "PAYEE_FAN_IN", "STRUCTURING"] },
  behaviour: { kind: "model", stage: "S1 Initial access", artifact: "behaviour_v1.joblib",
    what: "Logistic regression on login behaviour: new device, new network (ASN), distance from home, unusual hour, failed logins.",
    reasons: ["NEW_DEVICE", "NEW_ASN", "FAR_FROM_HOME", "ODD_HOUR", "IMPOSSIBLE_TRAVEL", "COLD_START"] },
  graph: { kind: "graph", stage: "S5 Positioning",
    what: "Entity graph: payee distance to confirmed mule devices / accounts, mule flow (fan-in, pass-through) and payee-name mismatch.",
    reasons: ["SEED_DISTANCE_1", "SEED_DISTANCE_2", "MULE_FLOW", "PAYEE_NAME_MISMATCH"] },
  auth: { kind: "rules", stage: "S2 Control takeover",
    what: "MFA / profile / SIM changes after a new device, MFA fail-then-pass, push spam, recent SIM swap, step-up results, \"Not me\".",
    reasons: ["MFA_CHANGED_AFTER_NEW_DEVICE", "PROFILE_CHANGE_AFTER_NEW_DEVICE", "MFA_FAIL_THEN_PASS", "PUSH_SPAM", "RECENT_SIM_SWAP", "CUSTOMER_DENIED"] },
  kyc: { kind: "rules", stage: "S3 Identity manipulation", what: "Re-KYC results: weak liveness, low face match, document tampering, injection.",
    reasons: ["LOW_LIVENESS", "LOW_FACE_MATCH", "DOC_TAMPER", "INJECTION_SUSPECTED"] },
  cyber: { kind: "rules", stage: "S4 Escalation", what: "Sigma-style rules over cloud / support-console audit logs: limit raises and MFA resets from untrusted IPs, bulk profile reads.",
    reasons: ["cloud_limit_raise_untrusted_ip", "mfa_reset_by_support_untrusted_ip", "bulk_profile_read_support_console"] },
  netsec: { kind: "rules", stage: "S0 Recon", what: "Suricata IDS alerts by severity, and credential stuffing across customers from one IP.",
    reasons: ["IDS_SEV1", "IDS_SEV2", "IDS_SEV3", "CREDENTIAL_STUFFING_IP"] },
};
const DOMAIN_LABEL: Record<string, string> = { synthetic: "Bank events (synthetic)", ieee_cis: "IEEE-CIS real card fraud", amlsim: "IBM AMLSim laundering" };

function ModelDetail({ m }: { m: ModelArtifact }) {
  const domains = m.per_domain ? Object.entries(m.per_domain) : [["test", { pr_auc: m.pr_auc, roc_auc: m.roc_auc, ece: m.ece, n: m.rows?.test ?? 0, positives: m.test_positives ?? 0 }]] as const;
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-3 gap-3">
        {domains.map(([name, d]) => (
          <div key={name} className="fm-tint p-4">
            <div className="font-mono text-[11px] uppercase tracking-[0.08em] text-on-surface-variant">{DOMAIN_LABEL[name] ?? name}</div>
            <div className="flex items-baseline gap-4 mt-1">
              <div><div className="text-[24px] font-semibold tnum">{d.roc_auc != null ? d.roc_auc.toFixed(3) : "—"}</div><div className="font-mono text-[11px] text-on-surface-variant">ROC-AUC</div></div>
              <div><div className="text-[24px] font-semibold tnum text-primary-container">{d.pr_auc != null ? d.pr_auc.toFixed(3) : "—"}</div><div className="font-mono text-[11px] text-on-surface-variant">PR-AUC</div></div>
            </div>
            <div className="font-mono text-[11px] text-on-surface-variant mt-1">{d.n.toLocaleString("en-IN")} test rows · {d.positives.toLocaleString("en-IN")} fraud · ECE {d.ece}</div>
          </div>
        ))}
      </div>
      <div className="text-body-sm text-on-surface-variant">
        <b className="text-on-surface">{m.model}</b> · {m.best_iteration ? `${m.best_iteration} trees · ` : ""}split {m.split ?? "by time"} ·
        sha256 <span className="font-mono">{m.sha256.slice(0, 12)}</span>{m.training_data && <> · trained on {m.training_data.join(" + ")}</>}
      </div>
      <div className="flex flex-wrap gap-1.5">{m.features.map((f) => (
        <span key={f} className="fm-pill">{f}{m.coefficients?.[f] != null && <span className="text-primary-container">{m.coefficients[f] > 0 ? "+" : ""}{m.coefficients[f].toFixed(2)}</span>}</span>))}</div>
    </div>
  );
}

export function Detectors() {
  const q = useDetectors();
  const cfg = useEngineConfig();
  const metrics = useMetrics();
  const cases = useCases();
  const [kind, setKind] = useState<"all" | Kind>("all");
  const [selected, setSelected] = useState<DetectorId>("txn");
  const dets = (q.data ?? []).filter((d) => kind === "all" || INFO[d.detector].kind === kind);
  const sel = (q.data ?? []).find((d) => d.detector === selected);
  const model = INFO[selected].artifact ? cfg.data?.models.find((m) => m.file === INFO[selected].artifact) : undefined;
  const txn = cfg.data?.models.find((m) => m.file === "txn_v1.joblib");
  const bench = metrics.data?.benchmark;
  const recent = (cases.data?.items ?? []).filter((c) => c.band === "CRITICAL" || c.band === "HIGH")
    .sort((a, b) => b.updated_at.localeCompare(a.updated_at)).slice(0, 6);

  return (
    <div className="px-8 py-7 flex flex-col gap-7" data-testid="detection-engine">
      <PageHeader eyebrow="Mesh core inference" meta={<>contract {cfg.data?.contract_version ?? "—"} · base rate {cfg.data?.base_rate ?? "—"}</>}
        title="Detection Engine" subtitle="Seven specialised detectors, each scoring its own silo; fusion weighs them by learned reliability." />
      {q.isError && <div className="text-risk-critical text-body-sm">{(q.error as ApiError).message}</div>}
      <div className="grid grid-cols-4 gap-6">
        <Kpi label="Operational detectors" value={`${(q.data ?? []).length} / 7`} icon="hub" sub="all scoring every event they handle" />
        <Kpi label="Txn model on bank events" value={txn ? txn.roc_auc.toFixed(3) : "—"} unit="ROC" icon="speed" tone="low"
          sub={txn ? `PR-AUC ${txn.pr_auc.toFixed(4)} on the held-out days` : ""} />
        <Kpi label="On real-world data" value={txn?.per_domain?.ieee_cis?.roc_auc?.toFixed(3) ?? "—"} unit="ROC" icon="public" tone="high"
          sub={txn?.per_domain ? `IEEE-CIS card fraud · AMLSim ${txn.per_domain.amlsim?.roc_auc?.toFixed(3)}` : "single-dataset model"} />
        <Kpi label="False-positive rate" value={bench ? pct(bench.false_positive_rate, 2) : "—"} icon="verified_user" tone="low"
          sub={bench ? `${bench.benign_flagged_high} of ${bench.benign_customers} genuine customers flagged HIGH` : ""} />
      </div>

      <div className="flex items-center justify-between">
        <SegTabs value={kind} onChange={setKind} options={[
          { value: "all", label: `All detectors (${(q.data ?? []).length})` }, { value: "model", label: "ML models (2)" },
          { value: "graph", label: "Graph intelligence (1)" }, { value: "rules", label: "Rules & heuristics (4)" }]} />
      </div>

      <div className="grid grid-cols-4 gap-5" data-testid="detectors-table">
        {dets.map((d) => {
          const info = INFO[d.detector], on = d.detector === selected;
          return (
            <button key={d.detector} onClick={() => setSelected(d.detector)}
              className={"text-left p-5 rounded-[1.25rem] transition-all flex flex-col gap-3 " + (on ? "fm-card ring-2 ring-primary-container/50" : "fm-card-sm hover:shadow-porcelain")}>
              <div className="flex items-center justify-between">
                <span className="fm-pill"><span className="w-1.5 h-1.5 rounded-full bg-primary-container" />{info.kind === "model" ? "Model" : info.kind === "graph" ? "Graph" : "Rules"} · active</span>
                <span className="font-mono text-[11px] text-on-surface-variant">{info.stage.split(" ")[0]}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined !text-[22px]" style={{ color: DETECTOR[d.detector].color }}>{DETECTOR[d.detector].icon}</span>
                <span className={"text-[18px] font-semibold " + (on ? "text-primary-container" : "")}>{DETECTOR[d.detector].label}</span>
              </div>
              <p className="text-body-sm text-on-surface-variant line-clamp-2 min-h-[40px]">{info.what}</p>
              <div className="grid grid-cols-2 gap-2">
                <div className="fm-sunken px-3 py-2"><div className="font-mono text-[10.5px] uppercase text-on-surface-variant">Reliability</div><div className="font-mono font-semibold">{pct(d.reliability)}</div></div>
                <div className="fm-sunken px-3 py-2"><div className="font-mono text-[10.5px] uppercase text-on-surface-variant">α / β</div><div className="font-mono font-semibold">{d.alpha.toFixed(0)} / {d.beta.toFixed(0)}</div></div>
              </div>
              <div className="h-1.5 rounded-full bg-surface-container overflow-hidden"><div className="h-full bg-primary-container" style={{ width: `${d.reliability * 100}%` }} /></div>
            </button>
          );
        })}
      </div>

      {sel && (
        <Panel title={<span className="flex items-center gap-2"><span className="material-symbols-outlined" style={{ color: DETECTOR[sel.detector].color }}>{DETECTOR[sel.detector].icon}</span>
          {DETECTOR[sel.detector].label}</span>} subtitle={`${INFO[sel.detector].stage} · family ${sel.family}`}
          right={<span className="fm-pill">reliability {pct(sel.reliability)} · Beta({sel.alpha.toFixed(1)}, {sel.beta.toFixed(1)})</span>} testid="detector-detail">
          <div className="px-6 pb-6 flex flex-col gap-4">
            <p className="text-body-md">{INFO[sel.detector].what}</p>
            {model ? <ModelDetail m={model} /> : (
              <div className="flex flex-wrap gap-2">{INFO[sel.detector].reasons.map((r) => (
                <span key={r} className="fm-tint px-3 py-2 text-body-sm"><span className="font-mono text-[12px] text-primary">{r}</span> · {reasonText(r)}</span>))}</div>
            )}
          </div>
        </Panel>
      )}

      <Panel title="Recently escalated cases" subtitle="Latest HIGH and CRITICAL cases built from these detectors' evidence"
        right={<Link to="/queue" className="fm-btn !h-9">Open queue</Link>}>
        <table className="w-full text-body-sm">
          <thead><tr className="font-mono text-[11px] tracking-[0.08em] uppercase text-on-surface-variant bg-surface-container-low/70">
            <th className="pl-6 py-3 text-left">Case</th><th className="px-3 text-left">Attack vector</th><th className="px-3 text-left">Risk</th>
            <th className="px-3 text-right">Exposure</th><th className="px-3 text-left">State</th><th className="pr-6 text-right">Updated</th></tr></thead>
          <tbody>{recent.map((c) => (
            <tr key={c.case_id} className="fm-row border-t border-taupe/20 h-14">
              <td className="pl-6"><Link className="font-mono font-semibold text-primary-container hover:underline" to={`/cases/${c.case_id}`}>{shortCaseId(c.case_id)}</Link></td>
              <td className="px-3">{attackVector(c.stages_reached).label}</td><td className="px-3"><BandPill band={c.band} /></td>
              <td className="px-3 text-right font-mono">{c.amount_at_risk_paise ? inr(c.amount_at_risk_paise) : "—"}</td>
              <td className="px-3"><span className="fm-pill uppercase">{c.payment_state === "normal" ? "monitoring" : c.payment_state}</span></td>
              <td className="pr-6 text-right font-mono text-on-surface-variant">{istTime(c.updated_at)}</td>
            </tr>))}</tbody>
        </table>
      </Panel>
    </div>
  );
}
