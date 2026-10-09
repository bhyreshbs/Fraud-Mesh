// Footer feedback bar (POST /feedback) and the lead-only manual action dialog (POST /actions) — PRD §11.1.
import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { Action, Decision, FeedbackResult, Verdict } from "../types/contracts";
import { api, ApiError } from "../lib/api";
import { ACTION_LABEL } from "../lib/labels";

export function FeedbackBar({ caseId }: { caseId: string }) {
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  const m = useMutation({
    mutationFn: (verdict: Verdict) => api<FeedbackResult>(`/v1/cases/${caseId}/feedback`, { method: "POST", body: { verdict, note: note || null } }),
    onSuccess: () => { for (const k of ["case", "timeline", "cases", "detectors"]) qc.invalidateQueries({ queryKey: k === "cases" || k === "detectors" ? [k] : [k, caseId] }); },
  });
  const changed = m.data ? Object.keys(m.data.reliability_after).filter((d) => Math.abs(m.data!.reliability_after[d] - (m.data!.reliability_before[d] ?? 0)) > 1e-9) : [];
  return (
    <div className="sticky bottom-4 z-30 mx-8 mb-4 fm-glass rounded-2xl px-5 py-3 flex items-center gap-3">
      <span className="font-label-caps text-label-caps uppercase text-on-surface-variant">Analyst verdict</span>
      <input value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} placeholder="Note for the audit trail (optional)"
        className="flex-1 h-10 px-3 text-body-sm" />
      {m.isSuccess && <span className="text-body-xs text-risk-low">Saved: {m.data.verdict.replace("_", " ").toLowerCase()} · status {m.data.status_after}{changed.length ? ` · reliability updated: ${changed.join(", ")}` : ""}</span>}
      {m.isError && <span className="text-body-xs text-risk-critical">{(m.error as ApiError).message}</span>}
      <button disabled={m.isPending} onClick={() => m.mutate("INCONCLUSIVE")} className="fm-btn">Inconclusive</button>
      <button disabled={m.isPending} onClick={() => m.mutate("FALSE_POSITIVE")} className="fm-btn !text-risk-low">False positive</button>
      <button disabled={m.isPending} onClick={() => m.mutate("CONFIRMED_FRAUD")} className="fm-btn-primary !bg-risk-critical">Confirm fraud</button>
    </div>
  );
}

const MANUAL: Action[] = ["HOLD_OUTBOUND_PAYMENTS", "BLOCK_PENDING_PAYMENTS", "FREEZE_NEW_PAYEES", "REVOKE_SESSIONS", "STEP_UP_TRUSTED_FACTOR", "ALLOW"];

export function ManualActionDialog({ caseId, onClose }: { caseId: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [picked, setPicked] = useState<Action[]>([]);
  const [reason, setReason] = useState("");
  const m = useMutation({
    mutationFn: () => api<Decision>(`/v1/cases/${caseId}/actions`, { method: "POST", body: { actions: picked, reason } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["case", caseId] }); qc.invalidateQueries({ queryKey: ["timeline", caseId] }); onClose(); },
  });
  return (
    <div className="fixed inset-0 z-[60] bg-[rgba(17,24,39,0.4)] flex items-center justify-center" onClick={onClose}>
      <div role="dialog" aria-label="Manual action" onClick={(e) => e.stopPropagation()}
        className="w-[440px] bg-white border border-[#D1D5DB] rounded-lg shadow-[0_12px_16px_-4px_rgba(16,24,40,0.08)]">
        <div className="h-11 px-4 flex items-center justify-between border-b border-outline-variant">
          <span className="font-headline-sm text-headline-sm">Manual action (lead)</span>
          <button onClick={onClose} className="material-symbols-outlined text-on-surface-variant">close</button>
        </div>
        <div className="p-4 flex flex-col gap-3">
          <div className="grid grid-cols-2 gap-1.5">
            {MANUAL.map((a) => (
              <label key={a} className="flex items-center gap-2 text-body-sm cursor-pointer">
                <input type="checkbox" checked={picked.includes(a)} onChange={() => setPicked((p) => p.includes(a) ? p.filter((x) => x !== a) : [...p, a])} />
                {ACTION_LABEL[a]}
              </label>
            ))}
          </div>
          <label className="text-body-sm font-medium">Reason (required, written to the audit log)
            <textarea value={reason} onChange={(e) => setReason(e.target.value)} maxLength={1000} rows={3}
              className="mt-1 w-full px-3 py-2 text-body-sm border border-outline-variant rounded-lg focus:outline-none focus:border-brand" /></label>
          {m.isError && <div className="text-body-sm text-risk-critical">{(m.error as ApiError).code}: {(m.error as ApiError).message}</div>}
        </div>
        <div className="px-4 py-3 border-t border-outline-variant flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 rounded-lg border border-outline-variant text-body-sm">Cancel</button>
          <button disabled={!picked.length || !reason.trim() || m.isPending} onClick={() => m.mutate()}
            className="h-8 px-3 rounded-lg bg-primary-container hover:bg-primary disabled:opacity-50 text-on-primary text-body-sm font-semibold">Apply</button>
        </div>
      </div>
    </div>
  );
}
