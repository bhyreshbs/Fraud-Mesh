// Step-up before sensitive actions (PRD §11.2): check GET /demo/step-up/pending?channel=app; if a challenge is pending,
// the "Verify it's you" modal collects the OTP and POSTs /respond before the action runs.
import { useState, type ReactNode } from "react";
import type { PendingChallenge } from "../types/contracts";
import { BankError, pendingChallenge, respond } from "../lib/api";
import { useIdentity } from "../lib/identity";

export function useStepUp() {
  const { identity } = useIdentity();
  const [challenge, setChallenge] = useState<PendingChallenge | null>(null);
  const [resume, setResume] = useState<(() => void) | null>(null);

  /** Runs `action` now, or after the customer passes the pending challenge. */
  async function guard(action: () => void) {
    const r = await pendingChallenge(identity.subject.customer_ref ?? "", "app");
    if (!r.challenge) { action(); return; }
    setChallenge(r.challenge);
    setResume(() => action);
  }

  const modal: ReactNode = challenge ? (
    <OtpModal challenge={challenge} onDone={(passed) => { const go = resume; setChallenge(null); setResume(null); if (passed && go) go(); }} />
  ) : null;
  return { guard, modal };
}

export function OtpModal({ challenge, onDone }: { challenge: PendingChallenge; onDone: (passed: boolean) => void }) {
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tries, setTries] = useState(0);

  async function submit() {
    setBusy(true); setMsg(null);
    try {
      const r = await respond(challenge.challenge_id, { code });
      if (r.status === "passed") { onDone(true); return; }
      if (r.status === "pending") { setTries((t) => t + 1); setMsg(`Incorrect code. ${2 - tries} attempt(s) left.`); setCode(""); }
      else setMsg(r.status === "failed" ? "Too many incorrect codes. Verification failed." : `Verification ${r.status.replace(/_/g, " ")}.`);
    } catch (e) {
      setMsg(e instanceof BankError ? e.message : "Something went wrong.");
    } finally { setBusy(false); }
  }
  const final = msg !== null && !msg.startsWith("Incorrect");

  return (
    <div className="fixed inset-0 z-50 bg-[rgba(17,24,39,0.45)] flex items-center justify-center p-4">
      <div role="dialog" aria-label="Verify it's you" data-testid="otp-modal" className="w-full max-w-sm bg-white rounded-xl border border-[#D1D5DB] shadow-xl p-6">
        <div className="w-10 h-10 rounded-full bg-[#E6F4F1] text-[#0F766E] flex items-center justify-center mb-3"><span className="material-symbols-outlined">lock</span></div>
        <h2 className="text-[18px] font-semibold">Verify it&apos;s you</h2>
        <p className="text-[13px] text-text-secondary mt-1">We sent a 6-digit code to <span className="font-mono">{challenge.masked_destination}</span>.
          It expires at {new Date(challenge.expires_at).toLocaleTimeString("en-GB", { timeZone: "Asia/Kolkata", hour: "2-digit", minute: "2-digit" })} IST.</p>
        <input autoFocus inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} disabled={final}
          data-testid="otp-input" data-telemetry="off" autoComplete="one-time-code"
          className="mt-4 w-full h-12 text-center text-[22px] tracking-[0.5em] font-mono border border-border-default rounded-lg focus:outline-none focus:border-[#0F766E]" placeholder="••••••" />
        {msg && <p className={"mt-2 text-[13px] " + (final ? "text-risk-critical" : "text-risk-high")}>{msg}</p>}
        <div className="mt-5 flex gap-2 justify-end">
          <button onClick={() => onDone(false)} className="h-9 px-4 rounded-lg border border-border-default text-[13px]">{final ? "Close" : "Cancel"}</button>
          {!final && <button disabled={code.length !== 6 || busy} onClick={submit} data-testid="otp-verify"
            className="h-9 px-4 rounded-lg bg-[#0F766E] hover:bg-[#115E59] disabled:opacity-50 text-white text-[13px] font-semibold">Verify</button>}
        </div>
      </div>
    </div>
  );
}
