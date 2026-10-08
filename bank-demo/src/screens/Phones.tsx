// The two simulated phones (PRD §11.2):
//   /phone/attacker — the attacker's phone after the SIM/number swap; polls the demo SMS inbox every second
//   /phone/priya    — Priya's registered phone; polls for push challenges (channel=phone) and answers Approve / Not me
import { useEffect, useState, type ReactNode } from "react";
import type { PendingChallenge, SmsMessage } from "../types/contracts";
import { BankError, pendingChallenge, respond, smsInbox } from "../lib/api";

const ATTACKER_PHONE = "+919000011111";
const PRIYA_PHONE = "+919845000000";

function usePoll<T>(fn: () => Promise<T>, ms = 1000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    const tick = () => fn().then((d) => { if (alive) { setData(d); setError(null); } })
      .catch((e) => { if (alive) setError(e instanceof BankError ? e.message : String(e)); });
    tick();
    const t = setInterval(tick, ms);
    return () => { alive = false; clearInterval(t); };
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps
  return { data, error };
}

function Phone({ owner, number, children, error }: { owner: string; number: string; children: ReactNode; error: string | null }) {
  const now = new Date().toLocaleTimeString("en-GB", { timeZone: "Asia/Kolkata", hour: "2-digit", minute: "2-digit" });
  return (
    <div className="min-h-screen bg-[#1F2937] flex flex-col items-center justify-center gap-3 p-6">
      <div className="text-[#9CA3AF] text-[12px]">Simulated phone · {owner}</div>
      <div className="w-[340px] h-[680px] rounded-[44px] bg-black p-3 shadow-2xl">
        <div className="w-full h-full rounded-[34px] bg-[#F3F4F6] overflow-hidden flex flex-col">
          <div className="h-9 px-6 flex items-center justify-between text-[12px] font-semibold"><span>{now}</span>
            <span className="flex items-center gap-1"><span className="material-symbols-outlined !text-[14px]">signal_cellular_alt</span>
              <span className="material-symbols-outlined !text-[14px]">battery_5_bar</span></span></div>
          <div className="px-4 pb-2 text-[11px] text-text-tertiary font-mono">{number}</div>
          {error && <div className="mx-3 mb-2 px-2 py-1 rounded bg-risk-critical-fill text-risk-critical text-[11px]">{error}</div>}
          <div className="flex-1 overflow-y-auto px-3 pb-4">{children}</div>
        </div>
      </div>
    </div>
  );
}

export function AttackerPhone() {
  const { data, error } = usePoll(() => smsInbox(ATTACKER_PHONE));
  const msgs: SmsMessage[] = [...(data?.messages ?? [])].reverse();
  return (
    <Phone owner="the attacker (number swapped onto their SIM)" number="+91 90000 11111" error={error}>
      <div className="text-[18px] font-semibold px-1 mb-2">Messages</div>
      {msgs.length === 0 && <div className="text-[13px] text-text-tertiary px-1" data-testid="sms-empty">No messages yet. OTPs sent to +91 90000 11111 appear here.</div>}
      <ul className="flex flex-col gap-2" data-testid="sms-list">
        {msgs.map((m, i) => {
          const code = m.text.match(/\b\d{6}\b/)?.[0];
          return (
            <li key={i} className="bg-white rounded-2xl px-3 py-2 shadow-sm">
              <div className="flex justify-between text-[11px] text-text-tertiary"><span className="font-semibold text-text-secondary">NAMMABK</span>
                <span>{new Date(m.at).toLocaleTimeString("en-GB", { timeZone: "Asia/Kolkata", hour12: false })}</span></div>
              <div className="text-[13px] mt-0.5">{m.text}</div>
              {code && <div className="mt-1 font-mono text-[22px] font-semibold tracking-widest text-[#0F766E]" data-testid="sms-code">{code}</div>}
            </li>
          );
        })}
      </ul>
    </Phone>
  );
}

export function PriyaPhone() {
  const { data, error } = usePoll(() => pendingChallenge("C-1042", "phone"));
  const sms = usePoll(() => smsInbox(PRIYA_PHONE));
  const [answered, setAnswered] = useState<{ id: string; status: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const ch: PendingChallenge | null = data?.challenge ?? null;

  async function answer(decision: "approve" | "deny") {
    if (!ch) return;
    setBusy(true);
    try { const r = await respond(ch.challenge_id, { decision }); setAnswered({ id: ch.challenge_id, status: r.status }); }
    catch (e) { setAnswered({ id: ch.challenge_id, status: e instanceof BankError ? e.message : "error" }); }
    finally { setBusy(false); }
  }

  return (
    <Phone owner="Priya (registered device, enrolled 90 days ago)" number="+91 98450 00000 · fp_priya_phone" error={error}>
      <div className="text-[18px] font-semibold px-1 mb-2">NammaBank</div>
      {ch ? (
        <div className="bg-white rounded-2xl p-4 shadow-md border border-[#0F766E]/30" data-testid="push-card">
          <div className="flex items-center gap-2 text-[12px] text-text-tertiary"><span className="material-symbols-outlined !text-[16px] text-[#0F766E]">account_balance</span>
            NammaBank · now</div>
          <div className="text-[16px] font-semibold mt-2">Is this you?</div>
          <p className="text-[13px] text-text-secondary mt-1">Someone is trying to make changes to your account and move money from it.
            Approve only if it is you.</p>
          <div className="text-[11px] text-text-tertiary mt-2 font-mono">{ch.challenge_id}</div>
          <div className="mt-4 grid grid-cols-2 gap-2">
            <button disabled={busy} onClick={() => answer("deny")} data-testid="push-deny"
              className="h-11 rounded-xl bg-risk-critical text-white font-semibold text-[14px]">Not me</button>
            <button disabled={busy} onClick={() => answer("approve")} data-testid="push-approve"
              className="h-11 rounded-xl border border-border-default bg-white font-semibold text-[14px]">Approve</button>
          </div>
        </div>
      ) : (
        <div className="text-[13px] text-text-tertiary px-1" data-testid="push-empty">No sign-in requests. Push challenges for customer C-1042 appear here.</div>
      )}
      {(sms.data?.messages ?? []).length > 0 && (
        <div className="mt-4">
          <div className="text-[13px] font-semibold px-1 mb-1">Messages</div>
          {[...(sms.data?.messages ?? [])].reverse().map((m, i) => (
            <div key={i} className="bg-white rounded-2xl px-3 py-2 mb-2 text-[13px] shadow-sm">{m.text}</div>
          ))}
        </div>
      )}
      {answered && (
        <div className="mt-3 bg-white rounded-2xl p-3 text-[13px]" data-testid="push-result">
          {answered.status === "denied_by_customer" ? "Thanks. We blocked the request and secured your account." :
            answered.status === "passed" ? "Approved. You can continue." : `Request ${answered.status}.`}
          <div className="text-[11px] text-text-tertiary font-mono">{answered.id}</div>
        </div>
      )}
    </Phone>
  );
}
