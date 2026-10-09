// NammaBank account screens (PRD §11.2). Every action emits one event through POST /v1/demo/emit.
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { BankError, emit, paymentStatus } from "../lib/api";
import { useIdentity } from "../lib/identity";
import { BankShell, Card, input, primaryBtn, Result } from "../components/BankShell";
import { useStepUp } from "../components/StepUp";

const errText = (e: unknown) => (e instanceof BankError ? `${e.code}: ${e.message}` : "Something went wrong.");
const ist = (iso: string) => new Date(iso).toLocaleTimeString("en-GB", { timeZone: "Asia/Kolkata", hour12: false });

function useEmitter() {
  const { identity, context, log } = useIdentity();
  return async (event_type: Parameters<typeof emit>[0], payload: Record<string, unknown>, label: string) => {
    const r = await emit(event_type, identity.subject, context, payload);
    log({ who: identity.label, label, event_id: r.event_id });
    return r.event_id;
  };
}

// ------------------------------------------------------------------ /login
export function Login() {
  const { identity, setLoggedIn } = useIdentity();
  const send = useEmitter();
  const navigate = useNavigate();
  const [wrong, setWrong] = useState(false);
  const [pw, setPw] = useState("");
  const [res, setRes] = useState<{ kind: "ok" | "bad"; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const method = identity.id === "priya_phone" ? "password+push" : identity.id === "attacker" ? "password+otp" : "password";

  async function submit(e: FormEvent) {
    e.preventDefault(); setBusy(true); setRes(null);
    try {
      const id = await send("login", { result: wrong ? "failure" : "success", auth_method: method }, wrong ? "Failed login" : "Login");
      if (wrong) setRes({ kind: "bad", text: `Incorrect password (login failure recorded, ${id}).` });
      else { setLoggedIn(true); navigate("/home"); }
    } catch (err) { setRes({ kind: "bad", text: errText(err) }); } finally { setBusy(false); }
  }
  return (
    <BankShell requireLogin={false}>
      <Card title="Log in to NammaBank" sub={`Signing in as ${identity.who}.`}>
        <form onSubmit={submit} className="flex flex-col gap-4">
          <label className="text-[13px] font-medium">Customer ID
            <input className={input + " mt-1 font-mono"} value={identity.subject.customer_ref ?? ""} readOnly /></label>
          <label className="text-[13px] font-medium">Password
            <input type="password" className={input + " mt-1"} value={pw} onChange={(e) => setPw(e.target.value)} placeholder="any password works in the demo" /></label>
          <label className="flex items-center gap-2 text-[13px]"><input type="checkbox" checked={wrong} onChange={(e) => setWrong(e.target.checked)} />
            Simulate a wrong password</label>
          <div><button className={primaryBtn} disabled={busy} data-testid="login-submit">{busy ? "Signing in…" : "Log in"}</button></div>
        </form>
        {res && <Result kind={res.kind}>{res.text}</Result>}
      </Card>
    </BankShell>
  );
}

// ------------------------------------------------------------------ /home
export function Home() {
  const { identity, activity } = useIdentity();
  return (
    <BankShell>
      <div className="grid grid-cols-[1fr_1fr] gap-4">
        <section className="bg-white rounded-xl border border-border-default p-6">
          <div className="text-[13px] text-text-secondary">Savings account</div>
          <div className="font-mono text-[13px]">{identity.subject.account_ref}</div>
          <div className="text-[30px] font-semibold mt-2 tnum">₹6,12,450.00</div>
          <div className="text-[12px] text-text-tertiary">Available balance (demo)</div>
          <div className="mt-4 flex gap-2 flex-wrap">
            <Link to="/transfer" className={primaryBtn + " inline-flex items-center"}>Send money</Link>
            <Link to="/payees" className="h-10 px-4 rounded-lg border border-border-default inline-flex items-center text-[14px]">Add payee</Link>
          </div>
        </section>
        <section className="bg-white rounded-xl border border-border-default p-6">
          <div className="text-[14px] font-semibold mb-2">This session&apos;s activity</div>
          {activity.length === 0 && <div className="text-[13px] text-text-tertiary">Nothing yet.</div>}
          <ul className="flex flex-col gap-1.5" data-testid="activity">
            {activity.map((a) => (
              <li key={a.event_id} className="text-[13px] flex gap-2"><span className="font-mono text-text-tertiary">{ist(a.at)}</span>
                <span className="flex-1">{a.label} <span className="text-text-tertiary">· {a.who}</span></span>
                <span className="font-mono text-[11px] text-text-tertiary">{a.event_id}</span></li>
            ))}
          </ul>
        </section>
      </div>
    </BankShell>
  );
}

// ------------------------------------------------------------------ /security
export function Security() {
  const { identity } = useIdentity();
  const send = useEmitter();
  const [phone, setPhone] = useState(identity.id === "attacker" ? "+91 90000 11111" : "+91 98450 00000");
  const [res, setRes] = useState<{ kind: "ok" | "bad"; text: string } | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault(); setRes(null);
    try {
      const id = await send("mfa_change", { factor: "sms", action: "replace", new_phone: phone }, `SMS number changed to ${phone}`);
      setRes({ kind: "ok", text: `Your SMS number for one-time codes is now ${phone}. (${id})` });
    } catch (err) { setRes({ kind: "bad", text: errText(err) }); }
  }
  return (
    <BankShell>
      <Card title="Security settings" sub="Change the mobile number that receives your one-time codes.">
        <form onSubmit={submit} className="flex flex-col gap-4">
          <label className="text-[13px] font-medium">New SMS number
            <input className={input + " mt-1 font-mono"} value={phone} onChange={(e) => setPhone(e.target.value)} required data-testid="new-phone" /></label>
          <div><button className={primaryBtn} data-testid="security-submit">Update number</button></div>
        </form>
        {res && <Result kind={res.kind}>{res.text}</Result>}
      </Card>
    </BankShell>
  );
}

// ------------------------------------------------------------------ /kyc
export function Kyc() {
  const send = useEmitter();
  const { guard, modal } = useStepUp();
  const [sample, setSample] = useState<"genuine" | "deepfake">("deepfake");
  const [file, setFile] = useState<string>("");
  const [res, setRes] = useState<{ kind: "ok" | "bad" | "info"; text: string } | null>(null);
  const scores = sample === "genuine" ? { liveness_score: 0.94, face_match_score: 0.93, doc_tamper_score: 0.05 }
    : { liveness_score: 0.38, face_match_score: 0.81, doc_tamper_score: 0.12 };
  async function run() {
    try {
      const id = await send("kyc_result", { ...scores, injection_suspected: false, reason: "re_verification" }, `KYC re-verification (${sample} sample)`);
      setRes({ kind: "info", text: `Selfie video submitted for review. (${id})` });
    } catch (err) { setRes({ kind: "bad", text: errText(err) }); }
  }
  return (
    <BankShell>
      <Card title="Re-verify your identity" sub="Upload a short selfie video. We compare it with your ID document.">
        <div className="flex flex-col gap-4">
          <label className="text-[13px] font-medium">Selfie video
            <input type="file" accept="video/*,image/*" className="mt-1 block text-[13px]" onChange={(e) => setFile(e.target.files?.[0]?.name ?? "")} /></label>
          <label className="text-[13px] font-medium">Demo sample (decides the scores sent)
            <select className={input + " mt-1"} value={sample} onChange={(e) => setSample(e.target.value as "genuine" | "deepfake")} data-testid="kyc-sample">
              <option value="genuine">Genuine selfie (liveness 0.94)</option>
              <option value="deepfake">Deepfake injection (liveness 0.38)</option>
            </select></label>
          <div className="text-[12px] text-text-tertiary">{file ? `Selected: ${file} (not uploaded — the demo sends scores only)` : "No file chosen (optional in the demo)."}</div>
          <div><button className={primaryBtn} onClick={() => guard(run).catch((e) => setRes({ kind: "bad", text: errText(e) }))} data-testid="kyc-submit">Submit for verification</button></div>
        </div>
        {res && <Result kind={res.kind}>{res.text}</Result>}
      </Card>
      {modal}
    </BankShell>
  );
}

// ------------------------------------------------------------------ /payees
export function Payees() {
  const { payees, addPayee } = useIdentity();
  const send = useEmitter();
  const { guard, modal } = useStepUp();
  const [account, setAccount] = useState("A-RAVI-778");
  const [nickname, setNickname] = useState("Rent - Ravi");
  const [match, setMatch] = useState(true);
  const [res, setRes] = useState<{ kind: "ok" | "bad"; text: string } | null>(null);
  async function run() {
    try {
      const id = await send("payee_added", { payee_account: account, payee_name_match: match, nickname }, `Payee added: ${nickname} (${account})`);
      addPayee({ account, nickname });
      setRes({ kind: "ok", text: `${nickname} was added as a payee. (${id})` });
    } catch (err) { setRes({ kind: "bad", text: errText(err) }); }
  }
  return (
    <BankShell>
      <div className="grid grid-cols-[1fr_280px] gap-4 items-start">
        <Card title="Add a payee" sub="Payees you add can receive transfers from your account.">
          <form onSubmit={(e) => { e.preventDefault(); guard(run).catch((er) => setRes({ kind: "bad", text: errText(er) })); }} className="flex flex-col gap-4">
            <label className="text-[13px] font-medium">Account number
              <input className={input + " mt-1 font-mono"} value={account} onChange={(e) => setAccount(e.target.value)} required data-testid="payee-account" /></label>
            <label className="text-[13px] font-medium">Nickname
              <input className={input + " mt-1"} value={nickname} onChange={(e) => setNickname(e.target.value)} maxLength={64} /></label>
            <label className="text-[13px] font-medium">Name check result
              <select className={input + " mt-1"} value={match ? "yes" : "no"} onChange={(e) => setMatch(e.target.value === "yes")}>
                <option value="yes">Matches the account holder</option><option value="no">Does not match</option></select></label>
            <div><button className={primaryBtn} data-testid="payee-submit">Add payee</button></div>
          </form>
          {res && <Result kind={res.kind}>{res.text}</Result>}
        </Card>
        <section className="bg-white rounded-xl border border-border-default p-4">
          <div className="text-[14px] font-semibold mb-2">Your payees</div>
          <ul className="flex flex-col gap-1">{payees.map((p) => <li key={p.account} className="text-[13px]">{p.nickname} <span className="font-mono text-text-tertiary">{p.account}</span></li>)}</ul>
        </section>
      </div>
      {modal}
    </BankShell>
  );
}

// ------------------------------------------------------------------ /transfer
type Outcome = "pending" | "completed" | "held" | "blocked";
const OUTCOME_TEXT: Record<Outcome, [string, "ok" | "warn" | "bad" | "info"]> = {
  completed: ["Completed", "ok"], held: ["On hold – verify in app", "warn"], blocked: ["Blocked – contact your bank", "bad"],
  pending: ["Still processing… check again in a moment", "info"],
};

export function Transfer() {
  const { payees } = useIdentity();
  const send = useEmitter();
  const { guard, modal } = useStepUp();
  const [payee, setPayee] = useState(payees.find((p) => p.account === "A-RAVI-778")?.account ?? payees[0]?.account ?? "");
  const [amount, setAmount] = useState("480000");
  const [channel, setChannel] = useState("IMPS");
  const [status, setStatus] = useState<{ outcome: Outcome | "sending"; event_id?: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function run() {
    setErr(null); setStatus({ outcome: "sending" });
    try {
      const paise = Math.round(Number(amount) * 100);
      const id = await send("transaction", { amount_paise: paise, payee_account: payee, channel }, `Transfer ₹${Number(amount).toLocaleString("en-IN")} to ${payee}`);
      setStatus({ outcome: "pending", event_id: id });
      for (let i = 0; i < 10; i++) {                         // poll every second for up to 10 s (PRD §11.2)
        await new Promise((r) => setTimeout(r, 1000));
        const s = await paymentStatus(id);
        if (s.outcome !== "pending") { setStatus({ outcome: s.outcome, event_id: id }); return; }
      }
    } catch (e) { setErr(errText(e)); setStatus(null); }
  }
  const valid = Number(amount) > 0 && payee;
  return (
    <BankShell>
      <Card title="Send money" sub="Transfers go to a payee you have added.">
        <form onSubmit={(e) => { e.preventDefault(); guard(run).catch((er) => setErr(errText(er))); }} className="flex flex-col gap-4">
          <label className="text-[13px] font-medium">Payee
            <select className={input + " mt-1"} value={payee} onChange={(e) => setPayee(e.target.value)} data-testid="transfer-payee">
              {payees.map((p) => <option key={p.account} value={p.account}>{p.nickname} · {p.account}</option>)}
            </select></label>
          <label className="text-[13px] font-medium">Amount (₹)
            <input className={input + " mt-1 tnum"} inputMode="decimal" value={amount} onChange={(e) => setAmount(e.target.value.replace(/[^\d.]/g, ""))} data-testid="transfer-amount" /></label>
          <label className="text-[13px] font-medium">Channel
            <select className={input + " mt-1"} value={channel} onChange={(e) => setChannel(e.target.value)}>
              {["IMPS", "UPI", "NEFT"].map((c) => <option key={c}>{c}</option>)}</select></label>
          <div><button className={primaryBtn} disabled={!valid || status?.outcome === "sending" || status?.outcome === "pending"} data-testid="transfer-submit">Send</button></div>
        </form>
        {status?.outcome === "sending" && <Result kind="info">Sending…</Result>}
        {status && status.outcome !== "sending" && (
          <Result kind={OUTCOME_TEXT[status.outcome][1]}><span className="font-semibold">{OUTCOME_TEXT[status.outcome][0]}</span>
            <span className="block text-[12px] opacity-80 font-mono">{status.event_id}</span></Result>
        )}
        {err && <Result kind="bad">{err}</Result>}
      </Card>
      {modal}
    </BankShell>
  );
}
