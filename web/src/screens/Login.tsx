// /login — Stitch "Authentication Suite" state 1 (sign in) and state 3 (error), wired to POST /v1/auth/login.
import { useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { ApiError, USE_FIXTURES } from "../lib/api";
import { useAuth } from "../lib/auth";
import { Backdrop } from "../components/Backdrop";

const TRUST = [
  ["Signed, tokenized ingestion with no raw PII stored", "M8 1.5L2.5 4V7.5C2.5 11 5 13.5 8 14.5C11 13.5 13.5 11 13.5 7.5V4L8 1.5Z"],
  ["Tamper-evident, hash-chained audit trail", "M3 2.5H13V13.5H3V2.5Z M5.5 6H10.5M5.5 8.5H10.5M5.5 11H8.5"],
  ["Role-based, least-privilege access", "M8 2.5a2.5 2.5 0 1 0 0 5a2.5 2.5 0 1 0 0-5 M3.5 13.5C3.5 10.5 5.5 9.5 8 9.5C10.5 9.5 12.5 10.5 12.5 13.5"],
];

export function Login() {
  const { session, login } = useAuth();
  const location = useLocation();
  const [email, setEmail] = useState("analyst@fraudmesh.local");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (session) return <Navigate to={(location.state as { from?: string })?.from ?? "/overview"} replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof ApiError
        ? (err.code === "UNAUTHENTICATED" ? "Incorrect email or password." : `${err.code}: ${err.message}`)
        : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen relative">
      <Backdrop />
      <div className="relative z-10 min-h-screen flex flex-col md:flex-row">
      <section className="w-full md:w-[55%] text-white p-10 lg:p-14 flex flex-col justify-between relative overflow-hidden m-4 md:mr-0 rounded-[1.75rem] shadow-float"
        style={{ background: "linear-gradient(140deg, #A94D29 0%, #C25A26 45%, #E07A44 100%)" }}>
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-11 h-11 rounded-xl bg-white/15 border border-white/30 backdrop-blur flex items-center justify-center">
              <span className="material-symbols-outlined !text-[24px]">hub</span>
            </div>
            <span className="font-bold text-[24px] tracking-tight">FraudMesh</span>
            <span className="ml-1 px-2.5 py-0.5 text-[11px] font-mono tracking-[0.12em] bg-white/15 rounded-full border border-white/30">2.0</span>
          </div>
          <p className="text-[14px] text-white/80 font-medium">Fraud, identity, KYC and cyber signals: one attack decision</p>
        </div>
        <div className="relative z-10 max-w-lg my-auto py-6">
          <div className="inline-block px-3 py-1 mb-5 font-mono text-[11px] uppercase tracking-[0.12em] bg-white/15 border border-white/30 rounded-full">Investigator console</div>
          <h2 className="text-[38px] font-semibold tracking-[-0.025em] leading-[1.15] mb-4">One attack. Multiple signals. One explainable case.</h2>
          <p className="text-[15px] text-white/85 leading-relaxed mb-8">
            Weak clues from fraud, identity, KYC, device and security systems are joined into one case, explained event by event,
            with the earliest moment FraudMesh could have intervened.
          </p>
          <div className="space-y-3.5 pt-2">
            {TRUST.map(([label, d]) => (
              <div key={label} className="flex items-center gap-3 text-[14px]">
                <div className="w-8 h-8 rounded-lg bg-white/15 border border-white/30 flex items-center justify-center shrink-0">
                  <svg className="w-4 h-4" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5"><path d={d} /></svg>
                </div>
                <span className="font-medium">{label}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="relative z-10 font-mono text-[11.5px] text-white/75">
          Demo system with synthetic data. All activity is logged to the audit chain.
        </div>
      </section>

      <section className="w-full md:w-[45%] p-8 lg:p-12 flex flex-col justify-center items-center">
        <div className="w-full max-w-[420px] fm-card p-8">
          <div className="mb-6">
            <span className="fm-eyebrow">Secure sign-in</span>
            <h3 className="text-[28px] font-semibold text-on-surface tracking-[-0.02em] mt-3">Welcome back</h3>
            <p className="text-[14px] text-on-surface-variant mt-1">Enter your credentials to open the investigation console.</p>
          </div>
          {error && (
            <div role="alert" className="mb-4 flex items-start gap-2 px-3 py-2.5 rounded-xl bg-risk-critical-fill border border-risk-critical-border text-[13px] text-risk-critical">
              <span className="material-symbols-outlined !text-[16px]">error</span>{error}
            </div>
          )}
          <form onSubmit={submit} className="space-y-5">
            <div>
              <label htmlFor="email" className="block text-[13.5px] font-semibold text-on-surface mb-1.5">Email</label>
              <input id="email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required
                className="w-full h-11 px-4 text-[14px] font-mono" />
              <p className="font-mono text-[11.5px] text-on-surface-variant mt-1.5">analyst@, lead@ or admin@fraudmesh.local</p>
            </div>
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label htmlFor="password" className="text-[13.5px] font-semibold text-on-surface">Password</label>
                <button type="button" onClick={() => setShow(!show)} className="text-[12.5px] text-primary-container hover:underline font-semibold">{show ? "Hide" : "Show"}</button>
              </div>
              <input id="password" type={show ? "text" : "password"} autoComplete="current-password" value={password}
                onChange={(e) => setPassword(e.target.value)} required={!USE_FIXTURES} className="w-full h-11 px-4 text-[14px]" />
              <p className="font-mono text-[11.5px] text-on-surface-variant mt-1.5">The DEMO_PASSWORD value from your .env file</p>
            </div>
            <button type="submit" disabled={busy} className="fm-btn-primary w-full justify-center !h-11">
              <span>{busy ? "Signing in…" : "Sign in"}</span>
              <span className="material-symbols-outlined !text-[18px]">arrow_forward</span>
            </button>
          </form>
        </div>
      </section>
      </div>
    </div>
  );
}
