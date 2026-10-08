// NammaBank shell: demo banner with the identity switcher, header and account navigation. Fictional bank, no real branding.
import type { ReactNode } from "react";
import { Link, NavLink, Navigate } from "react-router-dom";
import { IDENTITIES, useIdentity, type IdentityId } from "../lib/identity";

const NAV = [["/home", "home", "Home"], ["/transfer", "send_money", "Transfer"], ["/payees", "group_add", "Payees"],
  ["/kyc", "badge", "Re-verify ID"], ["/security", "shield_lock", "Security"]];

export function BankShell({ children, requireLogin = true }: { children: ReactNode; requireLogin?: boolean }) {
  const { identity, setIdentity, deviceId, loggedIn, setLoggedIn } = useIdentity();
  if (requireLogin && !loggedIn) return <Navigate to="/login" replace />;
  return (
    <div className="min-h-screen bg-[#F3F6F5]">
      <div className="bg-[#FFF7E6] border-b border-[#FCD399] text-[12px] text-[#7A4A00] px-4 py-1.5 flex items-center gap-3 flex-wrap">
        <span className="font-semibold">DEMO</span> NammaBank is a fictional bank used to demo FraudMesh. Nothing here moves real money.
        <span className="ml-auto flex items-center gap-2 flex-wrap">
          <span>Using as:</span>
          <select data-testid="identity-switcher" value={identity.id} onChange={(e) => setIdentity(e.target.value as IdentityId)}
            className="h-7 px-2 rounded border border-[#FCD399] bg-white text-[12px]">
            {IDENTITIES.map((i) => <option key={i.id} value={i.id}>{i.label}</option>)}
          </select>
          <span className="font-mono text-[11px]" data-testid="device-id">device {deviceId ?? "…"}</span>
          <Link to="/phone/attacker" target="_blank" className="underline">attacker&apos;s phone</Link>
          <Link to="/phone/priya" target="_blank" className="underline">Priya&apos;s phone</Link>
        </span>
      </div>
      <header className="bg-[#0F766E] text-white">
        <div className="max-w-5xl mx-auto px-4 h-14 flex items-center gap-6">
          <span className="flex items-center gap-2 font-semibold text-[18px]"><span className="material-symbols-outlined">account_balance</span>NammaBank</span>
          {loggedIn && <nav className="flex gap-1">
            {NAV.map(([to, icon, label]) => (
              <NavLink key={to} to={to} className={({ isActive }) => "h-9 px-3 rounded-lg flex items-center gap-1.5 text-[13px] " + (isActive ? "bg-white/20 font-semibold" : "hover:bg-white/10")}>
                <span className="material-symbols-outlined !text-[16px]">{icon}</span>{label}</NavLink>
            ))}
          </nav>}
          {loggedIn && <button onClick={() => setLoggedIn(false)} className="ml-auto text-[13px] hover:underline">Log out</button>}
        </div>
      </header>
      <main className="max-w-5xl mx-auto px-4 py-6">{children}</main>
    </div>
  );
}

export function Card({ title, children, sub }: { title: string; sub?: string; children: ReactNode }) {
  return (
    <section className="bg-white rounded-xl border border-border-default p-6 max-w-xl">
      <h1 className="text-[20px] font-semibold">{title}</h1>
      {sub && <p className="text-[13px] text-text-secondary mt-1">{sub}</p>}
      <div className="mt-5">{children}</div>
    </section>
  );
}

export const input = "w-full h-10 px-3 text-[14px] border border-border-default rounded-lg focus:outline-none focus:border-[#0F766E] bg-white";
export const primaryBtn = "h-10 px-5 rounded-lg bg-[#0F766E] hover:bg-[#115E59] disabled:opacity-50 text-white text-[14px] font-semibold";

export function Result({ kind, children }: { kind: "ok" | "warn" | "bad" | "info"; children: ReactNode }) {
  const s = { ok: "bg-risk-low-fill text-risk-low border-risk-low-border", warn: "bg-risk-high-fill text-risk-high border-risk-high-border",
    bad: "bg-risk-critical-fill text-risk-critical border-risk-critical-border", info: "bg-surface-container-low text-on-surface-variant border-outline-variant" }[kind];
  return <div data-testid="result" data-kind={kind} className={`mt-4 px-3 py-2.5 rounded-lg border text-[14px] ${s}`}>{children}</div>;
}
