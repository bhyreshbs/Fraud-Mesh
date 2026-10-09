// Identity switcher (PRD §11.2): who is using the bank app. Sets subject + context from the demo identity table (PRD §4);
// the device ID comes from FingerprintJS unless the chosen identity overrides it.
import FingerprintJS from "@fingerprintjs/fingerprintjs";
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Context, Subject } from "../types/contracts";
import { deviceContext, snapshotTelemetry, startTelemetry, type DemoSignals } from "./telemetry";

export type IdentityId = "priya_phone" | "attacker" | "this_browser";
export type Identity = { id: IdentityId; label: string; who: string; subject: Subject; deviceOverride: string | null; ip?: string };

export const IDENTITIES: Identity[] = [
  { id: "priya_phone", label: "Priya's phone", who: "Priya (account holder)", subject: { customer_ref: "C-1042", account_ref: "A-88213" }, deviceOverride: "fp_priya_phone" },
  { id: "attacker", label: "Attacker laptop", who: "Attacker using Priya's stolen password", subject: { customer_ref: "C-1042", account_ref: "A-88213" }, deviceOverride: "fp_attacker_01" },
  { id: "this_browser", label: "This browser (FingerprintJS)", who: "Priya, on a device the bank has never seen", subject: { customer_ref: "C-1042", account_ref: "A-88213" }, deviceOverride: null, ip: "49.207.10.21" },
];

type State = {
  identity: Identity; setIdentity: (id: IdentityId) => void; deviceId: string | null; context: Context;
  loggedIn: boolean; setLoggedIn: (v: boolean) => void; payees: Payee[]; addPayee: (p: Payee) => void;
  activity: Activity[]; log: (a: Omit<Activity, "at">) => void;
  demoSignals: DemoSignals; setDemoSignals: (s: DemoSignals) => void;
  /** The context for an event being sent now: identity + device fields + a fresh telemetry snapshot. */
  eventContext: () => Context;
};
export type Activity = { at: string; who: string; label: string; event_id: string };
export type Payee = { account: string; nickname: string };

const Ctx = createContext<State | null>(null);
const load = (k: string) => { try { return localStorage.getItem(k); } catch { return null; } };
const save = (k: string, v: string) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable */ } };

export function IdentityProvider({ children }: { children: ReactNode }) {
  const [id, setId] = useState<IdentityId>((load("nb.identity") as IdentityId) || "attacker");
  const [fp, setFp] = useState<string | null>(null);
  const [logged, setLogged] = useState<Record<string, boolean>>({});
  const [activity, setActivity] = useState<Activity[]>([]);
  const [demoSignals, setDemoSignals] = useState<DemoSignals>({ remoteAccess: false, activeCall: false });
  const [payees, setPayees] = useState<Payee[]>(() => {
    try { return JSON.parse(load("nb.payees") || "") as Payee[]; } catch { return [{ account: "A-20001", nickname: "Electricity board" }]; }
  });

  useEffect(() => { startTelemetry(); }, []);
  useEffect(() => { FingerprintJS.load().then((a) => a.get()).then((r) => setFp("fpjs_" + r.visitorId.slice(0, 20))).catch(() => setFp("fpjs_unavailable")); }, []);

  const value = useMemo<State>(() => {
    const identity = IDENTITIES.find((i) => i.id === id) ?? IDENTITIES[1];
    const deviceId = identity.deviceOverride ?? fp;
    const context: Context = { device_id: deviceId, ip: identity.ip ?? null, user_agent: navigator.userAgent.slice(0, 200),
      city: null, lat: null, lon: null, asn: null,      // the server fills asn/city/lat/lon for known demo devices
      ...deviceContext(), telemetry: null };
    return {
      identity, deviceId, context, demoSignals, setDemoSignals,
      eventContext: () => ({ ...context, ...deviceContext(), telemetry: snapshotTelemetry(demoSignals) }),
      setIdentity: (next) => { setId(next); save("nb.identity", next); },
      loggedIn: !!logged[id], setLoggedIn: (v) => setLogged((l) => ({ ...l, [id]: v })),
      activity, log: (a) => setActivity((xs) => [{ ...a, at: new Date().toISOString() }, ...xs].slice(0, 30)),
      payees, addPayee: (p) => setPayees((ps) => { const n = [...ps.filter((x) => x.account !== p.account), p]; save("nb.payees", JSON.stringify(n)); return n; }),
    };
  }, [id, fp, logged, payees, activity, demoSignals]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useIdentity(): State {
  const c = useContext(Ctx);
  if (!c) throw new Error("useIdentity outside IdentityProvider");
  return c;
}
