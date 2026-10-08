// Auth context: the access token lives in memory only (PRD §11.1); a page reload restores it from the
// HttpOnly fm_refresh cookie via POST /v1/auth/refresh.
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Role, TokenResponse } from "../types/contracts";
import { api, refreshAccessToken, setAccessToken, setOnAuthLost } from "./api";

type Session = { role: Role; userId: string };
type AuthState = {
  session: Session | null;
  ready: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthState | null>(null);

function userIdOf(token: string): string {
  try {
    return JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).sub ?? "fixture";
  } catch {
    return "fixture";
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    setOnAuthLost(() => { setAccessToken(null); setSession(null); });
    refreshAccessToken().then((r) => {
      if (r) setSession({ role: r.role as Role, userId: userIdOf(r.access_token) });
      setReady(true);
    });
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const r = await api<TokenResponse>("/v1/auth/login", { method: "POST", body: { email, password } });
    setAccessToken(r.access_token);
    setSession({ role: r.role, userId: userIdOf(r.access_token) });
  }, []);

  const logout = useCallback(async () => {
    try { await api("/v1/auth/logout", { method: "POST" }); } catch { /* token may already be gone */ }
    setAccessToken(null);
    setSession(null);
  }, []);

  const value = useMemo(() => ({ session, ready, login, logout }), [session, ready, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}

const RANK: Record<Role, number> = { analyst: 0, lead: 1, admin: 2 };
export const hasRole = (s: Session | null, min: Role) => !!s && RANK[s.role] >= RANK[min];
