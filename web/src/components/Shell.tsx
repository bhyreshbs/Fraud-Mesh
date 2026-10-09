// App shell (Stitch "Warm Neumorphic Glass" over a three.js backdrop): a floating sidebar where each nav category is its
// own liquid-glass card (foldable, remembered on this device; the category of the open page always unfolds), and a
// glass top bar with breadcrumb, live-stream pill, case search, critical-case bell and the signed-in user.
// Every number comes from the API.
import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, USE_FIXTURES } from "../lib/api";
import { hasRole, useAuth } from "../lib/auth";
import { istDateTime } from "../lib/format";
import { useCases } from "../lib/queries";
import { useStream } from "../lib/stream";
import type { Health, Role } from "../types/contracts";
import { Backdrop } from "./Backdrop";
import { LiveDot } from "./ui";

type Item = { to: string; icon: string; label: string; min?: Role; badge?: "open" };
type Group = { id: string; title: string; icon: string; color: string; blurb: string; items: Item[] };
const GROUPS: Group[] = [
  { id: "core", title: "Core intelligence", icon: "hub", color: "#D96B35", blurb: "Cases · dossiers", items: [
    { to: "/overview", icon: "grid_view", label: "Overview" },
    { to: "/queue", icon: "inbox", label: "Case Queue", badge: "open" },
    { to: "/investigations", icon: "manage_search", label: "Investigations" },
  ] },
  { id: "detect", title: "Detection & analysis", icon: "radar", color: "#4F6D8A", blurb: "Signals · models", items: [
    { to: "/detectors", icon: "shield", label: "Detection Engine" },
    { to: "/metrics", icon: "insights", label: "Metrics & Analytics" },
    { to: "/twin", icon: "hub", label: "Digital Twin" },
  ] },
  { id: "system", title: "Simulation & system", icon: "science", color: "#5E8C6A", blurb: "Demo · operations", items: [
    { to: "/demo-panel", icon: "restart_alt", label: "Demo" },
    { to: "/demo", icon: "science", label: "Demo Simulator", min: "admin" },
    { to: "/status", icon: "monitor_heart", label: "System Health" },
    { to: "/settings", icon: "tune", label: "Settings" },
  ] },
];

const FOLDS_KEY = "fm-nav-folds";

// Which category cards are unfolded, remembered on this device (storage can be blocked: then it holds until reload).
function useFolds(): [Record<string, boolean>, (id: string, open: boolean) => void] {
  const [open, setOpen] = useState<Record<string, boolean>>(() => {
    const base: Record<string, boolean> = Object.fromEntries(GROUPS.map((g) => [g.id, true]));
    try { return { ...base, ...JSON.parse(localStorage.getItem(FOLDS_KEY) || "{}") }; } catch { return base; }
  });
  const set = (id: string, value: boolean) => setOpen((cur) => {
    if (cur[id] === value) return cur;
    const next = { ...cur, [id]: value };
    try { localStorage.setItem(FOLDS_KEY, JSON.stringify(next)); } catch { /* storage blocked */ }
    return next;
  });
  return [open, set];
}

function CategoryCard({ g, items, open, onToggle, openCases }:
  { g: Group; items: Item[]; open: boolean; onToggle: () => void; openCases: number }) {
  return (
    <section className="relative fm-glass-card fm-cat-card shrink-0 p-2.5" style={{ "--cat": g.color } as CSSProperties} data-testid={`nav-card-${g.id}`}>
      <button onClick={onToggle} aria-expanded={open} aria-controls={`nav-${g.id}`}
        className="w-full flex items-center gap-3 px-1.5 py-1.5 rounded-xl text-left hover:bg-white/40 transition-colors">
        <span className="fm-cat-tile w-9 h-9 rounded-xl flex items-center justify-center shrink-0">
          <span className="material-symbols-outlined !text-[19px]">{g.icon}</span></span>
        <span className="flex-1 min-w-0">
          <span className="block text-[13.5px] font-semibold text-on-surface leading-tight truncate">{g.title}</span>
          <span className="block font-mono text-[10.5px] text-on-surface-variant truncate">{g.blurb}</span>
        </span>
        {!open && <span className="font-mono text-[10.5px] px-1.5 py-px rounded-md bg-white/60 text-on-surface-variant">{items.length}</span>}
        <span className={"material-symbols-outlined !text-[18px] text-outline transition-transform " + (open ? "" : "-rotate-90")}>expand_more</span>
      </button>
      <div id={`nav-${g.id}`} className={"grid transition-all duration-200 " + (open ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0")}>
        <nav className="overflow-hidden min-h-0 flex flex-col gap-0.5" aria-hidden={!open}>
          <div className="h-1.5 shrink-0" />
          {items.map((n) => (
            <NavLink key={n.to} to={n.to} tabIndex={open ? undefined : -1}
              className={({ isActive }) => "flex items-center justify-between px-3 py-2 rounded-xl transition-all " +
                (isActive ? "fm-cat-active" : "text-on-surface-variant hover:bg-white/50 hover:text-on-surface font-medium")}>
              {({ isActive }) => (
                <>
                  <span className="flex items-center gap-3">
                    <span className={"material-symbols-outlined !text-[19px] " + (isActive ? "" : "text-outline")}
                      style={isActive ? { color: g.color } : undefined}>{n.icon}</span>
                    <span className="text-[14px]">{n.label}</span>
                  </span>
                  {n.badge === "open" && openCases > 0 && (
                    <span className="font-mono text-[12px] px-2 py-0.5 rounded-full bg-primary-fixed text-on-primary-fixed font-semibold">{openCases}</span>)}
                </>
              )}
            </NavLink>
          ))}
        </nav>
      </div>
    </section>
  );
}

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t); }, []);
  return <span className="font-mono text-[12px] text-on-surface-variant tnum whitespace-nowrap hidden min-[1560px]:inline">{istDateTime(now)}</span>;
}

export function Shell({ crumb, children }: { crumb: string; children: ReactNode }) {
  const { session, logout } = useAuth();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [folds, setFold] = useFolds();
  const { status } = useStream();
  const [q, setQ] = useState("");
  const [latency, setLatency] = useState<number | null>(null);
  const health = useQuery({
    queryKey: ["health"], refetchInterval: 10_000,
    queryFn: async () => { const t = performance.now(); const h = await api<Health>("/v1/health"); setLatency(Math.round(performance.now() - t)); return h; },
  });
  const cases = useCases();
  const items = cases.data?.items ?? [];
  const open = items.filter((c) => c.band !== "LOW" && (c.status === "OPEN" || c.status === "INVESTIGATING")).length;
  const critical = items.filter((c) => c.band === "CRITICAL" && c.status !== "CLOSED").length;
  const engineOk = health.data?.db && health.data?.pipeline_ready;
  const initials = (session?.userId ?? "?").replace(/^usr_/, "").slice(0, 2).toUpperCase();
  const visible = (g: Group) => g.items.filter((n) => !n.min || hasRole(session, n.min));

  // The card holding the open page always unfolds.
  useEffect(() => {
    GROUPS.filter((g) => g.items.some((n) => pathname === n.to || pathname.startsWith(n.to + "/"))).forEach((g) => setFold(g.id, true));
  }, [pathname]);   // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="min-h-screen relative">
      <Backdrop />
      <aside className="fixed left-3 top-3 bottom-3 w-64 z-50 flex flex-col gap-3 overflow-y-auto fm-no-scrollbar" data-testid="sidebar">
        <Link to="/overview" className="fm-glass-card shrink-0 h-[4.5rem] px-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-primary-container flex items-center justify-center text-on-primary shadow-btn-primary">
            <span className="material-symbols-outlined !text-[22px]">hub</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[19px] font-bold text-on-surface leading-tight tracking-tight">FraudMesh<span className="text-primary-container ml-0.5">2.0</span></span>
            <span className="font-mono text-[11px] text-on-surface-variant tracking-[0.12em] uppercase">{USE_FIXTURES ? "Fixture data" : "Correlation mesh"}</span>
          </div>
        </Link>
        {GROUPS.map((g) => (
          <CategoryCard key={g.id} g={g} items={visible(g)} open={folds[g.id] !== false} openCases={open}
            onToggle={() => setFold(g.id, folds[g.id] === false)} />
        ))}
        <div className="mt-auto shrink-0 fm-glass-card p-3.5 flex flex-col gap-1" data-testid="engine-status">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-on-surface-variant">Core engine</span>
            <span className="flex items-center gap-1.5 font-mono text-[12px]">
              <span className={"w-2 h-2 rounded-full " + (engineOk ? "bg-risk-low" : health.isLoading ? "bg-outline" : "bg-risk-critical")} />
              {engineOk ? "Operational" : health.isLoading ? "Checking" : "Unavailable"}</span>
          </div>
          <div className="flex items-center justify-between text-body-xs text-on-surface-variant">
            <span>API round-trip</span><span className="font-mono text-primary-container">{latency != null ? `${latency} ms` : "—"}</span>
          </div>
          <div className="flex items-center justify-between text-body-xs text-on-surface-variant">
            <span>Contract</span><span className="font-mono">{health.data?.contract_version ?? "—"}</span>
          </div>
        </div>
      </aside>

      <div className="relative z-10 pl-[17.5rem] pr-3 flex flex-col min-h-screen">
        <header className="sticky top-3 mt-3 h-[4.5rem] fm-glass-card z-40 px-6 flex items-center justify-between gap-6">
          <div className="flex items-center gap-4 min-w-0">
            <div className="flex items-center gap-2 text-[14.5px] whitespace-nowrap">
              <span className="text-on-surface-variant">FraudMesh</span>
              <span className="material-symbols-outlined !text-[16px] text-outline">chevron_right</span>
              <span className="font-semibold text-on-surface">{crumb}</span>
            </div>
            <span className="fm-pill py-1 px-3 shadow-porcelain-sm bg-porcelain whitespace-nowrap" data-testid="live-pill">
              <LiveDot on={status === "live"} />
              {{ live: "LIVE STREAM", connecting: "CONNECTING", offline: "RECONNECTING", fixtures: "FIXTURES" }[status]}
            </span>
            <Clock />
          </div>
          <div className="flex items-center gap-4">
            <form onSubmit={(e) => { e.preventDefault(); navigate(`/queue?q=${encodeURIComponent(q.trim())}`); }}
              className="relative w-64 hidden lg:block">
              <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline !text-[18px]">search</span>
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search case ID or customer token…" data-testid="global-search"
                className="w-full h-10 pl-10 pr-3 text-body-sm placeholder:text-outline" />
            </form>
            <Link to="/queue?band=CRITICAL" title={`${critical} critical cases`}
              className="relative w-10 h-10 rounded-xl bg-porcelain shadow-porcelain-sm flex items-center justify-center text-on-surface-variant hover:text-primary-container">
              <span className="material-symbols-outlined !text-[20px]">notifications</span>
              {critical > 0 && <span className="absolute top-1.5 right-1.5 min-w-[18px] h-[18px] px-1 rounded-full bg-risk-critical text-white text-[10px] font-mono flex items-center justify-center">{critical}</span>}
            </Link>
            <div className="flex items-center gap-3">
              <div className="flex flex-col text-right">
                <span className="text-[14px] font-semibold text-on-surface leading-tight">{session?.userId}</span>
                <span className="font-mono text-[11.5px] text-on-surface-variant capitalize">{session?.role}</span>
              </div>
              <div className="w-10 h-10 rounded-xl bg-primary-container text-on-primary flex items-center justify-center font-semibold shadow-btn-primary">{initials}</div>
              <button onClick={() => logout()} title="Sign out" data-testid="sign-out"
                className="w-10 h-10 rounded-xl bg-porcelain shadow-porcelain-sm flex items-center justify-center text-on-surface-variant hover:text-risk-critical">
                <span className="material-symbols-outlined !text-[20px]">logout</span>
              </button>
            </div>
          </div>
        </header>
        <main className="flex-1">{children}</main>
      </div>
    </div>
  );
}
