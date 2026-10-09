// App shell (Stitch "Warm Neumorphic Glass"): porcelain sidebar with three nav groups, sticky top bar with breadcrumb,
// live-stream pill, case search, critical-case bell and the signed-in user. Every number comes from the API.
import { useEffect, useState, type ReactNode } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, USE_FIXTURES } from "../lib/api";
import { hasRole, useAuth } from "../lib/auth";
import { istDateTime } from "../lib/format";
import { useCases } from "../lib/queries";
import { useStream } from "../lib/stream";
import type { Health, Role } from "../types/contracts";
import { LiveDot } from "./ui";

type Item = { to: string; icon: string; label: string; min?: Role; badge?: "open" };
const GROUPS: { title: string; items: Item[] }[] = [
  { title: "Core intelligence", items: [
    { to: "/overview", icon: "grid_view", label: "Overview" },
    { to: "/queue", icon: "inbox", label: "Case Queue", badge: "open" },
    { to: "/investigations", icon: "manage_search", label: "Investigations" },
  ] },
  { title: "Detection & analysis", items: [
    { to: "/detectors", icon: "shield", label: "Detection Engine" },
    { to: "/metrics", icon: "insights", label: "Metrics & Analytics" },
    { to: "/twin", icon: "hub", label: "Digital Twin" },
  ] },
  { title: "Simulation & system", items: [
    { to: "/demo-panel", icon: "restart_alt", label: "Demo" },
    { to: "/demo", icon: "science", label: "Demo Simulator", min: "admin" },
    { to: "/status", icon: "monitor_heart", label: "System Health" },
    { to: "/settings", icon: "tune", label: "Settings" },
  ] },
];

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t); }, []);
  return <span className="font-mono text-[12px] text-on-surface-variant tnum whitespace-nowrap hidden xl:inline">{istDateTime(now)}</span>;
}

export function Shell({ crumb, children }: { crumb: string; children: ReactNode }) {
  const { session, logout } = useAuth();
  const navigate = useNavigate();
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

  return (
    <div className="min-h-screen bg-canvas">
      <aside className="fixed left-0 top-0 h-screen w-64 bg-porcelain z-50 flex flex-col justify-between border-r border-outline-variant/60 shadow-[2px_0_16px_rgba(184,169,154,0.18)]">
        <div className="flex flex-col overflow-y-auto">
          <Link to="/overview" className="h-20 px-6 flex items-center gap-3 border-b border-outline-variant/50">
            <div className="w-10 h-10 rounded-xl bg-primary-container flex items-center justify-center text-on-primary shadow-btn-primary">
              <span className="material-symbols-outlined !text-[22px]">hub</span>
            </div>
            <div className="flex flex-col">
              <span className="text-[19px] font-bold text-on-surface leading-tight tracking-tight">FraudMesh<span className="text-primary-container ml-0.5">2.0</span></span>
              <span className="font-mono text-[11px] text-on-surface-variant tracking-[0.12em] uppercase">{USE_FIXTURES ? "Fixture data" : "Correlation mesh"}</span>
            </div>
          </Link>
          {GROUPS.map((g) => (
            <div key={g.title} className="px-4 pt-5">
              <div className="font-mono text-[11px] uppercase tracking-[0.12em] text-outline px-3 pb-2 font-medium">{g.title}</div>
              <nav className="flex flex-col gap-1">
                {g.items.filter((n) => !n.min || hasRole(session, n.min)).map((n) => (
                  <NavLink key={n.to} to={n.to}
                    className={({ isActive }) => "flex items-center justify-between px-3.5 py-2.5 rounded-xl transition-all " +
                      (isActive ? "fm-nav-active" : "text-on-surface-variant hover:bg-surface-container-low hover:text-on-surface font-medium")}>
                    {({ isActive }) => (
                      <>
                        <span className="flex items-center gap-3">
                          <span className={"material-symbols-outlined !text-[20px] " + (isActive ? "text-primary-container" : "text-outline")}>{n.icon}</span>
                          <span className="text-[14.5px]">{n.label}</span>
                        </span>
                        {n.badge === "open" && open > 0 && (
                          <span className="font-mono text-[12px] px-2 py-0.5 rounded-full bg-primary-fixed text-on-primary-fixed font-semibold">{open}</span>)}
                      </>
                    )}
                  </NavLink>
                ))}
              </nav>
            </div>
          ))}
        </div>
        <div className="m-4 fm-card-sm p-3.5 flex flex-col gap-1" data-testid="engine-status">
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

      <div className="pl-64 flex flex-col min-h-screen">
        <header className="sticky top-0 h-20 bg-canvas/85 backdrop-blur-md z-40 px-8 flex items-center justify-between gap-6 border-b border-outline-variant/40">
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
              className="relative w-72 hidden lg:block">
              <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline !text-[18px]">search</span>
              <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search case ID or customer token…" data-testid="global-search"
                className="w-full h-10 pl-10 pr-3 text-body-sm placeholder:text-outline" />
            </form>
            <Link to="/queue?band=CRITICAL" title={`${critical} critical cases`}
              className="relative w-10 h-10 rounded-xl bg-porcelain shadow-porcelain-sm flex items-center justify-center text-on-surface-variant hover:text-primary-container">
              <span className="material-symbols-outlined !text-[20px]">notifications</span>
              {critical > 0 && <span className="absolute top-1.5 right-1.5 min-w-[18px] h-[18px] px-1 rounded-full bg-risk-critical text-white text-[10px] font-mono flex items-center justify-center">{critical}</span>}
            </Link>
            <div className="h-8 w-px bg-outline-variant" />
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
