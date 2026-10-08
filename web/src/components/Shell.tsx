// App shell from the Stitch export (fraudmesh_case_queue.html): slate sidebar rail + 56px header.
import { useEffect, useState, type ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, USE_FIXTURES } from "../lib/api";
import { hasRole, useAuth } from "../lib/auth";
import { istDateTime } from "../lib/format";
import type { Health, Role } from "../types/contracts";

const NAV: { to: string; icon: string; label: string; min?: Role }[] = [
  { to: "/queue", icon: "assignment_late", label: "Case queue" },
  { to: "/detectors", icon: "tune", label: "Detectors" },
  { to: "/metrics", icon: "insights", label: "Metrics and simulator" },
  { to: "/demo", icon: "science", label: "Demo control", min: "admin" },
  { to: "/status", icon: "verified_user", label: "System status" },
];

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t); }, []);
  return <span className="font-code-xs text-code-xs text-on-surface-variant tnum">{istDateTime(now)}</span>;
}

export function Shell({ crumb, children }: { crumb: string; children: ReactNode }) {
  const { session, logout } = useAuth();
  const health = useQuery({ queryKey: ["health"], queryFn: () => api<Health>("/v1/health"), refetchInterval: 10_000 });
  const engineOk = health.data?.db && health.data?.pipeline_ready;

  return (
    <div className="min-h-screen bg-surface-container-low">
      <aside className="fixed left-0 top-0 h-screen w-56 bg-inverse-surface z-50 flex flex-col justify-between">
        <div className="flex flex-col">
          <div className="h-14 px-space-base flex items-center justify-between border-b border-on-surface-variant/20">
            <div className="flex items-center gap-space-xs">
              <div className="w-6 h-6 rounded-lg bg-primary-container flex items-center justify-center">
                <span className="material-symbols-outlined text-inverse-on-surface !text-[16px]">shield</span>
              </div>
              <span className="font-headline-sm text-headline-sm text-inverse-on-surface tracking-tight">FraudMesh</span>
            </div>
            <span className="font-code-xs text-code-xs px-space-xs py-space-2xs bg-on-surface-variant/30 text-inverse-on-surface rounded-lg">
              {USE_FIXTURES ? "FIXTURES" : "v2.0"}
            </span>
          </div>
          <div className="px-space-md py-space-xs mt-space-xs">
            <span className="font-label-caps text-label-caps text-inverse-on-surface/60 uppercase px-space-xs">Operations console</span>
          </div>
          <nav className="flex flex-col px-space-xs gap-space-2xs">
            {NAV.filter((n) => !n.min || hasRole(session, n.min)).map((n) => (
              <NavLink key={n.to} to={n.to}
                className={({ isActive }) => "flex items-center gap-space-sm px-space-sm py-space-xs rounded-lg transition-colors " +
                  (isActive ? "bg-primary-container text-on-primary font-headline-sm"
                    : "text-inverse-on-surface hover:bg-on-surface-variant/20")}>
                <span className="material-symbols-outlined">{n.icon}</span>
                <span className="font-body-sm text-body-sm">{n.label}</span>
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="p-space-sm m-space-xs border border-on-surface-variant/30 rounded-lg flex flex-col gap-space-xs">
          <div className="flex items-center justify-between">
            <span className="font-label-caps text-label-caps text-inverse-on-surface/60 uppercase">Core engine</span>
            <div className="flex items-center gap-space-2xs">
              <span className={"w-2 h-2 rounded-full " + (engineOk ? "bg-emerald-400" : health.isLoading ? "bg-slate-400" : "bg-red-400")} />
              <span className="font-label-md text-label-md text-inverse-on-surface">
                {engineOk ? "Operational" : health.isLoading ? "Checking" : "Unavailable"}
              </span>
            </div>
          </div>
          <div className="flex items-center justify-between pt-space-2xs border-t border-on-surface-variant/20">
            <span className="font-body-xs text-body-xs text-inverse-on-surface/60">Contract</span>
            <span className="font-code-xs text-code-xs text-inverse-on-surface">{health.data?.contract_version ?? "—"}</span>
          </div>
        </div>
      </aside>

      <div className="pl-56 flex flex-col min-h-screen">
        <header className="fixed top-0 left-56 right-0 h-14 bg-surface-container-lowest border-b border-outline-variant z-40 px-space-base flex items-center justify-between gap-space-base">
          <div className="flex items-center gap-space-base">
            <div className="flex items-center gap-space-xs font-body-sm text-body-sm">
              <span className="text-on-surface-variant">Operations</span>
              <span className="text-outline-variant">/</span>
              <span className="font-headline-sm text-headline-sm text-on-surface">{crumb}</span>
            </div>
            <div className="h-4 w-px bg-outline-variant" />
            <Clock />
          </div>
          <div className="flex items-center gap-space-base">
            <span className="font-label-caps text-label-caps px-space-xs py-space-2xs bg-secondary-container text-on-secondary-container rounded-lg border border-outline-variant">
              DEMO · LOCAL
            </span>
            <div className="h-4 w-px bg-outline-variant" />
            <div className="flex flex-col text-right">
              <span className="font-code-sm text-code-sm text-on-surface leading-none">{session?.userId}</span>
              <span className="font-body-xs text-body-xs text-on-surface-variant capitalize">{session?.role}</span>
            </div>
            <button onClick={() => logout()} title="Sign out"
              className="h-8 px-2.5 rounded-lg border border-outline-variant bg-surface-container-lowest hover:bg-surface-container-low text-on-surface font-label-md text-label-md flex items-center gap-1">
              <span className="material-symbols-outlined !text-[16px]">logout</span> Sign out
            </button>
          </div>
        </header>
        <main className="pt-14 flex-1">{children}</main>
      </div>
    </div>
  );
}
