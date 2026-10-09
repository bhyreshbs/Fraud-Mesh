// useStream(): one WebSocket to /v1/stream per signed-in console (PRD §9.6, §11). case_update messages are applied
// to the TanStack Query cache (queue row upserted, case views refetched); challenge_update refreshes that case's timeline.
// The last 60 case updates are kept as a feed (Demo Simulator telemetry stream, Overview).
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type { CasesPage, CaseUpdate, ChallengeUpdate } from "../types/contracts";
import { API_BASE, getAccessToken, refreshAccessToken, USE_FIXTURES } from "./api";
import { useAuth } from "./auth";

export type StreamStatus = "connecting" | "live" | "offline" | "fixtures";
export type FeedItem = { at: string; msg: CaseUpdate };
const StreamContext = createContext<{ status: StreamStatus; fresh: Set<string>; feed: FeedItem[] }>({ status: "connecting", fresh: new Set(), feed: [] });
const FEED_MAX = 60;

export function StreamProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const { session } = useAuth();
  const [status, setStatus] = useState<StreamStatus>(USE_FIXTURES ? "fixtures" : "connecting");
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const [feed, setFeed] = useState<FeedItem[]>([]);

  useEffect(() => {
    if (!session || USE_FIXTURES) return;
    let ws: WebSocket | null = null;
    let stopped = false;
    let retry = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const markFresh = (id: string) => {
      setFresh((s) => new Set(s).add(id));
      setTimeout(() => setFresh((s) => { const n = new Set(s); n.delete(id); return n; }), 2500);
    };

    const apply = (msg: CaseUpdate | ChallengeUpdate) => {
      if (msg.type === "case_update") {
        const id = msg.case.case_id;
        qc.setQueryData<CasesPage>(["cases"], (old) => {
          if (!old) return old;
          const others = old.items.filter((c) => c.case_id !== id);
          return { ...old, items: [msg.case, ...others] };
        });
        markFresh(id);
        setFeed((f) => [{ at: new Date().toISOString(), msg }, ...f].slice(0, FEED_MAX));
        for (const key of ["case", "timeline", "explanation", "graph", "twin"]) qc.invalidateQueries({ queryKey: [key, id] });
        qc.invalidateQueries({ queryKey: ["twin-overview"] });
        qc.invalidateQueries({ queryKey: ["metrics"] });
      } else if (msg.type === "challenge_update") {
        qc.invalidateQueries({ queryKey: ["timeline", msg.case_id] });
      }
    };

    const schedule = () => {
      if (stopped) return;
      retry = Math.min(retry + 1, 6);
      timer = setTimeout(connect, 500 * 2 ** retry);
    };

    function connect() {
      setStatus("connecting");
      ws = new WebSocket(API_BASE.replace(/^http/, "ws") + "/v1/stream");
      ws.onopen = () => {
        ws?.send(JSON.stringify({ token: getAccessToken() }));
        setStatus("live");
        retry = 0;
      };
      ws.onmessage = (e) => { try { apply(JSON.parse(e.data)); } catch { /* ignore malformed frames */ } };
      ws.onclose = (e) => {
        setStatus("offline");
        if (stopped) return;
        if (e.code === 4401) refreshAccessToken().finally(schedule);   // token expired: refresh, then reconnect
        else schedule();
      };
    }

    connect();
    const keepAlive = setInterval(() => { if (ws?.readyState === WebSocket.OPEN) ws.send("ping"); }, 25_000);
    return () => { stopped = true; clearTimeout(timer); clearInterval(keepAlive); ws?.close(); };
  }, [session, qc]);

  return <StreamContext.Provider value={{ status, fresh, feed }}>{children}</StreamContext.Provider>;
}

export const useStream = () => useContext(StreamContext);
