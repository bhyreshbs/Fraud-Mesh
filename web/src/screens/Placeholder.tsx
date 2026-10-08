// Placeholder screens for routes whose Stitch wiring lands in a later Dev 1 phase. Each shows the raw contract
// response from its endpoint, so the route itself can already be checked.
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";

export function Placeholder({ title, phase, endpoint }: { title: string; phase: string; endpoint?: string }) {
  const params = useParams();
  const path = endpoint?.replace(":id", params.id ?? "");
  const q = useQuery({ queryKey: ["raw", path], queryFn: () => api<unknown>(path!), enabled: !!path });
  return (
    <div className="p-space-base flex flex-col gap-space-base">
      <div>
        <h1 className="font-headline-lg text-headline-lg tracking-tight">{title}</h1>
        <p className="text-body-sm text-on-surface-variant">The full Stitch screen is wired in <span className="font-mono">{phase}</span>.
          {path && <> Below is the live response of <span className="font-mono">GET {path}</span>.</>}</p>
      </div>
      {path && (
        <pre className="bg-surface-container-lowest border border-outline-variant rounded-lg p-3 text-code-xs font-mono overflow-auto max-h-[70vh]">
          {q.isLoading ? "Loading…" : q.isError ? `Error: ${(q.error as ApiError).code} ${(q.error as ApiError).message}` : JSON.stringify(q.data, null, 2)}
        </pre>
      )}
    </div>
  );
}
