// Typed TanStack Query hooks for the console. Keys are shared with useStream(), which invalidates them live.
import { useQuery } from "@tanstack/react-query";
import type { CaseDetail, CasesPage, DetectorInfo, Explanation, GraphElements, MetricsSummary, Timeline } from "../types/contracts";
import { api } from "./api";

export const useCases = () =>
  useQuery({ queryKey: ["cases"], queryFn: () => api<CasesPage>("/v1/cases?limit=200"), refetchInterval: 30_000 });
export const useCase = (id: string) =>
  useQuery({ queryKey: ["case", id], queryFn: () => api<CaseDetail>(`/v1/cases/${id}`) });
export const useTimeline = (id: string) =>
  useQuery({ queryKey: ["timeline", id], queryFn: () => api<Timeline>(`/v1/cases/${id}/timeline`) });
export const useExplanation = (id: string) =>
  useQuery({ queryKey: ["explanation", id], queryFn: () => api<Explanation>(`/v1/cases/${id}/explanation`) });
export const useGraph = (id: string, hops = 2) =>
  useQuery({ queryKey: ["graph", id, hops], queryFn: () => api<GraphElements>(`/v1/cases/${id}/graph?hops=${hops}`) });
export const useDetectors = () =>
  useQuery({ queryKey: ["detectors"], queryFn: () => api<DetectorInfo[]>("/v1/detectors") });
export const useMetrics = () =>
  useQuery({ queryKey: ["metrics"], queryFn: () => api<MetricsSummary>("/v1/metrics/summary"), refetchInterval: 15_000 });
