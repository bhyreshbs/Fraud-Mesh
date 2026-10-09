// Digital Twin API types (engine/twin/models.py; served by api/routers/twin.py).
import type { Band, Stage } from "./contracts";

export type Actor = "attacker" | "customer" | "network" | "insider" | "system";
export type StepOutcome = "happened" | "prevented" | "held" | "blocked" | "rejected" | "lost" | "completed";

export interface TwinStep {
  index: number; ts: string; event_id: string; event_type: string; actor: Actor; stage: Stage; summary: string;
  changes: string[]; p: number; band: Band; actions: string[]; amount_paise: number | null;
  forecast_stage: Stage | null; forecast_next: Stage | null; forecast_probability: number | null;
  forecast_p_money: number | null; forecast_minutes_to_money: number | null;
}
export interface EntityState { entity: string; kind: string; tags: string[] }
export interface Intervention { ts: string; action: string; effect: string }
export interface PolicyOutcome {
  policy_id: string; label: string; description: string; money_lost_paise: number; money_protected_paise: number;
  attack_stopped: boolean; stopped_at: string | null; stopped_stage: Stage | null; stop_reason: string | null;
  lead_time_s: number | null; first_intervention: string | null; interventions: Intervention[]; customer_friction: number;
  steps: StepOutcome[]; stages_reached: Stage[];
}
export interface NextStage { stage: Stage; probability: number; median_minutes: number | null }
export interface Prediction {
  from_stage: Stage | null; next_stages: NextStage[]; p_reach_monetization: number | null;
  expected_minutes_to_monetization: number | null; sample_size: number; note: string;
}
export interface CaseTwin {
  case_id: string; customer: string | null; steps: TwinStep[]; entities: EntityState[]; policies: PolicyOutcome[];
  best_policy: string; live_policy: string; earliest_intervention: string | null; prediction: Prediction; assumptions: string[];
}
export interface TwinOverview {
  entities: Record<string, number>; fraud_seeds: number; cases_by_band: Record<Band, number>; payments_held: number;
  payments_blocked: number; active_interventions: number; money_at_risk_paise: number; money_protected_paise: number;
  hottest_cases: { case_id: string; band: Band; p_attack: number; customer: string | null; stages: number;
    payment_state: string; amount_at_risk_paise: number; last_event_ts: string }[];
}

// GET /v1/engine/config (api/routers/config.py): read-only engine configuration.
export interface ModelDomainMetrics { pr_auc: number | null; roc_auc: number | null; ece: number; n: number; positives: number; split: string;
  rows: { train: number; calibrate: number; test: number } }
export interface ModelArtifact {
  file: string; sha256: string; model: string; features: string[]; pr_auc: number; roc_auc: number; ece: number;
  best_iteration?: number; split?: string; training_data?: string[]; rows?: Record<string, number>; test_positives?: number;
  coefficients?: Record<string, number>; per_domain?: Record<string, ModelDomainMetrics>; headline?: string;
  pooled_test?: { pr_auc: number; roc_auc: number; ece: number; n: number; positives: number };
}
export interface EngineConfig {
  contract_version: string; demo_mode: boolean; base_rate: number; thresholds: { medium: number; high: number; critical: number };
  policy_rules: { id: string; band: string | null; reason_any: string[]; actions: string[] }[];
  patterns: { id: string; label: string; bonus: number; sequence: string[]; within_min: number | null; when_detector: string | null; shared_kind: string | null }[];
  models: ModelArtifact[]; twin_forecast: { source: string | null; attacks: number };
}
