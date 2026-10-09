// Human labels for contract enums shown in the console. Values stay exactly as in engine/contracts.py.
import type { Action, DetectorId, Stage } from "../types/contracts";

export const DETECTOR: Record<DetectorId, { label: string; icon: string; color: string }> = {
  netsec: { label: "Network IDS", icon: "lan", color: "#7C3AED" },
  behaviour: { label: "Login behaviour", icon: "fingerprint", color: "#0E7490" },
  auth: { label: "Auth & MFA", icon: "key", color: "#B45309" },
  kyc: { label: "KYC", icon: "badge", color: "#BE185D" },
  cyber: { label: "Cloud audit", icon: "cloud", color: "#4338CA" },
  graph: { label: "Entity graph", icon: "hub", color: "#047857" },
  txn: { label: "Transaction model", icon: "payments", color: "#B42318" },
};

export const STAGE_LABEL: Record<Stage, string> = {
  S0_RECON: "Recon", S1_INITIAL_ACCESS: "Initial access", S2_CONTROL_TAKEOVER: "Control takeover",
  S3_IDENTITY_MANIPULATION: "Identity manipulation", S4_ESCALATION: "Escalation", S5_POSITIONING: "Positioning",
  S6_MONETIZATION: "Monetization",
};

export const ACTION_LABEL: Record<Action, string> = {
  ALLOW: "Allow", CAPTCHA_CHALLENGE: "CAPTCHA challenge", STEP_UP_ANY_FACTOR: "Step-up (any factor)",
  STEP_UP_TRUSTED_FACTOR: "Step-up on trusted device", HOLD_OUTBOUND_PAYMENTS: "HOLD outbound payments",
  FREEZE_NEW_PAYEES: "FREEZE new payees", BLOCK_PENDING_PAYMENTS: "BLOCK pending payments", REVOKE_SESSIONS: "REVOKE sessions",
  OPEN_CASE_P2: "Open case P2", OPEN_CASE_P1: "Open case P1",
};

export const REASON_LABEL: Record<string, string> = {
  IDS_SEV1: "IDS alert, severity 1", IDS_SEV2: "IDS alert, severity 2", IDS_SEV3: "IDS alert, severity 3",
  CREDENTIAL_STUFFING_IP: "Credential stuffing from one IP", NEW_DEVICE: "New device", NEW_ASN: "New network (ASN)",
  FAR_FROM_HOME: "Far from home", ODD_HOUR: "Unusual hour", FAILED_LOGINS: "Failed logins", IMPOSSIBLE_TRAVEL: "Impossible travel",
  COLD_START: "Little login history", MFA_CHANGED_AFTER_NEW_DEVICE: "MFA changed right after a new-device login",
  PROFILE_CHANGE_AFTER_NEW_DEVICE: "Profile changed right after a new-device login", MFA_FAIL_THEN_PASS: "MFA failed, then passed",
  PUSH_SPAM: "Push-notification spam", RECENT_SIM_SWAP: "Recent SIM swap",
  STEP_UP_PASSED_WITH_FRESH_FACTOR: "Step-up passed on a freshly changed factor", STEP_UP_FAILED_OR_TIMEOUT: "Step-up failed or timed out",
  STEP_UP_PASSED_TRUSTED: "Step-up passed on a trusted device", CUSTOMER_DENIED: "Customer tapped “Not me”",
  LOW_LIVENESS: "Low liveness", LOW_FACE_MATCH: "Low face match", DOC_TAMPER: "Document tampering", INJECTION_SUSPECTED: "Camera injection suspected",
  cloud_limit_raise_untrusted_ip: "Transfer limit raised from an untrusted IP", bulk_profile_read_support_console: "Bulk profile reads (support console)",
  mfa_reset_by_support_untrusted_ip: "MFA reset by support from an untrusted IP", SEED_DISTANCE_1: "Payee 1 hop from confirmed fraud",
  SEED_DISTANCE_2: "Payee 2 hops from confirmed fraud", SEED_DISTANCE_3: "Payee 3 hops from confirmed fraud",
  PAYEE_NAME_MISMATCH: "Payee name mismatch", MULE_FLOW: "Mule-like money flow", AMOUNT_HIGH_VS_MEDIAN: "Amount far above usual",
  NEW_PAYEE: "New payee", PAYEE_FAN_IN: "Many senders to this payee", STRUCTURING: "Split transfers just under limits",
};

export const reasonText = (code: string) => REASON_LABEL[code] ?? code.replace(/_/g, " ").toLowerCase();

export const signed = (x: number, digits = 2) => (x >= 0 ? "+" : "−") + Math.abs(x).toFixed(digits);

// A short "attack vector" for a case, read from the kill-chain stages it reached (no new data, just a readable label).
export function attackVector(stages: Stage[]): { label: string; icon: string } {
  const has = (s: Stage) => stages.includes(s);
  if (has("S2_CONTROL_TAKEOVER") && (has("S3_IDENTITY_MANIPULATION") || has("S4_ESCALATION"))) return { label: "Account takeover chain", icon: "person_alert" };
  if (has("S2_CONTROL_TAKEOVER")) return { label: "Control takeover (MFA / SIM / profile)", icon: "sim_card_alert" };
  if (has("S3_IDENTITY_MANIPULATION")) return { label: "Identity manipulation (KYC)", icon: "badge" };
  if (has("S4_ESCALATION")) return { label: "Privilege escalation (support console)", icon: "admin_panel_settings" };
  if (has("S5_POSITIONING") && has("S6_MONETIZATION")) return { label: "Mule / payee money flow", icon: "account_tree" };
  if (has("S6_MONETIZATION")) return { label: "Suspicious transfer pattern", icon: "payments" };
  if (has("S5_POSITIONING")) return { label: "Risky payee", icon: "person_add" };
  if (has("S1_INITIAL_ACCESS")) return { label: "Unusual access", icon: "login" };
  if (has("S0_RECON")) return { label: "Reconnaissance (IDS / guessing)", icon: "radar" };
  return { label: "Weak signal", icon: "query_stats" };
}
