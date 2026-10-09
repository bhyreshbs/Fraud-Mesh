// NammaBank talks only to the /v1/demo/* routes (PRD §9.5). It never holds a signing secret: /demo/emit signs server-side.
import type { ChallengeStatus, Context, DemoEmitResponse, EventType, PaymentStatus, PendingResponse, RespondResponse, SmsInbox, Subject }
  from "../types/contracts";

export const API_BASE: string = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

export class BankError extends Error {
  constructor(public status: number, public code: string, message: string) { super(message); }
}

async function call<T>(path: string, init?: { method?: string; body?: unknown }): Promise<T> {
  let res: Response;
  try {
    res = await fetch(API_BASE + path, { method: init?.method ?? "GET",
      headers: init?.body !== undefined ? { "Content-Type": "application/json" } : undefined,
      body: init?.body !== undefined ? JSON.stringify(init.body) : undefined });
  } catch {
    throw new BankError(0, "NETWORK", `Cannot reach the bank server at ${API_BASE}`);
  }
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new BankError(res.status, data?.error?.code ?? "HTTP_" + res.status, data?.error?.message ?? res.statusText);
  return data as T;
}

export const emit = (event_type: EventType, subject: Subject, context: Context, payload: Record<string, unknown>) =>
  call<DemoEmitResponse>("/v1/demo/emit", { method: "POST", body: { event_type, subject, context, payload } });
export const pendingChallenge = (customer_ref: string, channel: "app" | "phone") =>
  call<PendingResponse>(`/v1/demo/step-up/pending?customer_ref=${encodeURIComponent(customer_ref)}&channel=${channel}`);
export const respond = (challengeId: string, body: { code: string } | { decision: "approve" | "deny" }) =>
  call<RespondResponse>(`/v1/demo/step-up/${challengeId}/respond`, { method: "POST", body });
export const paymentStatus = (eventId: string) => call<PaymentStatus>(`/v1/demo/payment-status/${eventId}`);
export const smsInbox = (phone: string) => call<SmsInbox>(`/v1/demo/sms-inbox?phone=${encodeURIComponent(phone)}`);

export type { ChallengeStatus };
