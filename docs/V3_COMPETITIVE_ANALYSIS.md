# FraudMesh v3: competitive analysis

Status: working document, 2026-10-10. Base commit `11ff892` (contract 1.1.0).
Author's stance: fraud-prevention market analyst. This document makes **no claim that FraudMesh outperforms any
commercial platform**. FraudMesh is a hackathon-scale prototype evaluated mostly on synthetic data; the vendors below
run production systems at scale. The comparison is about *scope and architecture*, not measured performance.

## How to read this document

- **Verified (✓)**: the capability is described on the vendor's own public page or documentation, fetched on
  2026-10-10. The URL is cited. "Verified" means *the vendor says it offers this*; it does not mean we tested it, and
  vendor performance figures are vendor claims.
- **Assumed (~)**: plausible from general market knowledge, or only implied by marketing copy, but **not verified**
  on a vendor page during this review. Treat as *assumption / not verified*.
- **Not offered (–)**: used only for FraudMesh, where the repo shows the capability is absent. For vendors we never
  write "not offered"; absence of evidence on a page is recorded as "~ not verified".
- FraudMesh claims cite repository paths. Anything other engineers are building in parallel is marked
  **v3 in progress, verify before claiming**.

### Vendor sources consulted

| Ref | Vendor | URL |
|---|---|---|
| [FZ1] | Feedzai | https://www.feedzai.com/resource/end-to-end-defense-against-mule-networks/ |
| [FZ2] | Feedzai | https://www.feedzai.com/fraud/ |
| [FZ3] | Feedzai | https://www.feedzai.com/blog/money-mule-red-flags-and-how-to-spot-them/ (search-result summary only; not fetched) |
| [BC1] | BioCatch | https://www.biocatch.com/account-takeover-protection/remote-access-attacks |
| [BC2] | BioCatch | https://www.biocatch.com/social-engineering-scams-demo |
| [PP1] | PayPal | https://developer.paypal.com/docs/checkout/advanced/customize/fraud-protection/fraud-protection-advanced/ |
| [PP2] | PayPal | https://www.paypal.com/us/cshelp/article/what-is-multi-factor-authentication-and-a-remembered-device-help1156 |
| [SD1] | Sardine | https://www.sardine.ai/blog/protecting-victims-from-remote-access-scams-at-sardine-ai |
| [SD2] | Sardine | https://www.sardine.ai/blog/device-intelligence-and-behavior-biometrics-work-better-together |
| [SD3] | Sardine | https://www.sardine.ai/identity-fraud |
| [SD4] | Sardine | https://docs.sardine.ai/guides/public/getting-started/what-powers-sardine |
| [SE1] | SEON | https://docs.seon.io/getting-started/device-intelligence |
| [SE2] | SEON | https://docs.seon.io/knowledge-base/transactions-scoring/default-rules |
| [FP1] | Fingerprint | https://docs.fingerprint.com/docs/smart-signals-introduction |
| [FS1] | Featurespace | https://www.featurespace.com/solutions/aric-white-label |
| [FS2] | Featurespace | https://www.featurespace.com/newsroom/adaptive-behavioral-risk-models-automatically-protect-consumers |
| [FS3] | Featurespace | https://www.featurespace.com/newsroom/featurespace-launches-aric-scam-detect-to-protect-the-financial-services-industry-and-outsmart-scammers |
| [CF1] | Cloudflare | https://blog.cloudflare.com/detecting-cgn-to-reduce-collateral-damage/ |

Pages that could not be read: `https://www.featurespace.com/products/aric-risk-hub/` (rendered only "Loading...") and
the BioCatch vishing/APP data sheet PDF (not text-extractable). Nothing in this document relies on them.

---

## 1. Feature-by-feature comparison

Legend: ✓ verified (with ref) · ~ assumption / not verified · – not offered (FraudMesh only).
FraudMesh column: **✓** implemented in the repo (see §2 for paths) · **demo** implemented but only against
demo/synthetic inputs · **v3 WIP** being built in parallel, verify before claiming · **–** absent.

| Capability | FraudMesh | Feedzai | BioCatch | PayPal | Sardine | SEON | Fingerprint | Featurespace | Cloudflare |
|---|---|---|---|---|---|---|---|---|---|
| Real-time transaction risk scoring | ✓ (LightGBM, synthetic + public data) | ✓ "stop fraud in real time" [FZ2] | ~ | ✓ 0–100 risk score [PP1] | ~ | ~ | ~ | ✓ "within seconds" [FS1] | ~ |
| Approve / block / review actions on payments | ✓ hold / block (policy bands) | ✓ approve or block [FZ2] | ~ (Rule Manager seen only in search summary) | ✓ filters approve/reject/review [PP1] | ~ | ~ | ~ | ~ | ~ |
| Adaptive per-customer behavioural profiling | partial (30-day medians, first-seen device/ASN features) | ✓ "adaptive, unique profiles for every individual" [FZ2] | ~ | ~ | ~ | ~ | ~ | ✓ ABA "models normal customer behavior" [FS1][FS2] | ~ |
| Behavioural biometrics (keystroke, mouse, touch) | – (contract 1.1.0 has coarse telemetry fields only; no detector consumes them) | ~ (mentioned on [FZ2], not detailed) | ✓ [BC1] | ~ | ✓ keystroke, mouse, touch [SD2] | ~ | ~ | ~ | ~ |
| Remote-access-tool (RAT) detection | – (demo-only flag in contract 1.1.0 telemetry) | ~ | ✓ [BC1] | ~ | ✓ TeamViewer/AnyDesk/RDP etc. [SD1] | ✓ rule P113 open remote-access ports [SE2] | ~ | ~ | ~ |
| Social-engineering / APP scam detection | demo (`scenarios/scam_app.yaml`, payee-name-mismatch → transfer pattern) | ✓ social engineering [FZ2] | ✓ authorized payment fraud [BC2] | ~ | ✓ coached / remote-access scams [SD1] | ~ | ~ | ✓ ARIC Scam Detect [FS3] | ~ |
| Active-call signal | – (demo-only flag in contract 1.1.0) | ~ | ~ | ~ | ~ | ~ | ✓ "Active Call Detection" [FP1] | ~ | ~ |
| Account-takeover detection (multi-signal) | ✓ (synthetic chains) | ✓ ATO listed [FZ2] | ✓ ATO use cases [BC1] | ~ | ~ | ~ | ~ | ✓ "scams and account takeovers" [FS3] | ~ |
| Step-up MFA / remembered device | demo (SMS OTP + push to simulated phones) | ~ | ~ | ✓ MFA, remembered device, extra prompts [PP2] | ~ | ~ | ~ | ~ | ~ |
| Device fingerprint / persistent device ID | demo (FingerprintJS in bank demo; tokenized device id) | ~ | ~ | ✓ device data passed via `PAYPAL-CLIENT-METADATA-ID` [PP1] | ✓ persistent device fingerprinting [SD3] | ✓ unique device IDs [SE1] | ✓ [FP1] | ~ | ~ |
| VPN / proxy / Tor detection | – (`NetworkType` enum exists in contract 1.1.0; network intel is v3 WIP) | ~ | ~ | ~ | ~ | ✓ P103 Tor, P105/P112 proxy, HC134 VPN/proxy [SE2] | ✓ Browser/Mobile VPN, Proxy, IP Blocklist [FP1] | ~ | ✓ classifier separates CGNAT from VPN/proxy IPs [CF1] |
| Emulator / VM / tampering detection | – | ~ | ~ (mobile signals seen only in search summary) | ~ | ✓ emulators, bots [SD2] | ✓ HC108 emulator, HC121/HC125 [SE2] | ✓ VM, emulator, tampering, Frida [FP1] | ~ | ~ |
| Shared-IP / CGNAT handling | ✓ static CGNAT list excluded from joins (`engine/detectors/rules/cgnat.txt`); classification is v3 WIP | ~ | ~ | ~ | ~ | ✓ public-proxy (shared) rule P112 [SE2] | ~ | ~ | ✓ supervised CGNAT classifier [CF1] |
| Entity graph / link analysis | ✓ NetworkX graph (`engine/graph/`) | ✓ graph analytics over accounts, devices, networks, identities [FZ1] | ~ | ~ | ✓ links accounts, devices, identities [SD3] | ~ | ~ | ~ | ~ |
| Money-mule / ring detection | ✓ seed distance + mule flow (synthetic) | ✓ "expose and dismantle mule rings" [FZ1] | ~ | ~ | ✓ money mule networks [SD3] | ~ | ~ | ~ | ~ |
| Cross-institution / consortium data | – | ~ (network-level signals seen only in search summary) | ~ | ~ | ✓ "links devices, identities ... across institutions" [SD3] | ~ | ~ | ~ | ~ (network-wide view implied by [CF1], not a fraud consortium) |
| Cyber / SOC signals joined to customer cases (IDS, cloud audit) | ✓ Suricata EVE + Sigma-style cloud audit rules | ~ | ~ | ~ | ~ | ~ | ~ | ~ | ~ |
| KYC result signals in the same case | ✓ (`engine/detectors/kyc.py`, synthetic inputs) | ✓ onboarding linked to payments [FZ1] | ~ | ~ | ✓ identity fraud pre-account-creation [SD3] | ~ | ~ | ~ | ~ |
| Explainable decisions | ✓ exact log-odds waterfall + cited narrative | ✓ "explainable AI models" [FZ2] | ~ | ~ | ~ | ✓ rules with named scores [SE2] | ~ | ~ (not stated on fetched pages) | ~ |
| Rule editor / custom rules | partial (YAML/JSON config, no UI editor) | ~ | ✓ Rule Manager (search summary) ~ | ✓ custom filters, lists [PP1] | ~ | ✓ default + custom rules [SE2] | ~ | ✓ business rule editor [FS1] | ~ |
| Earliest-intervention replay / ablation | ✓ (`engine/replay/`) | ~ | ~ | ~ | ~ | ~ | ~ | ~ | ~ |
| Digital-twin policy simulation | ✓ (`engine/twin/`, simulated outcomes) | ~ | ~ | ~ | ~ | ~ | ~ | ~ | ~ |
| Payment hold before settlement (authorize/void) | demo (mock rail; PayPal sandbox adapter) | ~ | ~ | ✓ (risk filters act before approval [PP1]) | ~ | ~ | ~ | ~ | ~ |
| Production scale / deployments | – (single process, laptop demo) | ~ (search summary: "70 billion annual transactions" claim) | ~ (search summary: 18B sessions/month claim) | ~ | ~ | ~ | ~ | ~ (named bank customers in press releases, not fetched) | ~ |

Notes on the table:
- Cells noting "search summary" were seen only in search-engine summaries of vendor pages, not in a page fetched
  during this review. They stay "~" until someone opens the page.
- The "~" cells for FraudMesh-unique rows (replay, digital twin, cyber+customer case joining) mean **we did not find
  vendor evidence either way**. They are *not* evidence that vendors lack the capability. Enterprise platforms
  commonly have simulation, back-testing and case-management tooling that is not on public marketing pages.

---

## 2. FraudMesh current capabilities (implemented in the repo at `11ff892`)

Only capabilities the repository shows as implemented. Inputs are synthetic or demo unless stated.

| Capability | Evidence (paths) | Caveat |
|---|---|---|
| Signed ingestion of 11 event types, HMAC (default) or Ed25519 signatures, PII tokenized before storage | `api/routers/ingest.py`, `engine/common/tokenize.py`, `scripts/sign.py` | Tokenization is HMAC; IPs tokenized at /24 (IPv4) or /64 (IPv6) |
| Contract 1.1.0: optional session, network type, device-consistency and behavioural-telemetry fields | `engine/contracts.py`, `engine/common/tokenize.py`, `docs/CONTRACT_REQUESTS.md` (2026-10-10) | **Schema only.** No detector in `engine/detectors/` reads `telemetry` or `network_type` at this commit |
| Entity graph with hub and static CGNAT exclusion | `engine/graph/`, `engine/graph/resolve.py`, `engine/detectors/rules/cgnat.txt` | CGNAT list is a hand-written demo list, not a classifier |
| Payee reputation (stops popular payees chaining unrelated customers) | `engine/graph/reputation.py`, `engine/detectors/rules/payee_reputation.yaml`, `tests/engine/test_payee_reputation.py` | Rule thresholds, not learned; awaiting Dev 2 review per CONTRACT_REQUESTS |
| 7 detectors (netsec, behaviour, auth, kyc, cyber, graph, txn) emitting evidence with ATT&CK technique | `engine/detectors/` | Behaviour model trained on synthetic logins only (28 attack logins) |
| Reliability-weighted log-odds fusion, sequence patterns, floors | `engine/fusion/`, `engine/fusion/patterns.yaml` | Weights and bonuses hand-set |
| Case joiner (one case per attack) and kill-chain stages S0–S6 | `engine/cases/joiner.py`, `engine/cases/stages.py` | Validated on synthetic attacks |
| Policy bands and actions incl. APP-scam hold rule `app_scam_hold` | `engine/policy/policy.yaml`, `api/worker.py` | `SCAM_WARNING` / `COOLING_OFF_HOLD` actions exist in the contract but the policy wiring is v3 WIP |
| APP scam scenario | `scenarios/scam_app.yaml`, `tests/engine/test_scam_direct.py` | One scripted scenario; no behavioural or call signal involved |
| Step-up: SMS OTP, registered-device push, "Not me" | `api/stepup.py`, `bank-demo/` | Phones are simulated web pages; no telco or push provider |
| Explanation: exact contribution waterfall + narrative citing evidence IDs | `engine/explain/` | Template narrative |
| Replay: earliest intervention, detector ablation, siloed vs fused | `engine/replay/` | Deterministic replay of stored events |
| Policy simulator (threshold sliders) | `engine/replay/simulate.py` | |
| Digital Twin: 8 prevention strategies on isolated copies, stage forecast | `engine/twin/`, `ml/artifacts/twin_transitions.json` | Transitions learned from 120 synthetic labelled attacks; outcomes rest on stated behaviour assumptions |
| Analyst feedback → detector reliability (Beta α/β) and fraud seeds | `engine/feedback.py` | No retraining loop |
| Investigator AI (fixed tools + templates, citations, prompt-injection safe) | `api/investigator/` | Not an LLM; three question types |
| Hash-chained audit log | `api/audit.py` | |
| Live Suricata EVE follower (tail -F, rotation, resumable offset, retry/backoff) | `api/adapters/suricata_live.py`, `api/adapters/suricata.py` | Adapter only; **no live sensor is deployed or tested against real traffic** |
| Payment rail mirror: mock (default) or PayPal sandbox authorize / capture / void | `api/payments/`, `tests/api/test_payment_rail.py` | Tests use `httpx.MockTransport` only; sandbox authorize needs a vaulted method, else `422 ORDER_NOT_APPROVED` |
| Opt-in TLS everywhere, mTLS for senders, Ed25519 signatures, EdDSA JWTs | `scripts/make_certs.py`, `scripts/tls.py`, `README.md` §"Transport security and keys" | Local CA; Docker demo only |
| Benchmark harness (fused vs siloed) | `benchmark/run.py`, `benchmark/report.json`, `benchmark/report_details.json` | Synthetic, seed 7 |

### Measured results (from repo artefacts, not re-run for this document)

| Measure | Value | Source |
|---|---|---|
| Txn model, synthetic bank-event test | PR-AUC 0.9995, ROC-AUC 1.000 | `ml/artifacts/manifest.json` `per_domain.synthetic` |
| Txn model, IEEE-CIS test (147,635 rows, 5,100 fraud ≈ 3.45% prevalence) | PR-AUC 0.0969, ROC-AUC 0.7589 | `ml/artifacts/manifest.json` `per_domain.ieee_cis` |
| Txn model, IBM AMLSim test | PR-AUC 0.7416, ROC-AUC 0.8667 | `ml/artifacts/manifest.json` `per_domain.amlsim` |
| Txn model, pooled test | PR-AUC 0.478, ROC-AUC 0.8295 | `ml/artifacts/manifest.json` `pooled_test` |
| Benchmark strict ("hold before last event"), fused vs siloed | ATO 9/30 vs 0/30; mule fan-in 30/30 vs 30/30; structuring 0/30 vs 30/30 | `benchmark/report.json` |
| Benchmark "at or before last event" | ATO 27/30 vs 29/30; mule 30/30 vs 30/30; structuring 30/30 vs 30/30 | `benchmark/report_details.json` |
| Benign customers flagged HIGH; legit payments stopped | 0 / 1,656; 0 / 24,503 | `benchmark/report.json`, `benchmark/report_details.json` |
| Alert compression | 3.41 : 1 (573 alerts → 168 cases) | `benchmark/report_details.json` |
| Decision latency, 50 events/s, CI runner | p50 ≈ 4–5 ms, p95 ≈ 5–55 ms (target p95 < 150 ms) | `README.md` §4 Performance; Review 1 §7 |

Consistency note: `README.md` and Review 1 quote ATO "at or before" as 26/30 and compression as 3.5:1;
`benchmark/report_details.json` at this commit says 27/30 and 3.41:1. Use the JSON values and reconcile the prose.

**v3.0 rerun (Phase 16, on the fully merged v3 code; the table above is the 2.0 state this analysis started from):**

| Measure | 2.0 | v3.0 (rerun) | Source |
|---|---|---|---|
| Strict benchmark, fused vs siloed | ATO 9/30; structuring 0/30; mule 30/30 | **ATO 19/30** vs 0/30; **structuring 30/30** vs 30/30; mule 30/30 vs 30/30 | `benchmark/report.json` |
| "At or before last event" | ATO 27/30 | ATO 30/30; mule 30/30; structuring 30/30 | `benchmark/report_details.json` |
| Benign customers HIGH; legit payments stopped | 0 / 1,656; 0 / 24,503 | 1 / 1,656; 11 / 24,503 | `benchmark/report_v3.json` |
| Alert compression | 3.41 : 1 | 3.59 : 1 | `benchmark/report.json` |
| Txn model on IEEE-CIS | PR-AUC 0.0969 | 0.0969 (unchanged; not retrained) | `benchmark/report_v3.json` |
| Decision latency, 50 events/s, CI | p50 ≈ 4–5 ms, p95 ≈ 5–55 ms | p50 4.7 ms, p95 6.0 ms | `docs/V3_PERFORMANCE.md` |
| Twin scenario library | – | 14 of 15 scenarios meet their expected behaviour (gap: cloned stolen session) | `docs/V3_SCENARIOS.md` |

These remain synthetic-benchmark results; they are not a comparison with any commercial product.

---

## 3. Weaknesses and gaps (honest view)

1. **Synthetic core.** The cross-silo attack chains (IDS + login + MFA + KYC + cloud + payment for one customer) are
   generated by `ml/generator`. No public dataset links these silos for the same customer, so the headline
   "one case per attack" and "hold 13 minutes before the transfer" results are properties of our own simulator.
   `benchmark/report_details.json` states it directly: "Not a real-world estimate."
2. **Real-data transaction accuracy is weak.** On IEEE-CIS the txn model reaches PR-AUC **0.097** against a test
   prevalence of about **3.5%** (5,100 / 147,635). That is better than random (PR-AUC of a random ranker ≈ prevalence)
   but far from useful as a stand-alone card-fraud model. It uses 11 banking features; card-specific features are
   absent. The synthetic PR-AUC of 0.9995 mainly shows the simulator is learnable.
3. **Strict benchmark is mixed.** Under the PRD's strict definition, fused catches ATO **9/30** (siloed 0/30) but
   structuring **0/30** (siloed 30/30), because fusion is designed not to act on one weak signal. The
   "at or before last event" view looks better but is a different, looser metric. Mule fan-in median "lead time" is
   negative (−1,454 s), i.e. intervention after the first monetization evidence. The Digital Twin's "strong txn
   block" fix is simulated, not in `policy.yaml`.
   *v3.0:* two configurable floors (new payee within 24 h of a takeover; calibrated txn p ≥ 0.90) lift the strict
   counts to ATO 19/30 and structuring 30/30, at a cost of 1 benign customer flagged HIGH of 1,656. 11 ATO attacks are
   still caught only on the transfer (no payee name check, so no payee-step evidence).
4. **Behaviour model is synthetic-only** (21,391 logins, 28 attack logins; test positives 13). Its PR-AUC 1.0 in
   `ml/artifacts/manifest.json` says nothing about real login risk.
5. **No live sensors.** The Suricata follower exists, but no real sensor, cloud audit stream (CloudTrail / Azure AD),
   telco SIM-swap API or KYC vendor is connected. The demo IDS sensor stands in for Suricata.
6. **Demo-only phones and bank front end.** SMS OTP and push go to simulated phones in `bank-demo/`; there is no
   real push provider, telco, or core-banking integration. PayPal integration is sandbox/mock only.
7. **Single-process worker.** One asyncio worker task (`api/worker.py`) consumes events FIFO; the graph is in memory
   and rebuilt at startup; no Kafka, no sharding, no HA. Latency numbers are at 50 events/s on CI runners.
8. **No device, network or behavioural intelligence of its own.** No VPN/proxy/Tor/emulator/tampering detection, no
   behavioural biometrics, no consortium data. These are the core of SEON, Fingerprint, Sardine and BioCatch.
   Contract 1.1.0 only adds the *fields*.
9. **Static rules and hand-set weights.** CGNAT list, payee-reputation thresholds, pattern bonuses and fusion clips
   are hand-tuned on synthetic data; Beta reliability updates are the only learning from feedback.
10. **No fairness, drift or false-decline analysis on real customers**, and no regulatory validation (model risk
    management, PSD3/APP reimbursement rules, RBI guidance).

---

## 4. Genuine differentiators: hypotheses, not findings

FraudMesh's *design* differs from the point solutions above in a few ways. Each is a **hypothesis** about value.
None is demonstrated against a real deployment or against any vendor.

| Hypothesis | Why it might matter | What the repo shows today | Evidence needed to substantiate |
|---|---|---|---|
| H1. One case across fraud + identity + auth + KYC + cyber + payment + graph signals finds multi-stage attacks earlier than siloed tools | Each silo sees weak signals; ATO chains span teams | Synthetic: ATO strict 9/30 fused vs 0/30 siloed; 0 benign HIGH | Labelled, linked real event logs from at least one bank (or a consortium) with incident ground truth; comparison against the bank's existing siloed alerts on the same period |
| H2. Explanations that cite every evidence and decision ID reduce analyst time and improve auditability | Regulators and analysts need reasons | Exact waterfall + cited template narrative | Analyst study: time-to-decision and agreement rate with vs without the explanation; model-risk reviewer assessment |
| H3. Earliest-intervention replay and ablation help tune policies | Shows *when* a case could have been stopped and which detector mattered | `engine/replay/` on stored events | Back-test on real historical incidents; show policy changes chosen with replay reduce loss or friction in a subsequent period |
| H4. A digital twin can compare prevention strategies before changing live policy | Avoids learning in production | 8 strategies on synthetic held-out attacks; outcomes under stated assumptions | Calibrate twin assumptions (customer response times, attacker behaviour) on real data; check twin predictions against outcomes of a real A/B policy change |
| H5. Intervention before settlement (hold = authorize only, block = void) limits loss without irrevocable declines | Holds can be released on false positives | Mock rail and PayPal sandbox adapter; feedback releases or voids | A real rail integration with authorize/capture semantics; measure released-hold rate, customer complaints and recovered value |
| H6. Cyber signals (IDS, cloud admin audit) joined to customer cases add detection value | Insider and support-console abuse often precede ATO cash-out | Midnight ATO uses `pat_CASE_IP_CLOUD`; Suricata adapters | Real SOC + fraud data for the same customers; ablation showing incremental lift from cyber evidence |

Important: enterprise vendors may already offer similar cross-channel orchestration (Feedzai's "continuous risk
journey" across onboarding, monitoring and payments [FZ1]; Featurespace scoring scams and ATO together [FS3]). The
unification claim must therefore be phrased as "FraudMesh is designed around X", never "only FraudMesh does X".

---

## 5. Planned or in-progress features that must NOT be presented as implemented

### v3 in progress (parallel work; verify on `main` before claiming)
- ATO and structuring floors (to close the strict-benchmark gap).
- Shared-IP classification (beyond the static CGNAT list).
- Distributed credential-stuffing detection.
- Network intelligence (populating and using `network_type`: residential / mobile / hosting / VPN / Tor).
- Session-context-change detection (`SESSION_CONTEXT_CHANGE`) and device consistency checks.
- Seed-independent mule detection.
- Insider two-person approval.
- Application security hardening (beyond what README §8 describes).
- Firebase boundary.
- Consumption of contract 1.1.0 behavioural telemetry by any detector.
- Policy wiring of `SCAM_WARNING` and `COOLING_OFF_HOLD` actions.

### Future work only (README §14, PRD §1 out-of-scope list)
- Real login dataset for the behaviour model (RBA dataset); real telco SIM-swap, cloud audit and bank integrations.
- Graph ML (GNN, personalized PageRank, Louvain/community detection); learned mule-risk scores.
- Sequence models (HMM / transformer) for stage forecasting.
- Online retraining with drift monitoring; drift panel.
- Kafka, partitioned workers, graph database (Neo4j); horizontal scale.
- Keystroke timing / real behavioural biometrics, packet inspection, native mobile apps, live LLM answers.
- Fairness and false-decline analysis.
- The Twin's "FraudMesh + strong txn block" strategy in the live policy.

### Implemented but demo-grade (say so explicitly when presenting)
- Live Suricata follower (adapter exists; never run against a production sensor).
- PayPal rail (mock by default; sandbox adapter tested only against mocked HTTP).
- APP scam detection (one scripted scenario; no behavioural or call signals).
- TLS/mTLS/Ed25519/EdDSA (local CA, Docker demo).
- Step-up phones (simulated).

---

## 6. Evidence needed to substantiate any performance claim

Until the following exist, external material should say "on synthetic data" next to every FraudMesh number and
make no comparative performance claim against vendors.

1. **Comparable datasets.** Run the same models on public benchmarks vendors and academics also report on
   (IEEE-CIS, Feedzai's Bank Account Fraud suite, AMLSim / AMLworld, the RBA login dataset), with time-based splits
   and the metrics used in the literature (PR-AUC, recall at fixed FPR, value detection rate). Vendor numbers are
   rarely published on public data, so this supports *academic* comparison, not vendor comparison.
2. **Labelled real data with linked silos.** Fraud labels (confirmed fraud, chargebacks, APP reimbursement claims)
   joined to login, MFA, KYC, SOC and payment events for the same customers, under a data-sharing agreement. This is
   the only way to test H1.
3. **Shadow mode, then A/B.** Run FraudMesh in shadow alongside the incumbent stack; then a randomised policy A/B
   (or champion/challenger) measuring fraud loss, detection lead time, alerts per analyst, and customer friction.
4. **Latency and throughput under realistic load.** Sustained peak-hour event rates (not 50 events/s), multi-process
   or sharded workers, p99 latency, backlog behaviour on failure, graph size at millions of entities, and recovery
   time after restart.
5. **False-positive cost.** False-decline rate and held-payment release rate on genuine customers, step-up
   abandonment, complaint and call-centre volume, and the monetary cost per false positive; the current
   "0 / 1,656 benign flagged" is synthetic.
6. **Calibration on the deployment domain.** Per-domain calibration and reliability diagrams on live traffic; the
   current isotonic calibration is fitted on mixed domains.
7. **Independent review.** Model-risk validation, red-team of the adversarial assumptions (attackers who avoid new
   devices, slow-roll chains past the 6 h / 72 h join windows), and a privacy/legal review of HMAC tokenization.
8. **Twin validation.** Compare twin forecasts and strategy rankings with real outcomes of at least one policy change.

---

## Appendix: vendor claims that could not be verified in this review

These appeared only in search-engine summaries or were absent from fetched pages; treat them as unverified:
- Feedzai: "70 billion annual transactions" (Feedzai IQ), federated / consortium learning, device intelligence and
  behavioural biometrics details (mentioned on [FZ2] but not described).
- BioCatch: "18 billion sessions per month" and "$4 billion prevented" figures; Rule Manager decline/defer actions
  (data sheet PDF not extractable); mobile emulator/tap signals; any active-call signal.
- PayPal: a dedicated consumer account-takeover risk product beyond MFA/remembered-device prompts [PP2]; risk-based
  triggering of those prompts (the page does not say what triggers them).
- Sardine: VPN/proxy/"true IP" detection specifics; "detect all signups and logins from remote software" is a
  vendor self-claim [SD1]; ~90% automation and 5–10% emulator-signup statistics.
- SEON: accuracy or false-positive rates for VPN / residential-proxy detection (none published on fetched pages).
- Fingerprint: accuracy of any Smart Signal; roadmap items (ML-based VPN detection, VPN confidence levels).
- Featurespace: explainability / reason codes; per-individual (vs population) profiling; "up to 76% fewer false
  positives" and similar figures; the ARIC Risk Hub product page did not render.
- Cloudflare: its CGNAT classifier metrics (0.98 accuracy, 0.97 weighted F1) are published by Cloudflare [CF1] and
  are not independently verified; whether the detection is exposed as a customer-facing signal was not verified.
