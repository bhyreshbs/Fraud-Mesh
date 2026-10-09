# FraudMesh v3: performance (Phase 15)

Target (PRD §1): decision latency p95 < 150 ms at 50 events/s. **Result: met with a wide margin; no engine change was
needed or made.** Every number below is measured; the commands to reproduce them are at the end.

## 1. Engine only: `Pipeline.process` per event

`python -m benchmark.perf_pipeline` → `benchmark/perf_pipeline.json`. The seed-7 benchmark stream (14 days, 2,000
customers, 30 attacks per family, 63,237 events), MemoryStore, no database, no HTTP. Windows 11 laptop, Intel Core
(family 6 model 190), Python 3.12.

| Events | p50 | p95 | p99 | max | mean |
|---|---|---|---|---|---|
| all 63,237 | 1.43 ms | 3.25 ms | 5.36 ms | 1,179 ms | 1.75 ms |
| second half (warm graph and windows) | 1.46 ms | 3.18 ms | 5.45 ms | 1,179 ms | 1.82 ms |

| Event type | n | p50 | p95 | p99 |
|---|---|---|---|---|
| login | 31,965 | 0.81 ms | 1.38 ms | 2.04 ms |
| transaction | 29,941 | 2.47 ms | 3.75 ms | 6.69 ms |
| payee_added | 1,216 | 0.68 ms | 6.79 ms | 9.57 ms |
| mfa_change | 85 | 1.62 ms | 2.97 ms | 4.89 ms |
| kyc_result / profile_change / cloud_audit | 30 | 1.3–1.8 ms | ≤ 2.0 ms | ≤ 3.4 ms |

Throughput on one core: **537 events/s** (10× the 50 events/s target). The single 1.18 s maximum is one event out of
63,237; its cause was not isolated (it can be a one-off such as garbage collection or a large case recompute). p99 stays
under 7 ms for every event type.

## 2. End to end through the API (ingest → queue → worker → payment outcome)

`scripts/perf.py --rate 50 --seconds 120` in the CI `e2e` job (GitHub Linux runner, uvicorn + Postgres 16, the real
engine), on the v3 head before this phase (commit `29844e6`; the API code is the same in this release):

| | p50 | p95 | max |
|---|---|---|---|
| Ingest (POST /v1/events, signed, 202) | 3.7 ms | 4.9 ms | 131 ms |
| **Decision** (received → payment outcome row) | **4.7 ms** | **6.0 ms** | 14.8 ms |

6,000 events at 50.0/s, all accepted (202), 2,900 of 2,900 transactions decided. The CI job re-measures this on every
push and fails if decision p95 ≥ 150 ms.

**Local Windows numbers are not representative.** The same script against a v3 API on this laptop (Docker Desktop
Postgres) reached an ingest p95 of 3.8–9.7 s and then a client read error: every database round trip crosses the
Docker Desktop VM boundary, the same effect that makes the full demo reset take ~9 min here (README §13). Use the CI
numbers, or a Linux host, for latency claims.

## 3. Where the engine time goes

`python -m benchmark.perf_pipeline --customers 600 --profile` (cumulative time over 19,746 events, 62 s profiled):

| Share | What |
|---|---|
| ~32 % | txn detector: LightGBM predict + SHAP contributions (two booster calls per transaction) and isotonic calibration |
| ~24 % | graph detector: seed paths (`EntityGraph.seed_paths`, ~10 %), mule profiles and APP-scam assessment |
| ~18 % (of the profiled time) | pydantic deep copies inside **MemoryStore** (insert_event, list_evidence, upsert_edges) |
| ~11 % | behaviour model (logistic regression + isotonic) |
| rest | feature windows, fusion recompute, joiner |

## 4. Options evaluated

| Option | Decision | Why |
|---|---|---|
| One LightGBM call instead of two (probability = sigmoid of the summed SHAP contributions) | **Rejected** | Measured on 9,270 real transactions: not bit-identical (max difference 3.3e-15; 3 calibrated probabilities differ in the 15th decimal). The phase rule is "result-identical only", and the golden tests assert exact values. Saving would be ~0.4 ms per transaction. |
| Faster MemoryStore (no deep copies) | **Not done** | MemoryStore is the test and benchmark store; production uses PgStore. It would flatter benchmark timings without changing production latency, and the copies protect stored objects from mutation. |
| Per-customer worker sharding | **Not done** | `engine_lock` serialises `Pipeline.process` with feedback, manual actions, the graph view and the demo reset, and every shard would mutate the one shared in-memory entity graph (joins cross customers by design: mule fan-in). Sharding is unsafe without partitioning the graph, and unnecessary at 6 ms p95. |
| Cached seed distances | **Not done** | `seed_paths` is ~10 % of engine time (~0.2 ms/event). A cache needs invalidation on every new edge and every feedback seed; not worth the correctness risk at this headroom. |
| EMA customer baselines | **Not done** | Would change feature values, so the model inputs and the benchmark would move; it is a modelling change, not a performance fix. |
| Separate synchronous decision from slower enrichment | **Already in place** | Network enrichment runs at ingestion from local files (microseconds); the payment rail runs after the engine lock is released (`api/worker.py`); late evidence re-scores held payments before settlement (v3 11.6). |
| Distributed infrastructure | **Not introduced** | One FIFO worker sustains 537 events/s of engine work; the target is 50. |

## 5. Reproduce

```bash
python -m benchmark.perf_pipeline                          # engine latency -> benchmark/perf_pipeline.json (~2 min)
python -m benchmark.perf_pipeline --customers 600 --profile --no-write
python scripts/perf.py --rate 50 --seconds 120             # against a running API on Linux (CI e2e job)
```
