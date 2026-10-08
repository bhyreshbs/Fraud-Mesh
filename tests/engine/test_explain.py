"""Explanation (PRD §10.10): parts sum to log_odds; every narrative sentence cites at least one existing ID."""
from __future__ import annotations

from datetime import timedelta

import pytest

from engine.api import explain_case
from engine.common.tokenize import tok
from engine.contracts import Case, Evidence, Explanation, Reason
from engine.explain.narrative import indian_amount
from engine.fusion.fusion import Fusion
from engine.store_memory import MemoryStore
from ml.build_fixtures import golden_evidence, golden_store


@pytest.fixture(scope="module")
def golden():
    store, case = golden_store()
    return store, case, explain_case(store, case.case_id)


def known_ids(store, case) -> set[str]:
    return ({e.evidence_id for e in store.list_evidence(case.case_id)} | set(case.pattern_hits)
            | {d.decision_id for d in store.list_decisions(case.case_id)})


def test_parts_sum_to_the_case_log_odds(golden):
    _, case, x = golden
    assert sum(p.contribution for p in x.parts) == pytest.approx(case.log_odds, abs=1e-9)
    assert x.parts[-1].running_log_odds == pytest.approx(case.log_odds, abs=1e-9) == pytest.approx(x.final_log_odds)
    assert x.prior_log_odds == pytest.approx(-4.595, abs=1e-3) and x.p_attack == pytest.approx(0.997, abs=1e-3)
    assert x.band == "CRITICAL"


def test_part_order_patterns_follow_the_completing_evidence(golden):
    _, _, x = golden
    ids = [p.part_id for p in x.parts]
    assert ids == ["prior", "ev_demo_01", "ev_demo_02", "ev_demo_03", "pat_ATO1", "ev_demo_04", "ev_demo_05", "ev_demo_06",
                   "pat_CASE_IP_CLOUD", "ev_demo_07", "ev_demo_08"]
    assert [round(p.contribution, 3) for p in x.parts if p.kind == "evidence"] == [0.280, 0.990, 0.645, 1.507, 1.106, 0.709,
                                                                                  1.918, 2.550]
    assert all(a.running_log_odds == pytest.approx(b.running_log_odds - b.contribution) for a, b in zip(x.parts, x.parts[1:], strict=False))


def test_every_sentence_cites_an_existing_id(golden):
    store, case, x = golden
    ids = known_ids(store, case)
    assert len(x.narrative) == 9                                          # 8 evidence sentences + the closing one
    for s in x.narrative:
        assert s.cites and set(s.cites) <= ids, s
        assert all(f"[{c}]" in s.text for c in s.cites)


def test_narrative_content(golden):
    _, _, x = golden
    text = [s.text for s in x.narrative]
    assert text[0].startswith("At 00:39 a severity-2 IDS alert was seen from IP ")
    assert "Rs 4,80,000" in text[7] and "(T1098)" in text[5] and "[pat_ATO1]" in text[2]
    assert text[-1].startswith("FraudMesh first intervened at 00:52 with a hold on outbound payments")
    assert "185.220" not in " ".join(text)                                # no raw IP anywhere


def test_seed_path_and_shap(golden):
    _, _, x = golden
    assert [tok("acct", "A-RAVI-778"), tok("dev", "fp_mule_shared")] in x.seed_paths
    assert x.shap_by_evidence == {}                                       # fixture items carry no SHAP
    Explanation.model_validate_json(x.model_dump_json())


def test_no_floor_part_when_no_floor_raised_the_band(golden):
    _, _, x = golden
    assert not [p for p in x.parts if p.kind == "floor"]                   # the golden case is CRITICAL on its own


def test_floor_part_where_the_floor_raised_the_band():
    """The netsec item alone is LOW; a "Not me" 11 minutes later raises the band to CRITICAL through the floor."""
    netsec = golden_evidence()[0]
    denied = Evidence(evidence_id="ev_demo_09", event_id="evt_demo00000009", detector="auth", detector_version="f",
                      family="device", stage="S2_CONTROL_TAKEOVER", p=0.01, reliability=0.7, entities=[],
                      reasons=[Reason(code="CUSTOMER_DENIED")], ts=netsec.ts + timedelta(minutes=11))
    store = MemoryStore()
    case = Case(case_id="case_floor", anchor_entity="cust:x", customer="cust:x", opened_at=netsec.ts, updated_at=netsec.ts,
                last_event_ts=netsec.ts)
    store.save_case(case)
    for ev in (netsec, denied):
        store.save_evidence(ev, case.case_id)
        Fusion(store).recompute(case)
    store.save_case(case)
    x = explain_case(store, "case_floor")
    assert [p.part_id for p in x.parts] == ["prior", "ev_demo_01", "ev_demo_09", "floor_CUSTOMER_DENIED"]
    assert x.parts[-1].kind == "floor" and x.parts[-1].contribution == 0 and x.band == "CRITICAL"
    assert sum(p.contribution for p in x.parts) == pytest.approx(case.log_odds, abs=1e-9)


def test_indian_amount():
    assert [indian_amount(p) for p in (48_000_000, 99_900, 1_234_567_800, 5_000)] == ["4,80,000", "999", "1,23,45,678", "50"]


def test_unknown_case():
    store, _ = golden_store()
    with pytest.raises(KeyError):
        explain_case(store, "case_missing")
