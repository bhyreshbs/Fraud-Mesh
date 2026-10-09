"""The scenario API of PRD §16.1, for Dev 1's tools (play.py, load.py, /v1/demo/run, /v1/demo/reset).

Uses Dev 2's ml.scenario when it is importable (the frozen signatures). Until then, a DEV1 FALLBACK below implements the
same signatures over the §12.2 file format, reading scenarios/<id>.yaml (Dev 2) or fixtures/api/scenarios/<id>.yaml
(Dev 1 fallback copies). Delete the fallback once ml.scenario is merged.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIRS = [ROOT / "scenarios", ROOT / "fixtures" / "api" / "scenarios"]
SCENARIO_IDS = ("midnight_ato", "mule_fanin", "benign_odd", "scam_app",   # scam_app: APP scam (future-work scenario)
                "mule_ring_noseed", "popular_merchant_legit", "insider_trusted_network",   # v3 graph/scam/insider
                "structuring_split", "device_multi_account", "benign_vpn", "residential_proxy_ato",   # v3 phase 15 twin
                "session_replay_clone", "remote_access_demo", "appsec_payloads")   # library
# scenarios/late_evidence_feedback.yaml is benchmark-only (benchmark/twin_scenarios.py): its steps are in ARRIVAL order,
# with two delayed events listed after the transfer, and the API autopilot plays steps in occurred_at order.

try:                                                                   # Dev 2's implementation wins when present
    from ml.scenario import (  # type: ignore[import-not-found]  # noqa: F401
        Scenario,
        StepUpAction,
        expand,
        labels_for,
        load_scenario,
        preload_envelopes,
        seed_tokens,
    )
    SOURCE = "ml.scenario"
except ImportError:
    import yaml

    from engine.common.ids import new_id
    from engine.common.tokenize import tok
    from engine.contracts import Envelope, Label

    SOURCE = "dev1-fallback"

    @dataclass(frozen=True)
    class StepUpAction:
        at: datetime
        channel: Literal["app", "phone"]
        as_identity: str
        decision: str | None          # "approve" | "deny" for channel phone
        direct_payload: dict          # StepUpResultPayload fields minus challenge_id

    @dataclass(frozen=True)
    class Scenario:
        id: str
        default_start: datetime
        raw: dict                     # parsed YAML

    def load_scenario(path: str) -> Scenario:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return Scenario(id=raw["id"], default_start=datetime.fromisoformat(str(raw["default_start"])), raw=raw)

    def _identity(sc: Scenario, name: str | None) -> tuple[dict, dict]:
        ident = sc.raw.get("identities", {}).get(name) if name else None
        if name and ident is None:
            raise KeyError(f"scenario {sc.id}: unknown identity {name!r}")
        ident = ident or {}
        subject = {k: str(v) for k, v in (ident.get("subject") or {}).items()}
        context = {k: (str(v) if k in ("ip", "device_id", "asn", "city") else v) for k, v in (ident.get("context") or {}).items()}
        return subject, context

    def _envelope(sc: Scenario, step: dict, at: datetime) -> Envelope:
        subject, context = _identity(sc, step.get("as"))
        return Envelope(event_id=new_id("evt"), event_type=step["type"], source=step["source"], occurred_at=at,
                        subject=subject, context=context, payload=dict(step["payload"]))

    def _timed(items: list[dict], start: datetime) -> list[tuple[datetime, dict]]:
        seen: dict[int, int] = {}
        out = []
        for step in items:
            pos = seen.get(step["at_min"], 0)
            seen[step["at_min"]] = pos + 1
            out.append((start + timedelta(minutes=step["at_min"], seconds=10 * pos), step))
        return sorted(out, key=lambda x: x[0])

    def expand(sc: Scenario, start: datetime, mode: Literal["api", "direct"]) -> list[Envelope | StepUpAction]:
        """occurred_at = start + at_min + 10 s x position among steps sharing that at_min (PRD §12.2). In direct mode
        every StepUpAction becomes a step_up_result Envelope with challenge_id "chl_direct"."""
        out: list[Envelope | StepUpAction] = []
        for at, step in _timed(sc.raw.get("steps", []), start):
            if step.get("action") == "step_up_respond":
                if mode == "direct":
                    subject, context = _identity(sc, step.get("as"))
                    out.append(Envelope(event_id=new_id("evt"), event_type="step_up_result", source="demo-bank-web",
                                        occurred_at=at, subject=subject, context=context,
                                        payload={"challenge_id": "chl_direct", **step["direct_payload"]}))
                else:
                    out.append(StepUpAction(at=at, channel=step["channel"], as_identity=step["as"],
                                            decision=step.get("decision"), direct_payload=dict(step["direct_payload"])))
            else:
                out.append(_envelope(sc, step, at))
        return out

    def preload_envelopes(sc: Scenario, start: datetime) -> list[Envelope]:
        return [_envelope(sc, step, at) for at, step in _timed(sc.raw.get("preload", []), start)]

    def seed_tokens(sc: Scenario) -> list[str]:
        return [tok(s["kind"], str(s["raw"])) for s in sc.raw.get("seeds", []) or []]

    def labels_for(sc: Scenario, envelopes: list[Envelope]) -> list[Label]:
        lab = sc.raw.get("labels") or {}
        return [Label(event_id=e.event_id, scenario=sc.id, is_attack=bool(lab.get("is_attack")), attack_id=lab.get("attack_id"))
                for e in envelopes]


def scenario_path(scenario_id: str) -> Path | None:
    """scenarios/<id>.yaml (Dev 2) if present, else the Dev 1 fallback copy. Only the three PRD scenario ids resolve."""
    if scenario_id not in SCENARIO_IDS:
        return None
    for d in SCENARIO_DIRS:
        p = d / f"{scenario_id}.yaml"
        if p.exists():
            return p
    return None


def resolve(scenario: str) -> Path:
    """Accepts a scenario id or a path to a YAML file."""
    p = scenario_path(scenario)
    if p:
        return p
    p = Path(scenario)
    if p.exists():
        return p
    raise FileNotFoundError(f"unknown scenario {scenario!r}")
