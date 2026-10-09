"""The live detector set, in the PRD §10.1 order: netsec, behaviour, auth, kyc, cyber, graph, txn."""
from __future__ import annotations

from engine.detectors.auth import AuthDetector
from engine.detectors.base import DETECTOR_ORDER, Detector
from engine.detectors.behaviour import BehaviourDetector
from engine.detectors.cyber import CyberDetector
from engine.detectors.graph_det import GraphDetector
from engine.detectors.kyc import KycDetector
from engine.detectors.netsec import NetsecDetector
from engine.detectors.txn import TxnDetector


def default_detectors() -> list[Detector]:
    dets: list[Detector] = [NetsecDetector(), BehaviourDetector(), AuthDetector(), KycDetector(), CyberDetector(),
                            GraphDetector(), TxnDetector()]
    assert [d.id for d in dets] == list(DETECTOR_ORDER)
    return dets
