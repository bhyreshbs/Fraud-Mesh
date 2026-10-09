"""Cyber-Financial Digital Twin: a simulation-first virtual copy of the bank's entities, built from the events FraudMesh
already stores (no new data sources), in three parts:

  state.py     virtual banking state: customers, sessions, phones/SIMs, payees, limits, updated event by event
  simulate.py  attack and policy simulator: replay a case on isolated copies under alternative prevention strategies
  predict.py   attack progression forecast: stage-to-stage transitions learned from labelled attacks

build.py exposes twin_case() and twin_overview(); the API serves them at /v1/cases/{id}/twin and /v1/twin/overview.
"""
from engine.twin.build import twin_case, twin_overview

__all__ = ["twin_case", "twin_overview"]
