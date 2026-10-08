# engine/pipeline.py (Phase 0 stub, PRD §6.5 — owned by DEV2, replaced in D2-P2)
from engine.contracts import GraphElements


class Pipeline:
    def __init__(self, store): self.store = store; self._ready = False
    def startup(self): self._ready = True
    def process(self, event): return []
    def set_seeds(self, entity_ids, value=True): self.store.set_fraud_seeds(entity_ids, value)
    def graph_elements(self, case_id, hops=2, max_nodes=300): return GraphElements(nodes=[], edges=[])
    @property
    def ready(self): return self._ready
