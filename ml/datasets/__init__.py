"""External training datasets for the txn model, converted to FraudMesh events (PRD §7.1 event types).

Each adapter yields events in time order; `common.featurize` runs them through the engine's own feature module
(engine.features.iter_feature_rows), so external rows get exactly the 11 TXN_FEATURES the live engine computes.
The raw files are not in the repository (size, licences): see README "ML training data".
"""
