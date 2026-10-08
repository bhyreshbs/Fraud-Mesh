# FraudMesh — instructions for Claude Code
1. Read docs/PRD.md fully before any task. Then read .devrole (DEV1 or DEV2).
2. Work only on your role's phases (PRD §15 for DEV1, §16 for DEV2), one task at a time.
3. Edit only paths your role owns (PRD §3). Never edit BOTH-FROZEN files.
4. Use identifiers exactly as written in PRD §4–§9. Do not rename or add enum values.
5. Need a contract change? Append to docs/CONTRACT_REQUESTS.md, work around it locally, tell the human.
6. engine/ must not import api/. engine/ must not call datetime.now().
7. Finish each task with its tests green, then commit: "<ROLE> <PHASE-ID>: <summary>".
