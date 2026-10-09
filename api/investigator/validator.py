"""Investigator AI validator (PRD §15.6 task 3): drop any sentence without a valid citation, or with a number that is not
present in tool outputs; count the removals."""
from __future__ import annotations

import re

from engine.contracts import NarrativeSentence

NUMBER = re.compile(r"\d[\d,]*(?:\.\d+)?(?::\d\d)?")
CITATION = re.compile(r"\[[^\]]*\]")


def numbers_in(text: str) -> list[str]:
    return NUMBER.findall(CITATION.sub(" ", text))


def validate(sentences: list[NarrativeSentence], valid_ids: set[str], valid_numbers: set[str]) -> tuple[list[NarrativeSentence], int]:
    kept, removed = [], 0
    for s in sentences:
        ok = bool(s.cites) and all(c in valid_ids for c in s.cites) and all(n in valid_numbers for n in numbers_in(s.text))
        if ok:
            kept.append(s)
        else:
            removed += 1
    return kept, removed
