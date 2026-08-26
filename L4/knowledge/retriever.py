"""TF-IDF + cosine similarity retrieval over ``L4/knowledge/kb.json``.

RAG grounds L4 claims about the *threat landscape* — "this class's behaviour
matches a known MITRE ATT&CK Mobile technique / YARA rule / India banking
pattern" — never a claim about the specific bytes of this sample (that is
``L4/verify.py``'s job; see its docstring). ``retrieve()`` is the only public
entry point other L4 modules should call; it is deliberately a plain function
over a module-level cached index rather than a class, so callers do not need
to manage lifecycle.

Interface contract (``decisions/plan_l4_agentic_verdicts.md`` §6 — load-bearing,
matched exactly so other agents can build against it in parallel):

```python
@dataclass
class KBMatch:
    kb_id: str
    title: str
    similarity: float
    mitre_techniques: list[str]

def retrieve(query_text: str, top_k: int = 3, min_sim: float = 0.3) -> list[KBMatch]: ...
```
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.pipeline import FeatureUnion

KB_PATH = Path(__file__).resolve().parent / "kb.json"

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _expand_identifiers(text: str) -> str:
    """Append the split components of dotted / camelCase tokens.

    ``sendTextMessage`` -> ``... send Text Message``,
    ``android.telephony.SmsManager`` -> ``... android telephony SmsManager Sms Manager``.
    API names survive obfuscation (T22) where renamed identifiers do not, so
    exposing their word components lets the (word-level) retriever match KB
    descriptions that spell the behaviour out in prose.
    """
    extra: list[str] = []
    for tok in re.findall(r"[A-Za-z][A-Za-z0-9_.$/]{2,}", text):
        for part in re.split(r"[._$/]+", tok):
            if not part:
                continue
            extra.append(part)
            extra.extend(p for p in _CAMEL_RE.split(part) if p)
    return text + " " + " ".join(extra) if extra else text


def _make_vectorizer() -> FeatureUnion:
    """Word TF-IDF (topic match) unioned with char n-grams (robust to renaming
    and partial-token overlap, which plain word matching misses)."""
    return FeatureUnion([
        ("word", TfidfVectorizer(stop_words="english", lowercase=True,
                                 sublinear_tf=True)),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                 lowercase=True, min_df=1)),
    ])


@dataclass
class KBMatch:
    kb_id: str
    title: str
    similarity: float
    mitre_techniques: list[str] = field(default_factory=list)


class _KBIndex:
    """Lazily built, process-wide TF-IDF index over the KB entries."""

    def __init__(self, kb_path: Path = KB_PATH) -> None:
        self.kb_path = kb_path
        self.entries: list[dict[str, Any]] = []
        self.vectorizer: TfidfVectorizer | None = None
        self.matrix = None
        self._load()

    def _load(self) -> None:
        if not self.kb_path.exists():
            # Same discipline as build_kb.py's network degrade: an absent KB
            # is a valid (if useless) state, not a crash. retrieve() on an
            # empty index returns [] for every query.
            self.entries = []
            self.vectorizer = None
            self.matrix = None
            return

        kb = json.loads(self.kb_path.read_text(encoding="utf-8"))
        self.entries = kb.get("entries", [])
        if not self.entries:
            self.vectorizer = None
            self.matrix = None
            return

        documents = [_expand_identifiers(_entry_document(e)) for e in self.entries]
        self.vectorizer = _make_vectorizer()
        self.matrix = self.vectorizer.fit_transform(documents)

    def search(self, query_text: str, top_k: int, min_sim: float) -> list[KBMatch]:
        if not self.entries or self.vectorizer is None:
            return []

        query_vec = self.vectorizer.transform([_expand_identifiers(query_text)])
        sims = cosine_similarity(query_vec, self.matrix)[0]

        ranked = sorted(range(len(sims)), key=lambda i: sims[i], reverse=True)
        matches: list[KBMatch] = []
        for idx in ranked:
            sim = float(sims[idx])
            if sim < min_sim:
                break
            entry = self.entries[idx]
            matches.append(
                KBMatch(
                    kb_id=entry["id"],
                    title=entry.get("title", entry["id"]),
                    similarity=sim,
                    mitre_techniques=list(entry.get("mitre_techniques", [])),
                )
            )
            if len(matches) >= top_k:
                break

        return matches


def _entry_document(entry: dict[str, Any]) -> str:
    """Concatenate the fields worth matching on into one TF-IDF document."""
    parts = [
        entry.get("title", ""),
        entry.get("description", ""),
        " ".join(entry.get("code_indicators", [])),
        " ".join(entry.get("families", [])),
    ]
    return " ".join(p for p in parts if p)


_INDEX: _KBIndex | None = None


def _get_index() -> _KBIndex:
    global _INDEX
    if _INDEX is None:
        _INDEX = _KBIndex()
    return _INDEX


def retrieve(query_text: str, top_k: int = 3, min_sim: float = 0.3) -> list[KBMatch]:
    """Return up to ``top_k`` KB matches for ``query_text`` with similarity
    ``>= min_sim``, ranked highest similarity first. Empty list if nothing
    clears the threshold (the caller should then treat the query as "novel",
    per ``decisions/plan_l4_rag_verdicts.md``)."""
    return _get_index().search(query_text, top_k=top_k, min_sim=min_sim)


def reload_index(kb_path: Path = KB_PATH) -> None:
    """Force a rebuild of the cached index — used by tests that point at a
    fixture KB, and by any caller after ``build_kb.py`` regenerates kb.json
    within the same process."""
    global _INDEX
    _INDEX = _KBIndex(kb_path)
