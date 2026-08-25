"""corpus_labels.general_population — the guard against a registered-but-not-
folded-in subclass leaking into A4/L5/evaluate's headline numbers.

Regression: registering CICMalDroid's banking split (subclass="banking", so
L3b/dataset.py can find it) silently changed L5/validate_policy.py's measured
gate rates from a malware denominator of ~654 to 3052, even though the human
decision was explicitly "keep it separate" (CLAUDE.md's CICMalDroid section).
Nothing errored; the population just grew underneath every consumer that
didn't know to exclude it.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.corpus_labels import general_population  # noqa: E402


def test_a_registered_banking_subclass_sample_is_excluded():
    labels = {
        "a" * 64: {"class": "malware", "subclass": "banking"},
        "b" * 64: {"class": "malware"},
        "c" * 64: {"class": "benign"},
    }
    out = general_population(labels)
    assert "a" * 64 not in out
    assert set(out) == {"b" * 64, "c" * 64}


def test_a_sample_with_no_subclass_is_kept():
    labels = {"a" * 64: {"class": "malware"}}
    assert general_population(labels) == labels


def test_an_unrelated_subclass_is_kept():
    """Only subclasses named in GENERAL_POPULATION_EXCLUDED_SUBCLASSES are cut
    -- this must not become a blanket "drop anything with a subclass" filter,
    or india_malware (a subclass this project *does* want in headline
    numbers) would silently vanish too."""
    labels = {"a" * 64: {"class": "malware", "subclass": "india_malware"}}
    assert general_population(labels) == labels


def test_general_population_does_not_mutate_its_input():
    labels = {"a" * 64: {"class": "malware", "subclass": "banking"}}
    general_population(labels)
    assert "a" * 64 in labels
