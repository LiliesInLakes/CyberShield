"""L3b's family-disjoint split — the guard against B37's own failure mode.

B37 (docs/PROJECT_LOG.md §7.6): "banking families are small and tightly
clustered, so a random split trains and tests on variants of one family and
reports an AUROC that means nothing." These tests exist to make sure the
splitter cannot silently regress into that random split.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from L3b.family_labels import (  # noqa: E402
    FamilyLabel, attach_family, split_family_disjoint,
)


def _verified(family: str, n: int, start: int = 0) -> list[FamilyLabel]:
    return [FamilyLabel(sha256=f"{family}_{i:03d}".ljust(64, "0"), family=family,
                        tier="verified", source="test")
           for i in range(start, start + n)]


def _unknown(n: int) -> list[FamilyLabel]:
    return [FamilyLabel(sha256=f"unk_{i:03d}".ljust(64, "0"), family=None,
                        tier="unknown", source="test") for i in range(n)]


# --------------------------------------------------------------------------
# attach_family
# --------------------------------------------------------------------------

def test_a_sha_in_the_verified_map_is_tier_verified():
    lab = attach_family("aaaa", source="test",
                        verified_map={"aaaa": "Teabot"})
    assert lab.tier == "verified"
    assert lab.family == "Teabot"


def test_a_sha_in_only_the_weak_hint_map_is_tier_weak_hint():
    lab = attach_family("bbbb", source="test",
                        weak_hint_map={"bbbb": "Cerberus"})
    assert lab.tier == "weak_hint"


def test_verified_wins_over_weak_hint_for_the_same_sha():
    lab = attach_family("cccc", source="test",
                        verified_map={"cccc": "Hydra"},
                        weak_hint_map={"cccc": "Octo"})
    assert lab.tier == "verified"
    assert lab.family == "Hydra"


def test_a_sha_in_neither_map_is_tier_unknown():
    lab = attach_family("dddd", source="test")
    assert lab.tier == "unknown"
    assert lab.family is None


# --------------------------------------------------------------------------
# split_family_disjoint
# --------------------------------------------------------------------------

def test_too_few_verified_families_yields_unverified_status_not_a_fake_split():
    labels = _verified("Teabot", 5) + _unknown(50)
    split = split_family_disjoint(labels, min_families_for_split=4)
    assert split.status == "unverified_pending_malradar"
    assert split.test_ids == ()
    assert len(split.train_ids) == 55


def test_no_verified_family_ever_straddles_train_and_test():
    labels = (_verified("Teabot", 10) + _verified("Cerberus", 10)
             + _verified("Hydra", 10) + _verified("Octo", 10)
             + _verified("Ermac", 10))
    split = split_family_disjoint(labels, min_families_for_split=4, seed=1)
    assert split.status == "verified"
    train_set, test_set = set(split.train_ids), set(split.test_ids)
    assert train_set.isdisjoint(test_set)

    def family_of(sha: str) -> str:
        return sha.split("_")[0]

    train_families = {family_of(s) for s in train_set if family_of(s) in
                      ("Teabot", "Cerberus", "Hydra", "Octo", "Ermac")}
    test_families = {family_of(s) for s in test_set}
    assert train_families.isdisjoint(test_families)


def test_held_out_families_are_reported_and_nonempty():
    labels = (_verified("Teabot", 10) + _verified("Cerberus", 10)
             + _verified("Hydra", 10) + _verified("Octo", 10))
    split = split_family_disjoint(labels, min_families_for_split=4, seed=1)
    assert split.status == "verified"
    assert len(split.held_out_families) >= 1
    assert set(split.held_out_families) <= {"Teabot", "Cerberus", "Hydra", "Octo"}


def test_unknown_tier_samples_never_enter_the_test_partition():
    labels = (_verified("Teabot", 10) + _verified("Cerberus", 10)
             + _verified("Hydra", 10) + _verified("Octo", 10) + _unknown(100))
    split = split_family_disjoint(labels, min_families_for_split=4, seed=1)
    unknown_shas = {lab.sha256 for lab in labels if lab.tier == "unknown"}
    assert unknown_shas.isdisjoint(set(split.test_ids))
    assert unknown_shas <= set(split.train_ids)


def test_a_family_with_only_one_verified_sample_cannot_be_held_out():
    """Holding out a single-sample family would test on nothing meaningful."""
    labels = (_verified("Teabot", 10) + _verified("Cerberus", 10)
             + _verified("Hydra", 10) + _verified("Octo", 10)
             + _verified("RareFamily", 1))
    split = split_family_disjoint(labels, min_families_for_split=4, seed=1)
    rare_sha = next(lab.sha256 for lab in labels if lab.family == "RareFamily")
    assert rare_sha in split.train_ids
    assert rare_sha not in split.test_ids
