"""
Least-privilege recommendation engine.

Simulates a 90-day action-usage log per identity (standing in for a real
CloudTrail/Access Advisor export), diffs "granted" against "actually used"
to produce a trimmed policy recommendation, flags unused permissions that
are specifically the ingredients of a known escalation technique, and then
*proves the value* of the recommendation by rebuilding the attack graph
with the trimmed permissions and showing how many escalation paths
disappear.
"""

from __future__ import annotations
import random
from dataclasses import dataclass, field
from typing import Dict, List, Set

from .models import IAMDataset
from .privesc_rules import PRIVESC_RULES
from . import graph_builder
from . import attack_paths as ap_module

ALL_PRIVESC_ACTIONS: Set[str] = set()
for _rule in PRIVESC_RULES:
    ALL_PRIVESC_ACTIONS.update(_rule.required_actions)


@dataclass
class IdentityRecommendation:
    identity_id: str
    identity_type: str
    label: str
    granted_count: int
    used_count: int
    unused_count: int
    gap_ratio: float
    dangerous_unused: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> Dict:
        return {
            "identity_id": self.identity_id, "identity_type": self.identity_type,
            "label": self.label, "granted_count": self.granted_count,
            "used_count": self.used_count, "unused_count": self.unused_count,
            "gap_ratio": round(self.gap_ratio, 2),
            "dangerous_unused": self.dangerous_unused,
            "recommended_actions": self.recommended_actions,
            "note": self.note,
        }


def _simulate_usage(identity_id: str, granted: Set[str], seed: int) -> Set[str]:
    rnd = random.Random(f"{seed}-{identity_id}")
    granted_list = sorted(granted)
    if not granted_list:
        return set()
    frac = rnd.uniform(0.3, 0.75)
    k = max(1, int(len(granted_list) * frac))
    return set(rnd.sample(granted_list, k))


def build_recommendations(dataset: IAMDataset, seed: int = 42
                           ) -> Dict[str, IdentityRecommendation]:
    recs: Dict[str, IdentityRecommendation] = {}

    actors = [(u.id, "user", u.name) for u in dataset.users] + \
             [(r.id, "role", r.name) for r in dataset.roles]

    for aid, atype, label in actors:
        granted = graph_builder.effective_actions(aid, dataset)

        if "*" in granted:
            recs[aid] = IdentityRecommendation(
                identity_id=aid, identity_type=atype, label=label,
                granted_count=1, used_count=0, unused_count=0, gap_ratio=1.0,
                dangerous_unused=["*"], recommended_actions=[],
                note="Holds AdministratorAccess ('*'). Action-level usage "
                     "can't be measured against a wildcard -- replace with "
                     "a scoped policy before a least-privilege gap can even "
                     "be calculated.",
            )
            continue

        used = _simulate_usage(aid, granted, seed)
        unused = granted - used
        dangerous = sorted(unused & ALL_PRIVESC_ACTIONS)
        gap_ratio = (len(unused) / len(granted)) if granted else 0.0

        note = ""
        if dangerous:
            note = (f"{len(dangerous)} unused permission(s) are the exact "
                    f"ingredients of a known privilege-escalation technique "
                    f"-- removing them closes that path without affecting "
                    f"day-to-day work.")

        recs[aid] = IdentityRecommendation(
            identity_id=aid, identity_type=atype, label=label,
            granted_count=len(granted), used_count=len(used),
            unused_count=len(unused), gap_ratio=gap_ratio,
            dangerous_unused=dangerous,
            recommended_actions=sorted(used), note=note,
        )

    return recs


def remediation_impact(dataset: IAMDataset, recs: Dict[str, IdentityRecommendation]
                         ) -> Dict:
    """
    Rebuild the attack graph using only each identity's *used* (recommended)
    actions instead of everything they were granted, and report how much
    the attack surface shrinks.
    """
    overrides: Dict[str, Set[str]] = {}
    for aid, rec in recs.items():
        if rec.recommended_actions:
            overrides[aid] = set(rec.recommended_actions)
        elif rec.dangerous_unused == ["*"]:
            continue  # leave wildcard identities untouched -- separate fix
        else:
            overrides[aid] = set()

    baseline_graph = graph_builder.build_graph(dataset)
    remediated_graph = graph_builder.build_graph(dataset, overrides=overrides)

    baseline_paths = ap_module.find_user_attack_paths(baseline_graph)
    remediated_paths = ap_module.find_user_attack_paths(remediated_graph)

    baseline_admin_count = ap_module.count_users_with_path_to_admin(baseline_graph)
    remediated_admin_count = ap_module.count_users_with_path_to_admin(remediated_graph)

    return {
        "users_with_path_to_admin_before": baseline_admin_count,
        "users_with_path_to_admin_after": remediated_admin_count,
        "paths_found_before": len(baseline_paths),
        "paths_found_after": len(remediated_paths),
        "avg_risk_score_before": round(
            sum(p.risk_score for p in baseline_paths) / len(baseline_paths), 1
        ) if baseline_paths else 0.0,
        "avg_risk_score_after": round(
            sum(p.risk_score for p in remediated_paths) / len(remediated_paths), 1
        ) if remediated_paths else 0.0,
    }
