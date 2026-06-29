"""
Graph-based attack-path discovery.

For every user, finds the cheapest (lowest-weight) path through the attack
graph to a "high-value target" -- full admin, or any resource tagged
sensitivity=high -- and converts that path into a human-readable chain of
exploited techniques plus a 0-100 risk score.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import networkx as nx

from .graph_builder import ROOT_ADMIN, node_label


@dataclass
class PathStep:
    from_node: str
    to_node: str
    kind: str
    rule_name: str
    attack_id: str
    technique: str
    description: str = ""


@dataclass
class AttackPath:
    source: str
    target: str
    source_label: str
    target_label: str
    hops: int
    weight: float
    steps: List[PathStep]
    risk_score: float
    mfa_enabled: Optional[bool] = None


def _sensitive_resource_targets(g: nx.DiGraph) -> List[str]:
    return [n for n, data in g.nodes(data=True)
            if data.get("kind") == "resource" and data.get("sensitivity") == "high"]


def _path_to_steps(g: nx.DiGraph, path: List[str]) -> List[PathStep]:
    steps = []
    for a, b in zip(path[:-1], path[1:]):
        edata = g.get_edge_data(a, b)
        steps.append(PathStep(
            from_node=a, to_node=b, kind=edata.get("kind", "?"),
            rule_name=edata.get("rule_name", edata.get("kind", "?")),
            attack_id=edata.get("attack_id", "-"),
            technique=edata.get("technique", edata.get("kind", "")),
            description=edata.get("description", ""),
        ))
    return steps


def _score(weight: float, hops: int, mfa_enabled: Optional[bool],
           already_admin: bool) -> float:
    score = 100.0
    score -= weight * 8.0
    score -= max(0, hops - 1) * 6.0
    if mfa_enabled is False:
        score += 12.0
    if already_admin:
        score = max(score, 95.0)
    return round(max(0.0, min(100.0, score)), 1)


def _cheapest_path_to_one_of(g: nx.DiGraph, source: str,
                               targets: List[str]) -> Optional[AttackPath]:
    best_path, best_weight, best_target = None, None, None
    for t in targets:
        if t == source:
            continue
        try:
            w, path = nx.single_source_dijkstra(g, source, target=t, weight="weight")
        except nx.NetworkXNoPath:
            continue
        if best_weight is None or w < best_weight:
            best_weight, best_path, best_target = w, path, t

    if best_path is None:
        return None

    steps = _path_to_steps(g, best_path)
    already_admin = any(s.kind == "already_admin" for s in steps)
    mfa = g.nodes[source].get("mfa_enabled")
    score = _score(best_weight, len(best_path) - 1, mfa, already_admin)

    return AttackPath(
        source=source, target=best_target,
        source_label=node_label(g, source), target_label=node_label(g, best_target),
        hops=len(best_path) - 1, weight=round(best_weight, 2),
        steps=steps, risk_score=score, mfa_enabled=mfa,
    )


def find_privesc_paths_to_admin(g: nx.DiGraph) -> List[AttackPath]:
    """
    The headline result: for every user, the cheapest chain of
    privilege-escalation techniques that ends in full admin -- this is
    what 'graph-based attack path' means in this project. Users with no
    such path are simply omitted (good news, not a row).
    """
    results: List[AttackPath] = []
    for n, data in g.nodes(data=True):
        if data.get("kind") != "user":
            continue
        p = _cheapest_path_to_one_of(g, n, [ROOT_ADMIN])
        if p:
            results.append(p)
    results.sort(key=lambda p: p.risk_score, reverse=True)
    return results


def find_resource_exposure_paths(g: nx.DiGraph) -> List[AttackPath]:
    """
    A complementary, lower-stakes metric: how directly can each user reach
    a resource tagged sensitivity=high, independent of full-admin takeover.
    This is 'blast radius', not privilege escalation.
    """
    results: List[AttackPath] = []
    targets = _sensitive_resource_targets(g)
    for n, data in g.nodes(data=True):
        if data.get("kind") != "user":
            continue
        p = _cheapest_path_to_one_of(g, n, targets)
        if p:
            results.append(p)
    results.sort(key=lambda p: p.risk_score, reverse=True)
    return results


# Backwards-compatible combined view (used by least_privilege.py's
# before/after impact comparison, where the only thing that matters is
# "did the count or average severity change").
def find_user_attack_paths(g: nx.DiGraph) -> List[AttackPath]:
    admin_paths = {p.source: p for p in find_privesc_paths_to_admin(g)}
    resource_paths = find_resource_exposure_paths(g)
    for p in resource_paths:
        admin_paths.setdefault(p.source, p)
    results = list(admin_paths.values())
    results.sort(key=lambda p: p.risk_score, reverse=True)
    return results


def count_users_with_path_to_admin(g: nx.DiGraph) -> int:
    count = 0
    for n, data in g.nodes(data=True):
        if data.get("kind") != "user":
            continue
        if nx.has_path(g, n, ROOT_ADMIN):
            count += 1
    return count


def path_to_dict(p: AttackPath) -> Dict:
    return {
        "source": p.source, "source_label": p.source_label,
        "target": p.target, "target_label": p.target_label,
        "hops": p.hops, "weight": p.weight, "risk_score": p.risk_score,
        "mfa_enabled": p.mfa_enabled,
        "steps": [
            {
                "from": s.from_node, "to": s.to_node, "kind": s.kind,
                "rule_name": s.rule_name, "attack_id": s.attack_id,
                "technique": s.technique, "description": s.description,
            } for s in p.steps
        ],
    }
