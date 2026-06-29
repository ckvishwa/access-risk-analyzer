"""
Builds a directed, weighted attack graph from an IAMDataset.

Node types:
  user:<id>, role:<id>, group:<id>, resource:<id>, "ROOT_ADMIN" (virtual)

Edge kinds (stored as edge attribute "kind"):
  member_of    -- cosmetic, user/role -> group
  has_access   -- actor can use the resource's service directly
  escalate     -- a privilege-escalation technique connects actor -> target
  already_admin -- actor already holds '*' (terminal edge straight to ROOT_ADMIN)

Every traversable edge (has_access / escalate / already_admin) carries a
"weight" used for shortest-path risk scoring: lower weight = cheaper/easier
for an attacker to exploit = more dangerous.

The `overrides` parameter lets the same builder construct a "what-if" graph
where specific identities' effective actions are replaced (e.g. with a
trimmed least-privilege action set) without touching the underlying
dataset -- this is what powers the before/after remediation-impact report.
"""

from __future__ import annotations
from typing import Dict, Optional, Set, List, Tuple
import networkx as nx

from .models import IAMDataset, IAMUser, IAMRole
from .privesc_rules import PRIVESC_RULES, actions_satisfy_rule

ROOT_ADMIN = "ROOT_ADMIN"

RESOURCE_SERVICE_MAP = {
    "S3 Bucket": "s3",
    "RDS Instance": "rds",
    "EC2 Fleet": "ec2",
    "Secrets Manager Vault": "secretsmanager",
    "KMS Key": "kms",
}


def effective_actions(identity_id: str, dataset: IAMDataset,
                       overrides: Optional[Dict[str, Set[str]]] = None) -> Set[str]:
    """Union of all actions an identity (user or role) effectively holds."""
    if overrides and identity_id in overrides:
        return set(overrides[identity_id])

    actions: Set[str] = set()
    user = next((u for u in dataset.users if u.id == identity_id), None)
    role = next((r for r in dataset.roles if r.id == identity_id), None)

    if user:
        for pid in user.attached_policies:
            actions.update(dataset.policies[pid].actions())
        for stmt in user.inline_statements:
            if stmt.effect == "Allow":
                actions.update(stmt.actions)
        for gname in user.groups:
            group = next((g for g in dataset.groups if g.name == gname), None)
            if group:
                for pid in group.attached_policies:
                    actions.update(dataset.policies[pid].actions())
    elif role:
        for pid in role.attached_policies:
            actions.update(dataset.policies[pid].actions())

    return actions


def _user_groups(user: IAMUser) -> List[str]:
    return user.groups


def build_graph(dataset: IAMDataset,
                 overrides: Optional[Dict[str, Set[str]]] = None) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node(ROOT_ADMIN, kind="virtual", label="Full Admin / Root")

    actors: List[Tuple[str, str]] = [(u.id, "user") for u in dataset.users] + \
                                     [(r.id, "role") for r in dataset.roles]

    for u in dataset.users:
        g.add_node(f"user:{u.id}", kind="user", label=u.name,
                    mfa_enabled=u.mfa_enabled, title=u.title)
    for r in dataset.roles:
        g.add_node(f"role:{r.id}", kind="role", label=r.name,
                    sensitivity=r.sensitivity)
    for grp in dataset.groups:
        g.add_node(f"group:{grp.id}", kind="group", label=grp.name)
    for res in dataset.resources:
        g.add_node(f"resource:{res.id}", kind="resource", label=res.name,
                    sensitivity=res.sensitivity, rtype=res.type)

    # cosmetic membership edges
    for u in dataset.users:
        for gname in u.groups:
            grp = next((x for x in dataset.groups if x.name == gname), None)
            if grp:
                g.add_edge(f"user:{u.id}", f"group:{grp.id}", kind="member_of", weight=0.01)

    actions_cache: Dict[str, Set[str]] = {
        aid: effective_actions(aid, dataset, overrides) for aid, _ in actors
    }

    # --- resource access edges ------------------------------------------
    for aid, atype in actors:
        node = f"{atype}:{aid}"
        acts = actions_cache[aid]
        for res in dataset.resources:
            prefix = RESOURCE_SERVICE_MAP.get(res.type)
            if not prefix:
                continue
            if "*" in acts or f"{prefix}:*" in acts or any(
                    a.startswith(f"{prefix}:") for a in acts):
                g.add_edge(node, f"resource:{res.id}", kind="has_access", weight=0.5)

    # --- already-admin terminal edges -----------------------------------
    for aid, atype in actors:
        if "*" in actions_cache[aid]:
            g.add_edge(f"{atype}:{aid}", ROOT_ADMIN, kind="already_admin",
                       weight=0.1, rule_name="already_admin",
                       attack_id="-", technique="N/A (already holds AdministratorAccess)")

    # --- privilege-escalation edges --------------------------------------
    all_user_ids = [u.id for u in dataset.users]
    all_role_ids = [r.id for r in dataset.roles]

    for aid, atype in actors:
        node = f"{atype}:{aid}"
        acts = actions_cache[aid]
        if "*" in acts:
            continue  # already covered by already_admin edge

        for rule in PRIVESC_RULES:
            if not actions_satisfy_rule(acts, rule):
                continue

            edge_kwargs = dict(kind="escalate", weight=rule.weight,
                                rule_name=rule.name, attack_id=rule.attack_id,
                                technique=rule.technique,
                                description=rule.description)

            if rule.target_type == "self":
                g.add_edge(node, ROOT_ADMIN, **edge_kwargs)

            elif rule.target_type == "user":
                for other_id in all_user_ids:
                    if other_id == aid and atype == "user":
                        continue
                    g.add_edge(node, f"user:{other_id}", **edge_kwargs)

            elif rule.target_type == "role":
                for other_id in all_role_ids:
                    if other_id == aid and atype == "role":
                        continue
                    g.add_edge(node, f"role:{other_id}", **edge_kwargs)

            elif rule.target_type == "role_trust":
                user_obj = next((u for u in dataset.users if u.id == aid), None) if atype == "user" else None
                principal_strs = set()
                if user_obj:
                    principal_strs.add(f"user:{user_obj.id}")
                    for gname in user_obj.groups:
                        principal_strs.add(f"group:{gname}")
                for role in dataset.roles:
                    if role.id == aid and atype == "role":
                        continue
                    allowed = set(role.trust_policy.allowed_principals)
                    if principal_strs & allowed:
                        g.add_edge(node, f"role:{role.id}", **edge_kwargs)

    return g


def node_label(g: nx.DiGraph, node_id: str) -> str:
    if node_id == ROOT_ADMIN:
        return "Full Admin"
    return g.nodes[node_id].get("label", node_id)
