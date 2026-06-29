"""
Data models for the Access Risk Analyzer.

These mirror (in simplified form) the building blocks of a real cloud IAM
system: identities (users/groups/roles), policies made of statements, trust
relationships, and resources. Keeping this as a typed, serializable layer
means the rest of the pipeline (graph builder, attack-path engine,
least-privilege engine) never has to care whether the data came from a
generator, a JSON fixture, or eventually a real AWS/Azure/GCP export.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any


@dataclass
class PolicyStatement:
    effect: str                     # "Allow" or "Deny"
    actions: List[str]
    resources: List[str] = field(default_factory=lambda: ["*"])

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Policy:
    id: str
    name: str
    statements: List[PolicyStatement]
    managed: bool = True            # AWS-managed vs customer-managed style

    def actions(self) -> List[str]:
        acts = []
        for s in self.statements:
            if s.effect == "Allow":
                acts.extend(s.actions)
        return acts

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class TrustPolicy:
    allowed_principals: List[str] = field(default_factory=list)  # identity IDs

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IAMUser:
    id: str
    name: str
    groups: List[str] = field(default_factory=list)
    attached_policies: List[str] = field(default_factory=list)
    inline_statements: List[PolicyStatement] = field(default_factory=list)
    mfa_enabled: bool = True
    title: str = "user"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class IAMGroup:
    id: str
    name: str
    members: List[str] = field(default_factory=list)
    attached_policies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IAMRole:
    id: str
    name: str
    trust_policy: TrustPolicy
    attached_policies: List[str] = field(default_factory=list)
    sensitivity: str = "medium"     # low / medium / high blast radius if compromised

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Resource:
    id: str
    name: str
    type: str
    sensitivity: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class IAMDataset:
    users: List[IAMUser]
    groups: List[IAMGroup]
    roles: List[IAMRole]
    policies: Dict[str, Policy]
    resources: List[Resource]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "users": [u.to_dict() for u in self.users],
            "groups": [g.to_dict() for g in self.groups],
            "roles": [r.to_dict() for r in self.roles],
            "policies": {pid: p.to_dict() for pid, p in self.policies.items()},
            "resources": [r.to_dict() for r in self.resources],
        }
