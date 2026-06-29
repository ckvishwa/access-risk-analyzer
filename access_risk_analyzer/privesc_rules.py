"""
Privilege-escalation rule catalog.

Each rule encodes a *known* IAM privilege-escalation technique (the same
class of techniques documented by Rhino Security Labs' AWS IAM privesc
research and tools like PMapper/Cloudsplaining) as:

  required_actions  -> the IAM actions an identity needs to pull it off
  target_type       -> what kind of node the technique lets you pivot to
  weight             -> how "cheap"/reliable the technique is (lower = easier
                        for an attacker = more dangerous edge in the graph)
  attack_id / technique -> MITRE ATT&CK (Cloud) mapping for reporting

This file is the rule engine's *knowledge base*. graph_builder.py walks an
identity's effective permission set against this catalog to decide which
escalation edges exist in the attack graph.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import FrozenSet, List


@dataclass(frozen=True)
class PrivescRule:
    name: str
    required_actions: FrozenSet[str]
    target_type: str        # "user" | "self" | "role" | "role_trust"
    weight: float            # lower = easier / more dangerous
    attack_id: str
    technique: str
    description: str


PRIVESC_RULES: List[PrivescRule] = [
    PrivescRule(
        name="create_access_key_for_user",
        required_actions=frozenset({"iam:CreateAccessKey"}),
        target_type="user",
        weight=1.0,
        attack_id="T1098.001",
        technique="Account Manipulation: Additional Cloud Credentials",
        description="Can mint a new access key for another IAM user and "
                     "operate as them directly.",
    ),
    PrivescRule(
        name="update_login_profile",
        required_actions=frozenset({"iam:UpdateLoginProfile"}),
        target_type="user",
        weight=1.0,
        attack_id="T1098.001",
        technique="Account Manipulation: Additional Cloud Credentials",
        description="Can reset another user's console password and log in "
                     "as them.",
    ),
    PrivescRule(
        name="attach_user_policy",
        required_actions=frozenset({"iam:AttachUserPolicy"}),
        target_type="self",
        weight=1.5,
        attack_id="T1098.003",
        technique="Account Manipulation: Additional Cloud Roles",
        description="Can attach AdministratorAccess (or any policy) "
                     "directly to self or another user.",
    ),
    PrivescRule(
        name="attach_group_policy",
        required_actions=frozenset({"iam:AttachGroupPolicy"}),
        target_type="self",
        weight=1.5,
        attack_id="T1098.003",
        technique="Account Manipulation: Additional Cloud Roles",
        description="Can attach an elevated policy to a group the "
                     "identity belongs to.",
    ),
    PrivescRule(
        name="put_user_policy",
        required_actions=frozenset({"iam:PutUserPolicy"}),
        target_type="self",
        weight=1.5,
        attack_id="T1098.003",
        technique="Account Manipulation: Additional Cloud Roles",
        description="Can inline an elevated policy directly onto self.",
    ),
    PrivescRule(
        name="create_policy_version",
        required_actions=frozenset({"iam:CreatePolicyVersion"}),
        target_type="self",
        weight=1.5,
        attack_id="T1098.003",
        technique="Account Manipulation: Additional Cloud Roles",
        description="Can push a new default policy version granting "
                     "broader permissions on an existing managed policy.",
    ),
    PrivescRule(
        name="update_assume_role_policy",
        required_actions=frozenset({"iam:UpdateAssumeRolePolicy"}),
        target_type="role",
        weight=2.0,
        attack_id="T1098.003",
        technique="Account Manipulation: Additional Cloud Roles",
        description="Can rewrite a role's trust policy to allow self to "
                     "assume it.",
    ),
    PrivescRule(
        name="pass_role_ec2",
        required_actions=frozenset({"iam:PassRole", "ec2:RunInstances"}),
        target_type="role",
        weight=2.5,
        attack_id="T1548.005",
        technique="Abuse Elevation Control Mechanism: Temporary Elevated "
                   "Cloud Access",
        description="Can launch an EC2 instance with an attached role and "
                     "harvest the instance-profile credentials.",
    ),
    PrivescRule(
        name="pass_role_lambda",
        required_actions=frozenset({"iam:PassRole", "lambda:CreateFunction",
                                     "lambda:InvokeFunction"}),
        target_type="role",
        weight=2.5,
        attack_id="T1548.005",
        technique="Abuse Elevation Control Mechanism: Temporary Elevated "
                   "Cloud Access",
        description="Can create and invoke a Lambda function with an "
                     "attached role to execute with its permissions.",
    ),
    PrivescRule(
        name="add_user_to_group",
        required_actions=frozenset({"iam:AddUserToGroup"}),
        target_type="self",
        weight=2.0,
        attack_id="T1098.003",
        technique="Account Manipulation: Additional Cloud Roles",
        description="Can add self to a higher-privileged group.",
    ),
    PrivescRule(
        name="assume_role_via_trust",
        required_actions=frozenset({"sts:AssumeRole"}),
        target_type="role_trust",
        weight=1.0,
        attack_id="T1078.004",
        technique="Valid Accounts: Cloud Accounts",
        description="Permissive trust policy lets this identity assume a "
                     "more privileged role directly.",
    ),
]


def actions_satisfy_rule(effective_actions: set, rule: PrivescRule) -> bool:
    """An identity's wildcard ('iam:*', '*') or exact actions can satisfy a rule."""
    if "*" in effective_actions:
        return True
    for required in rule.required_actions:
        service = required.split(":")[0]
        wildcard = f"{service}:*"
        if required not in effective_actions and wildcard not in effective_actions:
            return False
    return True
