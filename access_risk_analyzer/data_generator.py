"""
Generates a synthetic but realistic IAM environment: users, groups, roles,
managed/inline policies, and resources. A configurable fraction of
identities are seeded with deliberately risky, but entirely plausible,
permission combinations (the same kinds of misconfigurations that show up
in real cloud environments) so the attack-path engine has something to find.

Everything is deterministic given a seed, so a generated dataset and the
analysis run against it are reproducible end to end.
"""

from __future__ import annotations
import random
from typing import Dict, List

from faker import Faker

from .models import (
    PolicyStatement, Policy, TrustPolicy, IAMUser, IAMGroup, IAMRole,
    Resource, IAMDataset,
)

# --- Reference policy catalog (trimmed but representative AWS-style policies)
MANAGED_POLICY_CATALOG: Dict[str, List[str]] = {
    "ReadOnlyAccess": [
        "s3:GetObject", "s3:ListBucket", "ec2:DescribeInstances",
        "iam:GetUser", "iam:ListUsers", "rds:DescribeDBInstances",
        "cloudwatch:GetMetricData",
    ],
    "PowerUserAccess": [
        "s3:*", "ec2:*", "lambda:*", "rds:*", "cloudwatch:*",
        "sqs:*", "sns:*",
    ],
    "AdministratorAccess": ["*"],
    "IAMFullAccess": ["iam:*"],
    "IAMSelfManageCredentials": [
        "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey",
        "iam:ChangePassword",
    ],
    "DeveloperDeployPolicy": [
        "ec2:RunInstances", "ec2:DescribeInstances", "iam:PassRole",
        "s3:GetObject", "s3:PutObject",
    ],
    "LambdaDeployPolicy": [
        "lambda:CreateFunction", "lambda:InvokeFunction",
        "lambda:UpdateFunctionCode", "iam:PassRole", "logs:CreateLogGroup",
    ],
    "S3AdminPolicy": ["s3:*"],
    "SecurityAuditPolicy": [
        "iam:GetUser", "iam:ListUsers", "iam:ListRoles",
        "iam:ListAttachedUserPolicies", "cloudtrail:LookupEvents",
    ],
    # Intentionally over-permissioned "convenience" policies that show up a
    # lot in real environments because someone needed *one* action and got
    # handed a whole service instead.
    "LegacyAdminHelperPolicy": [
        "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateAccessKey",
    ],
    "GroupManagerPolicy": [
        "iam:AddUserToGroup", "iam:AttachGroupPolicy", "iam:ListGroups",
    ],
    "PolicyAuthorPolicy": [
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
        "iam:ListPolicies",
    ],
    "TrustEditorPolicy": [
        "iam:UpdateAssumeRolePolicy", "iam:GetRole", "iam:ListRoles",
    ],
    "AssumeDeployRolePolicy": ["sts:AssumeRole"],
}

JOB_TITLES = [
    "junior_developer", "developer", "senior_developer", "devops_engineer",
    "data_analyst", "qa_engineer", "support_engineer", "intern",
    "security_analyst", "platform_engineer",
]

RESOURCE_TYPES = [
    ("S3 Bucket", "customer-data"), ("RDS Instance", "billing-db"),
    ("S3 Bucket", "build-artifacts"), ("Secrets Manager Vault", "prod-secrets"),
    ("EC2 Fleet", "prod-web-tier"), ("S3 Bucket", "internal-docs"),
    ("KMS Key", "data-encryption-key"), ("RDS Instance", "analytics-db"),
]


def _new_policy(pid: str, name: str, actions: List[str], managed: bool = True) -> Policy:
    return Policy(
        id=pid, name=name, managed=managed,
        statements=[PolicyStatement(effect="Allow", actions=actions)],
    )


def generate_dataset(num_users: int = 25, seed: int = 42,
                      risky_fraction: float = 0.22) -> IAMDataset:
    """
    Build a synthetic IAM environment.

    risky_fraction: proportion of non-privileged users who get handed an
    extra "convenience" policy that, combined with what they already have,
    opens an escalation path. This models real-world permission creep
    rather than hand-placed scenario flags.
    """
    rnd = random.Random(seed)
    fake = Faker()
    Faker.seed(seed)

    # --- Policies -----------------------------------------------------
    policies: Dict[str, Policy] = {}
    for i, (name, actions) in enumerate(MANAGED_POLICY_CATALOG.items()):
        pid = f"pol-{i:03d}"
        policies[pid] = _new_policy(pid, name, actions)
    name_to_pid = {p.name: pid for pid, p in policies.items()}

    # --- Resources ------------------------------------------------------
    resources: List[Resource] = []
    for i, (rtype, rname) in enumerate(RESOURCE_TYPES):
        sensitivity = "high" if any(k in rname for k in
                                     ("secrets", "billing", "customer", "encryption")) else "medium"
        resources.append(Resource(id=f"res-{i:03d}", name=rname, type=rtype,
                                   sensitivity=sensitivity))

    # --- Groups ---------------------------------------------------------
    group_defs = [
        ("Developers", ["DeveloperDeployPolicy"]),
        ("DataTeam", ["ReadOnlyAccess"]),
        ("SecurityTeam", ["SecurityAuditPolicy"]),
        ("Admins", ["AdministratorAccess"]),
        ("PlatformOps", ["LambdaDeployPolicy", "GroupManagerPolicy"]),
    ]
    groups: List[IAMGroup] = []
    for i, (gname, gpolicies) in enumerate(group_defs):
        groups.append(IAMGroup(
            id=f"grp-{i:03d}", name=gname, members=[],
            attached_policies=[name_to_pid[p] for p in gpolicies],
        ))
    group_by_name = {g.name: g for g in groups}

    # --- Roles ------------------------------------------------------------
    role_defs = [
        ("DeployRole", ["DeveloperDeployPolicy", "LambdaDeployPolicy"], "medium"),
        ("DataPipelineRole", ["PowerUserAccess"], "high"),
        ("BreakGlassAdminRole", ["AdministratorAccess"], "high"),
        ("AuditReadOnlyRole", ["SecurityAuditPolicy", "ReadOnlyAccess"], "low"),
    ]
    roles: List[IAMRole] = []
    for i, (rname, rpolicies, sensitivity) in enumerate(role_defs):
        roles.append(IAMRole(
            id=f"role-{i:03d}", name=rname,
            trust_policy=TrustPolicy(allowed_principals=[]),
            attached_policies=[name_to_pid[p] for p in rpolicies],
            sensitivity=sensitivity,
        ))

    # Wire up trust policies (who can assume which role) -- includes one
    # deliberately broad trust relationship, modeling a common real misstep.
    roles[0].trust_policy.allowed_principals = ["group:Developers"]
    roles[1].trust_policy.allowed_principals = ["group:PlatformOps"]
    roles[2].trust_policy.allowed_principals = ["group:Admins"]
    roles[3].trust_policy.allowed_principals = ["group:SecurityTeam", "group:Developers"]

    # --- Users --------------------------------------------------------------
    users: List[IAMUser] = []
    convenience_policies = ["LegacyAdminHelperPolicy", "GroupManagerPolicy",
                             "PolicyAuthorPolicy", "TrustEditorPolicy",
                             "AssumeDeployRolePolicy"]

    for i in range(num_users):
        title = rnd.choice(JOB_TITLES)
        uname = fake.user_name()
        uid = f"usr-{i:03d}"

        if title in ("security_analyst",):
            base_group = "SecurityTeam"
        elif title in ("devops_engineer", "platform_engineer"):
            base_group = "PlatformOps"
        elif title == "data_analyst":
            base_group = "DataTeam"
        elif "developer" in title:
            base_group = "Developers"
        else:
            base_group = rnd.choice(["Developers", "DataTeam"])

        attached: List[str] = []
        groups_for_user = [base_group]

        # ~4% of the population are legitimate admins (small team, by design)
        if rnd.random() < 0.04:
            groups_for_user = ["Admins"]

        # Seed the permission-creep vulnerability: extra "helper" policy
        # bolted onto an otherwise normal account, plus the ability to
        # assume a role -- the exact pattern that turns "convenience" into
        # a privilege-escalation path.
        is_risky = rnd.random() < risky_fraction and "Admins" not in groups_for_user
        if is_risky:
            attached.append(name_to_pid[rnd.choice(convenience_policies)])
            if rnd.random() < 0.5:
                attached.append(name_to_pid["AssumeDeployRolePolicy"])

        mfa_enabled = rnd.random() > 0.18  # ~18% missing MFA, realistic-ish

        user = IAMUser(id=uid, name=uname, groups=groups_for_user,
                        attached_policies=attached, mfa_enabled=mfa_enabled,
                        title=title)
        users.append(user)
        group_by_name[groups_for_user[0]].members.append(uid)

    # Let a couple of risky users actually be allowed by a role's trust
    # policy too (broadening the "assume_role_via_trust" path realistically)
    for u in users:
        if any(pid == name_to_pid["AssumeDeployRolePolicy"] for pid in u.attached_policies):
            roles[1].trust_policy.allowed_principals.append(f"user:{u.id}")

    return IAMDataset(users=users, groups=groups, roles=roles,
                       policies=policies, resources=resources)
