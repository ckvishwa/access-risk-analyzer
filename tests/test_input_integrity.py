"""Regression tests: malformed IAM input or a dangling relationship must fail
loudly, never silently drop permissions and report a lower risk."""
import pytest

from access_risk_analyzer import attack_paths, graph_builder
from access_risk_analyzer.models import (IAMDataset, IAMGroup, IAMUser, Policy,
                                         PolicyStatement)

ADMIN = Policy("p-admin", "Admin", [PolicyStatement("Allow", ["*"])])


def _dataset(user, groups=None):
    groups = groups if groups is not None else [
        IAMGroup("g1", "Admins", attached_policies=["p-admin"])]
    return IAMDataset(users=[user], groups=groups, roles=[],
                      policies={"p-admin": ADMIN}, resources=[])


def test_resolvable_group_admin_is_reported():
    g = graph_builder.build_graph(_dataset(IAMUser("u1", "alice", groups=["Admins"])))
    assert attack_paths.count_users_with_path_to_admin(g) == 1


def test_unknown_group_membership_is_rejected_not_ignored():
    """Previously: group 'admins' (case typo) was skipped and alice, an
    effective admin, was reported with no path to admin."""
    with pytest.raises(ValueError, match="unknown group 'admins'"):
        graph_builder.build_graph(_dataset(IAMUser("u1", "alice", groups=["admins"])))


def test_unknown_attached_policy_is_a_clear_error():
    with pytest.raises(ValueError, match="unknown policy 'p-missing'"):
        graph_builder.build_graph(_dataset(IAMUser("u1", "alice", attached_policies=["p-missing"])))


def test_unknown_group_policy_is_a_clear_error():
    groups = [IAMGroup("g1", "Admins", attached_policies=["p-gone"])]
    with pytest.raises(ValueError, match="unknown policy 'p-gone'"):
        graph_builder.build_graph(_dataset(IAMUser("u1", "alice", groups=["Admins"]), groups))


@pytest.mark.parametrize("effect", ["allow", "ALLOW", "Permit", "", None])
def test_malformed_statement_effect_is_rejected(effect):
    """Previously: effect 'allow' was silently treated as not-Allow, so a
    wildcard grant disappeared from the risk result."""
    with pytest.raises(ValueError, match="effect"):
        PolicyStatement(effect, ["*"])


def test_deny_statement_is_still_accepted():
    assert PolicyStatement("Deny", ["s3:*"]).effect == "Deny"
