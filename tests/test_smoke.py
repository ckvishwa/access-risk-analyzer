"""
Sanity tests for the Access Risk Analyzer pipeline.

These aren't trying to prove the *security* findings are realistic (that's
a judgment call, documented in the README) -- they're checking that the
pipeline's internal logic is consistent: the graph builds, every reported
attack path is actually walkable, remediation never increases risk, and
the report's numbers add up. Run with: pytest -q
"""

import networkx as nx
import pytest

from access_risk_analyzer import data_generator, graph_builder, attack_paths, \
    least_privilege, risk_report
from access_risk_analyzer.graph_builder import ROOT_ADMIN


@pytest.fixture(scope="module")
def dataset():
    return data_generator.generate_dataset(num_users=30, seed=7, risky_fraction=0.25)


@pytest.fixture(scope="module")
def graph(dataset):
    return graph_builder.build_graph(dataset)


def test_graph_has_expected_node_types(graph):
    kinds = {data.get("kind") for _, data in graph.nodes(data=True)}
    assert {"user", "role", "group", "resource", "virtual"} <= kinds
    assert ROOT_ADMIN in graph.nodes


def test_every_user_has_effective_actions_computed(dataset):
    for u in dataset.users:
        acts = graph_builder.effective_actions(u.id, dataset)
        assert isinstance(acts, set)


def test_admin_paths_are_actually_walkable(graph):
    paths = attack_paths.find_privesc_paths_to_admin(graph)
    assert len(paths) > 0, "fixture should produce at least one escalation path"
    for p in paths:
        node_seq = [p.source] + [s.to_node for s in p.steps]
        for a, b in zip(node_seq[:-1], node_seq[1:]):
            assert graph.has_edge(a, b), f"reported path edge {a}->{b} doesn't exist in graph"
        assert node_seq[-1] == ROOT_ADMIN
        assert p.hops == len(p.steps)


def test_resource_exposure_paths_target_high_sensitivity_only(graph):
    paths = attack_paths.find_resource_exposure_paths(graph)
    for p in paths:
        target_data = graph.nodes[p.target]
        assert target_data.get("kind") == "resource"
        assert target_data.get("sensitivity") == "high"


def test_count_users_with_path_to_admin_matches_path_list(graph):
    paths = attack_paths.find_privesc_paths_to_admin(graph)
    count = attack_paths.count_users_with_path_to_admin(graph)
    assert count == len(paths)


def test_least_privilege_recommendations_never_exceed_granted(dataset):
    recs = least_privilege.build_recommendations(dataset, seed=7)
    for rec in recs.values():
        if rec.dangerous_unused == ["*"]:
            continue
        assert rec.used_count <= rec.granted_count
        assert set(rec.recommended_actions).issubset(
            graph_builder.effective_actions(rec.identity_id, dataset)
        )


def test_remediation_never_increases_admin_reachability(dataset):
    recs = least_privilege.build_recommendations(dataset, seed=7)
    impact = least_privilege.remediation_impact(dataset, recs)
    assert impact["users_with_path_to_admin_after"] <= impact["users_with_path_to_admin_before"]


def test_risk_report_row_count_matches_user_count(dataset, graph):
    admin_paths = attack_paths.find_privesc_paths_to_admin(graph)
    resource_paths = attack_paths.find_resource_exposure_paths(graph)
    recs = least_privilege.build_recommendations(dataset, seed=7)
    rows = risk_report.build_rows(dataset, graph, admin_paths, resource_paths, recs)
    assert len(rows) == len(dataset.users)
    assert all(0.0 <= r["composite_risk_score"] <= 100.0 for r in rows)


def test_dataset_is_deterministic_given_same_seed():
    d1 = data_generator.generate_dataset(num_users=15, seed=99)
    d2 = data_generator.generate_dataset(num_users=15, seed=99)
    assert [u.name for u in d1.users] == [u.name for u in d2.users]
    assert [u.attached_policies for u in d1.users] == [u.attached_policies for u in d2.users]
