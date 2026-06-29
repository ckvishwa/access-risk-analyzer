#!/usr/bin/env python3
"""
Access Risk Analyzer -- CLI entrypoint.

Pipeline:
  1. Generate a synthetic IAM environment (users/groups/roles/policies/resources)
  2. Build a weighted attack graph encoding known privilege-escalation techniques
  3. Find the cheapest attack path from every user to a high-value target
  4. Simulate 90-day usage logs and generate least-privilege recommendations
  5. Re-run the graph with trimmed permissions to quantify remediation impact
  6. Write a composite risk report (CSV + JSON) and a graph visualization

Usage:
  python -m access_risk_analyzer.main --num-users 25 --seed 42 --output-dir output
"""

from __future__ import annotations
import argparse
import json
import os

from . import data_generator, graph_builder, attack_paths, least_privilege, risk_report, visualize


def run(num_users: int, seed: int, output_dir: str, risky_fraction: float) -> None:
    os.makedirs(output_dir, exist_ok=True)

    print(f"[1/6] Generating synthetic IAM environment "
          f"(users={num_users}, seed={seed}, risky_fraction={risky_fraction})...")
    dataset = data_generator.generate_dataset(num_users=num_users, seed=seed,
                                               risky_fraction=risky_fraction)
    with open(os.path.join(output_dir, "iam_data.json"), "w") as f:
        json.dump(dataset.to_dict(), f, indent=2)

    print("[2/6] Building attack graph from IAM data + privesc rule catalog...")
    g = graph_builder.build_graph(dataset)
    print(f"      graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")

    print("[3/6] Finding privilege-escalation paths to admin + resource exposure paths...")
    admin_paths = attack_paths.find_privesc_paths_to_admin(g)
    resource_paths = attack_paths.find_resource_exposure_paths(g)
    admin_reachable = attack_paths.count_users_with_path_to_admin(g)
    combined = (
        [{"path_type": "privilege_escalation_to_admin", **attack_paths.path_to_dict(p)} for p in admin_paths]
        + [{"path_type": "sensitive_resource_exposure", **attack_paths.path_to_dict(p)} for p in resource_paths]
    )
    with open(os.path.join(output_dir, "attack_paths.json"), "w") as f:
        json.dump(combined, f, indent=2)
    print(f"      {len(admin_paths)}/{num_users} users have an escalation path to full admin")
    print(f"      {len(resource_paths)}/{num_users} users have direct exposure to a sensitive resource")

    print("[4/6] Simulating usage logs + building least-privilege recommendations...")
    recs = least_privilege.build_recommendations(dataset, seed=seed)
    with open(os.path.join(output_dir, "least_privilege_recommendations.json"), "w") as f:
        json.dump({k: v.to_dict() for k, v in recs.items()}, f, indent=2)

    print("[5/6] Re-running the graph with trimmed permissions to measure impact...")
    remediation = least_privilege.remediation_impact(dataset, recs)
    print(f"      users with a path to admin: {remediation['users_with_path_to_admin_before']} "
          f"-> {remediation['users_with_path_to_admin_after']}")

    print("[6/6] Writing composite risk report + graph visualization...")
    rows = risk_report.build_rows(dataset, g, admin_paths, resource_paths, recs)
    risk_report.write_csv(rows, os.path.join(output_dir, "risk_report.csv"))
    summary = risk_report.summary(rows, remediation)
    with open(os.path.join(output_dir, "risk_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    visualize.draw_graph(g, os.path.join(output_dir, "attack_graph.png"),
                          title="IAM Access Risk Graph -- full environment")

    # Prefer highlighting a genuine multi-hop privilege-escalation chain;
    # fall back to the riskiest direct resource-exposure path if no
    # escalation-to-admin path exists in this run.
    highlight_pool = admin_paths if admin_paths else resource_paths
    if highlight_pool:
        top = max(highlight_pool, key=lambda p: (p.hops, p.risk_score))
        visualize.draw_graph(g, os.path.join(output_dir, "top_risk_path.png"),
                              highlight_path=top,
                              title=f"Riskiest path: {top.source_label} -> {top.target_label} "
                                    f"(risk {top.risk_score}, {top.hops} hop(s))")

    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2))
    print(f"\nAll output files written to: {os.path.abspath(output_dir)}")


def main():
    parser = argparse.ArgumentParser(description="Access Risk Analyzer")
    parser.add_argument("--num-users", type=int, default=25)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", type=str, default="output")
    parser.add_argument("--risky-fraction", type=float, default=0.22,
                         help="Fraction of non-admin users seeded with an "
                              "extra over-permissioned 'convenience' policy.")
    args = parser.parse_args()
    run(args.num_users, args.seed, args.output_dir, args.risky_fraction)


if __name__ == "__main__":
    main()
