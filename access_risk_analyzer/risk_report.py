"""
Combines attack-path risk with least-privilege gap data into one composite,
per-user risk score and writes it out as a CSV (the kind of artifact you'd
actually hand to a team to action) plus a JSON summary.
"""

from __future__ import annotations
import csv
from typing import Dict, List
import networkx as nx

from .models import IAMDataset
from .attack_paths import AttackPath
from .least_privilege import IdentityRecommendation


def build_rows(dataset: IAMDataset, g: nx.DiGraph,
                admin_paths: List[AttackPath], resource_paths: List[AttackPath],
                recs: Dict[str, IdentityRecommendation]) -> List[Dict]:
    admin_by_user = {p.source: p for p in admin_paths}
    resource_by_user = {p.source: p for p in resource_paths}
    rows = []

    for u in dataset.users:
        node = f"user:{u.id}"
        admin_path = admin_by_user.get(node)
        resource_path = resource_by_user.get(node)
        rec = recs.get(u.id)

        admin_risk = admin_path.risk_score if admin_path else 0.0
        admin_hops = admin_path.hops if admin_path else ""
        resource_risk = resource_path.risk_score if resource_path else 0.0
        resource_label = resource_path.target_label if resource_path else "none found"
        resource_hops = resource_path.hops if resource_path else ""

        gap_ratio = rec.gap_ratio if rec else 0.0
        dangerous_n = len(rec.dangerous_unused) if rec else 0

        composite = (0.55 * admin_risk
                     + 0.20 * resource_risk
                     + 0.15 * (gap_ratio * 100)
                     + 0.10 * min(dangerous_n, 5) * 4)
        composite = round(min(100.0, composite), 1)

        rows.append({
            "identity_id": u.id,
            "label": u.name,
            "type": "user",
            "title": u.title,
            "mfa_enabled": u.mfa_enabled,
            "has_path_to_admin": admin_path is not None,
            "admin_path_risk_score": admin_risk,
            "admin_path_hops": admin_hops,
            "nearest_sensitive_resource": resource_label,
            "resource_exposure_hops": resource_hops,
            "least_priv_gap_ratio": round(gap_ratio, 2),
            "dangerous_unused_count": dangerous_n,
            "composite_risk_score": composite,
        })

    rows.sort(key=lambda r: r["composite_risk_score"], reverse=True)
    return rows


def write_csv(rows: List[Dict], output_path: str) -> None:
    if not rows:
        return
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def summary(rows: List[Dict], remediation: Dict) -> Dict:
    if not rows:
        return {}
    avg_composite = round(sum(r["composite_risk_score"] for r in rows) / len(rows), 1)
    high_risk = [r for r in rows if r["composite_risk_score"] >= 70]
    no_mfa_high_risk = [r for r in high_risk if not r["mfa_enabled"]]
    admin_reachable = [r for r in rows if r["has_path_to_admin"]]

    return {
        "total_users": len(rows),
        "avg_composite_risk_score": avg_composite,
        "users_with_path_to_admin": len(admin_reachable),
        "high_risk_user_count": len(high_risk),
        "high_risk_without_mfa_count": len(no_mfa_high_risk),
        "top_5_riskiest": [
            {"label": r["label"], "composite_risk_score": r["composite_risk_score"],
             "has_path_to_admin": r["has_path_to_admin"],
             "nearest_sensitive_resource": r["nearest_sensitive_resource"]}
            for r in rows[:5]
        ],
        "remediation_impact": remediation,
    }
