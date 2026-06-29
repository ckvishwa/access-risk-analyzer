"""
Renders the attack graph (or a single highlighted attack path) to a PNG
using matplotlib + networkx. Headless-safe (Agg backend) for CLI/CI use.
"""

from __future__ import annotations
from typing import List, Optional
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from .graph_builder import ROOT_ADMIN
from .attack_paths import AttackPath

NODE_COLORS = {
    "user": "#4C72B0",
    "role": "#DD8452",
    "group": "#9ca3af",
    "resource": "#55A868",
    "virtual": "#C44E52",
}


def _node_color(g: nx.DiGraph, n: str) -> str:
    if n == ROOT_ADMIN:
        return NODE_COLORS["virtual"]
    return NODE_COLORS.get(g.nodes[n].get("kind", ""), "#888888")


def draw_graph(g: nx.DiGraph, output_path: str,
               highlight_path: Optional[AttackPath] = None,
               title: str = "IAM Access Risk Graph") -> None:
    fig, ax = plt.subplots(figsize=(15, 11))
    pos = nx.spring_layout(g, seed=7, k=0.9)

    traversable = [(u, v) for u, v, d in g.edges(data=True)
                   if d.get("kind") != "member_of"]
    member_edges = [(u, v) for u, v, d in g.edges(data=True)
                    if d.get("kind") == "member_of"]

    nx.draw_networkx_edges(g, pos, edgelist=member_edges, ax=ax,
                            edge_color="#d1d5db", width=0.6, alpha=0.5,
                            style="dotted", arrows=False)
    nx.draw_networkx_edges(g, pos, edgelist=traversable, ax=ax,
                            edge_color="#9ca3af", width=0.8, alpha=0.55,
                            arrows=True, arrowsize=8,
                            connectionstyle="arc3,rad=0.05")

    colors = [_node_color(g, n) for n in g.nodes()]
    sizes = [900 if n == ROOT_ADMIN else
              (550 if g.nodes[n].get("kind") == "resource" else 260)
              for n in g.nodes()]
    nx.draw_networkx_nodes(g, pos, node_color=colors, node_size=sizes,
                            ax=ax, linewidths=0.5, edgecolors="white")

    labels = {n: g.nodes[n].get("label", n) for n in g.nodes()}
    nx.draw_networkx_labels(g, pos, labels=labels, font_size=6.5, ax=ax)

    if highlight_path is not None:
        path_nodes = [highlight_path.source] + [s.to_node for s in highlight_path.steps]
        path_edges = list(zip(path_nodes[:-1], path_nodes[1:]))
        nx.draw_networkx_edges(g, pos, edgelist=path_edges, ax=ax,
                                edge_color="#C44E52", width=3.0, arrows=True,
                                arrowsize=16, connectionstyle="arc3,rad=0.05")
        nx.draw_networkx_nodes(g, pos, nodelist=path_nodes, ax=ax,
                                node_color="none", node_size=[
                                    1000 if n == ROOT_ADMIN else 420 for n in path_nodes
                                ], edgecolors="#C44E52", linewidths=2.5)

    legend_handles = [
        plt.Line2D([0], [0], marker='o', color='w', label=k.capitalize(),
                   markerfacecolor=v, markersize=10)
        for k, v in NODE_COLORS.items()
    ]
    ax.legend(handles=legend_handles, loc="lower left", fontsize=9, frameon=True)
    ax.set_title(title, fontsize=14)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(output_path, dpi=160)
    plt.close(fig)
