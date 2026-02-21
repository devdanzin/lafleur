"""Corpus lineage visualization tool for lafleur.

Builds and renders lineage trees from coverage_state.pkl, showing how corpus
files descend from seeds through mutation chains. Supports ancestry (trace a
file back to its seed) and descendants (show what a file produced) modes.

Output formats: Graphviz DOT (default), JSON, or rendered images (PNG/SVG/PDF).
"""

from __future__ import annotations

import argparse
import json
import math
import pickle
import shutil
import subprocess
import sys
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from statistics import mean

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class LineageGraph:
    """Full adjacency graph built from per_file_coverage."""

    children: dict[str, list[str]]  # parent_id → list of child filenames
    parent: dict[str, str | None]  # filename → parent_id (None for seeds)
    roots: list[str]  # files with parent_id is None (seeds)
    metadata: dict[str, dict]  # filename → full per_file_coverage entry


@dataclass
class Subgraph:
    """A subset of the lineage graph for rendering."""

    nodes: set[str]  # filenames in this subgraph
    edges: list[tuple[str, str]]  # (parent, child) pairs
    collapsed: dict[str, int] = field(default_factory=dict)  # summary_node_id → count
    special_nodes: dict[str, str] = field(
        default_factory=dict
    )  # node_id → role (crash, ghost, mrca)


@dataclass
class NodeStyle:
    """Visual properties for a single node."""

    shape: str = "box"
    fillcolor: str = "#d4edda"
    fontcolor: str = "black"
    style: str = "filled"
    color: str = ""  # border color (empty = default)
    penwidth: float = 1.0
    label: str = ""
    tooltip: str = ""


@dataclass
class EdgeStyle:
    """Visual properties for a single edge."""

    color: str = "#000000"
    style: str = "solid"
    penwidth: float = 1.0
    label: str = ""


@dataclass
class DecoratedGraph:
    """Subgraph with visual properties assigned."""

    nodes: dict[str, NodeStyle]  # node_id → style
    edges: list[tuple[str, str, EdgeStyle]]  # (parent, child, style)
    graph_attrs: dict[str, str] = field(default_factory=dict)  # rankdir, fontname, etc.


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Node colors
COLOR_SEED = "#e8e8e8"
COLOR_NORMAL = "#d4edda"
COLOR_FERTILE = "#28a745"
COLOR_STERILE = "#f5f5f5"
COLOR_CRASH = "#dc3545"
COLOR_TIMEOUT = "#fd7e14"
COLOR_GHOST = "#f0f0f0"
COLOR_COLLAPSED = "#f0f0f0"
BORDER_ZOMBIE = "#dc3545"
BORDER_TACHYCARDIA = "#fd7e14"

# Edge colors by strategy
STRATEGY_COLORS: dict[str, str] = {
    "deterministic": "#6c757d",
    "havoc": "#007bff",
    "spam": "#6f42c1",
    "sniper": "#dc3545",
    "helper_sniper": "#e83e8c",
    "generative_seed": "#6c757d",
}
STRATEGY_STYLES: dict[str, str] = {
    "sniper": "bold",
    "helper_sniper": "bold",
    "generative_seed": "dashed",
}

FERTILE_THRESHOLD = 5  # total_finds >= this → fertile styling
ANCESTRY_DEPTH_LIMIT = 200
BORDER_MRCA = "#007bff"


# ---------------------------------------------------------------------------
# Tree metrics
# ---------------------------------------------------------------------------


@dataclass
class TreeMetrics:
    """Computed structural metrics for a subgraph."""

    strahler: dict[str, int]  # node_id → Strahler order
    branching_factors: dict[str, int]  # internal node_id → number of children
    subtree_sizes: dict[str, int]  # node_id → total descendants including self
    imbalance_cv: dict[str, float]  # internal node_id → CV of children's subtree sizes
    success_rates: dict[str, float | None]  # node_id → success rate (None if insufficient)
    # Aggregates
    max_strahler: int
    mean_branching: float
    max_branching: int
    mean_imbalance: float


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def load_coverage_state(state_path: Path) -> dict:
    """Load coverage_state.pkl and return the full state dict."""
    with open(state_path, "rb") as f:
        return pickle.load(f)


def build_adjacency_graph(per_file_coverage: dict[str, dict]) -> LineageGraph:
    """Build the full adjacency graph from per_file_coverage metadata."""
    children: dict[str, list[str]] = defaultdict(list)
    parent: dict[str, str | None] = {}
    roots: list[str] = []

    for filename, metadata in per_file_coverage.items():
        parent_id = metadata.get("parent_id")
        parent[filename] = parent_id

        if parent_id is not None:
            children[parent_id].append(filename)
        elif not metadata.get("is_pruned", False):
            roots.append(filename)

    # Sort children lists for deterministic output
    for parent_id in children:
        children[parent_id].sort()

    roots.sort()
    return LineageGraph(
        children=dict(children),
        parent=parent,
        roots=roots,
        metadata=per_file_coverage,
    )


# ---------------------------------------------------------------------------
# Subgraph extraction: ancestry
# ---------------------------------------------------------------------------


def extract_ancestry(graph: LineageGraph, target: str) -> Subgraph:
    """Walk parent_id backward from target to seed, producing a linear chain."""
    nodes_ordered: list[str] = []
    edges: list[tuple[str, str]] = []
    special_nodes: dict[str, str] = {}

    current = target
    visited: set[str] = set()

    for _ in range(ANCESTRY_DEPTH_LIMIT):
        if current in visited:
            break
        visited.add(current)
        nodes_ordered.append(current)

        # Check if this node is a ghost (not in metadata)
        if current not in graph.metadata:
            special_nodes[current] = "ghost"
            # Ghost may still have tombstone parent_id
            break

        parent_id = graph.parent.get(current)
        if parent_id is None:
            break  # Reached seed

        edges.append((parent_id, current))

        # Check if parent is a ghost
        if parent_id not in graph.metadata:
            # Insert ghost node
            special_nodes[parent_id] = "ghost"
            nodes_ordered.append(parent_id)
            # Check tombstone for further ancestry — tombstones are IN metadata
            break

        current = parent_id

    # Reverse to get seed-first order
    nodes_ordered.reverse()
    edges.reverse()
    return Subgraph(nodes=set(nodes_ordered), edges=edges, special_nodes=special_nodes)


# ---------------------------------------------------------------------------
# Subgraph extraction: descendants
# ---------------------------------------------------------------------------


def extract_descendants(
    graph: LineageGraph,
    root: str,
    max_depth: int | None = None,
    collapse_sterile: bool = True,
) -> Subgraph:
    """BFS from root through children, producing a tree."""
    nodes: set[str] = set()
    edges: list[tuple[str, str]] = []
    collapsed: dict[str, int] = {}
    special_nodes: dict[str, str] = {}

    # BFS
    queue: deque[tuple[str, int]] = deque([(root, 0)])
    nodes.add(root)

    # Track children per parent for sterile collapsing
    parent_children: dict[str, list[str]] = defaultdict(list)

    while queue:
        current, depth = queue.popleft()

        if max_depth is not None and depth >= max_depth:
            continue

        # Sort children by total_finds descending for consistent layout
        child_list = graph.children.get(current, [])
        sorted_children = sorted(
            child_list,
            key=lambda c: graph.metadata.get(c, {}).get("total_finds", 0),
            reverse=True,
        )

        for child in sorted_children:
            meta = graph.metadata.get(child, {})
            # Skip pruned nodes as BFS starting points
            if meta.get("is_pruned", False):
                continue

            if child not in nodes:
                nodes.add(child)
                edges.append((current, child))
                parent_children[current].append(child)
                queue.append((child, depth + 1))

    # Sterile collapsing
    if collapse_sterile:
        for parent_node, children_list in parent_children.items():
            # Find sterile childless siblings
            sterile_childless = [
                c
                for c in children_list
                if graph.metadata.get(c, {}).get("is_sterile", False)
                and not graph.children.get(c, [])
            ]

            if len(sterile_childless) >= 3 and len(sterile_childless) == len(children_list):
                # ALL children are sterile+childless — collapse all
                summary_id = f"__collapsed_{parent_node}_{len(sterile_childless)}"
                collapsed[summary_id] = len(sterile_childless)
                special_nodes[summary_id] = "collapsed"

                # Remove individual sterile nodes, add summary
                for c in sterile_childless:
                    nodes.discard(c)
                    edges = [(p, ch) for p, ch in edges if ch != c]
                nodes.add(summary_id)
                edges.append((parent_node, summary_id))

            elif len(sterile_childless) >= 3:
                # Some children are non-sterile — collapse only the sterile ones
                summary_id = f"__collapsed_{parent_node}_{len(sterile_childless)}"
                collapsed[summary_id] = len(sterile_childless)
                special_nodes[summary_id] = "collapsed"

                for c in sterile_childless:
                    nodes.discard(c)
                    edges = [(p, ch) for p, ch in edges if ch != c]
                nodes.add(summary_id)
                edges.append((parent_node, summary_id))

    return Subgraph(nodes=nodes, edges=edges, collapsed=collapsed, special_nodes=special_nodes)


# ---------------------------------------------------------------------------
# Subgraph extraction: MRCA
# ---------------------------------------------------------------------------


def _get_ancestor_list(graph: LineageGraph, target: str) -> list[str]:
    """Get ordered ancestor list for a target (target first, seed last)."""
    ancestors: list[str] = []
    current = target
    visited: set[str] = set()

    for _ in range(ANCESTRY_DEPTH_LIMIT):
        if current in visited:
            break
        visited.add(current)
        ancestors.append(current)

        if current not in graph.metadata:
            break

        parent_id = graph.parent.get(current)
        if parent_id is None:
            break
        current = parent_id

    return ancestors


def extract_mrca(graph: LineageGraph, targets: list[str]) -> Subgraph:
    """Find the MRCA of multiple files and return the subgraph from MRCA to each target.

    Returns a Subgraph containing:
    - The MRCA node (in special_nodes with role "mrca")
    - Diverging branches from MRCA to each target

    If targets share no common ancestor (different seeds), returns all full
    paths as disconnected components with no MRCA marked.
    """
    if not targets:
        return Subgraph(nodes=set(), edges=[])

    # Compute ancestor lists
    ancestor_lists: list[list[str]] = []
    ancestor_sets: list[set[str]] = []
    for t in targets:
        ancestors = _get_ancestor_list(graph, t)
        ancestor_lists.append(ancestors)
        ancestor_sets.append(set(ancestors))

    # Find MRCA: walk first target's ancestors from target toward root
    mrca: str | None = None
    for candidate in ancestor_lists[0]:
        if all(candidate in aset for aset in ancestor_sets[1:]):
            mrca = candidate
            break

    nodes: set[str] = set()
    edges: list[tuple[str, str]] = []
    special_nodes: dict[str, str] = {}

    if mrca is not None:
        special_nodes[mrca] = "mrca"
        # For each target, collect path from MRCA to target
        for ancestors in ancestor_lists:
            # ancestors is target-first, seed-last
            path: list[str] = []
            for a in ancestors:
                path.append(a)
                if a == mrca:
                    break
            # path is target → ... → mrca; reverse to mrca → ... → target
            path.reverse()
            for n in path:
                nodes.add(n)
            for i in range(len(path) - 1):
                edge = (path[i], path[i + 1])
                if edge not in edges:
                    edges.append(edge)
    else:
        # Disjoint seeds — return all full paths
        for ancestors in ancestor_lists:
            ancestors_reversed = list(reversed(ancestors))  # seed → ... → target
            for n in ancestors_reversed:
                nodes.add(n)
            for i in range(len(ancestors_reversed) - 1):
                edge = (ancestors_reversed[i], ancestors_reversed[i + 1])
                if edge not in edges:
                    edges.append(edge)

    return Subgraph(nodes=nodes, edges=edges, special_nodes=special_nodes)


# ---------------------------------------------------------------------------
# Tree metrics computation
# ---------------------------------------------------------------------------


def compute_strahler(graph: LineageGraph, subgraph: Subgraph) -> dict[str, int]:
    """Compute Strahler stream order for each node in the subgraph.

    Strahler order rules:
    - Leaves (no children in subgraph): order = 1
    - Internal node: if only one child has the maximum order among children,
      order = that maximum. If two or more children share the maximum,
      order = maximum + 1.
    """
    # Build children map within the subgraph
    sub_children: dict[str, list[str]] = defaultdict(list)
    for parent_node, child_node in subgraph.edges:
        sub_children[parent_node].append(child_node)

    strahler: dict[str, int] = {}

    def _compute(node: str) -> int:
        if node in strahler:
            return strahler[node]
        children = sub_children.get(node, [])
        if not children:
            strahler[node] = 1
            return 1
        child_orders = [_compute(c) for c in children]
        max_order = max(child_orders)
        count_max = child_orders.count(max_order)
        order = max_order + 1 if count_max >= 2 else max_order
        strahler[node] = order
        return order

    for node in subgraph.nodes:
        _compute(node)

    return strahler


def compute_tree_metrics(
    subgraph: Subgraph,
    graph: LineageGraph,
) -> TreeMetrics:
    """Compute all structural metrics for the subgraph."""
    # Children map within subgraph
    sub_children: dict[str, list[str]] = defaultdict(list)
    for parent_node, child_node in subgraph.edges:
        sub_children[parent_node].append(child_node)

    # Strahler
    strahler = compute_strahler(graph, subgraph)

    # Subtree sizes (post-order)
    subtree_sizes: dict[str, int] = {}

    def _subtree_size(node: str) -> int:
        if node in subtree_sizes:
            return subtree_sizes[node]
        children = sub_children.get(node, [])
        size = 1 + sum(_subtree_size(c) for c in children)
        subtree_sizes[node] = size
        return size

    for node in subgraph.nodes:
        _subtree_size(node)

    # Branching factor
    branching_factors: dict[str, int] = {}
    for node in subgraph.nodes:
        children = sub_children.get(node, [])
        if children:
            branching_factors[node] = len(children)

    # Imbalance CV
    imbalance_cv: dict[str, float] = {}
    for node, children in sub_children.items():
        if len(children) >= 2:
            child_sizes = [subtree_sizes.get(c, 1) for c in children]
            m = mean(child_sizes)
            if m > 0:
                std = math.sqrt(sum((s - m) ** 2 for s in child_sizes) / len(child_sizes))
                imbalance_cv[node] = std / m
            else:
                imbalance_cv[node] = 0.0

    # Success rates
    success_rates: dict[str, float | None] = {}
    for node in subgraph.nodes:
        if node.startswith("__collapsed_"):
            continue
        meta = graph.metadata.get(node, {})
        if meta.get("parent_id") is None:
            # Seed — not mutated
            success_rates[node] = None
            continue
        total_mutations = meta.get("total_mutations_against", 0)
        total_finds = meta.get("total_finds", 0)
        if total_mutations > 0:
            success_rates[node] = total_finds / total_mutations
        else:
            # Fallback lower bound
            denom = max(1, total_finds + meta.get("mutations_since_last_find", 0))
            success_rates[node] = total_finds / denom

    # Aggregates
    max_strahler = max(strahler.values()) if strahler else 0
    bf_values = list(branching_factors.values())
    mean_branching = mean(bf_values) if bf_values else 0.0
    max_branching = max(bf_values) if bf_values else 0
    cv_values = list(imbalance_cv.values())
    mean_imbalance = mean(cv_values) if cv_values else 0.0

    return TreeMetrics(
        strahler=strahler,
        branching_factors=branching_factors,
        subtree_sizes=subtree_sizes,
        imbalance_cv=imbalance_cv,
        success_rates=success_rates,
        max_strahler=max_strahler,
        mean_branching=mean_branching,
        max_branching=max_branching,
        mean_imbalance=mean_imbalance,
    )


# ---------------------------------------------------------------------------
# Edge discovery computation
# ---------------------------------------------------------------------------


def compute_edge_discoveries(
    parent_id: str,
    child_id: str,
    graph: LineageGraph,
    state: dict,
) -> list[str]:
    """Compute what new coverage the child discovered relative to its parent.

    Diffs child's baseline_coverage edges/rare_events against parent's
    lineage_coverage_profile. Returns human-readable strings for the
    most notable discoveries (up to 3).
    """
    parent_meta = graph.metadata.get(parent_id, {})
    child_meta = graph.metadata.get(child_id, {})

    # Parent lineage coverage (uses set[int])
    parent_lineage = parent_meta.get("lineage_coverage_profile", {})
    parent_edges: set[int] = set()
    parent_rare: set[int] = set()
    for harness_data in parent_lineage.values():
        if isinstance(harness_data, dict):
            edges = harness_data.get("edges", set())
            parent_edges.update(edges if isinstance(edges, set) else set(edges))
            rare = harness_data.get("rare_events", set())
            parent_rare.update(rare if isinstance(rare, set) else set(rare))

    # Child baseline coverage
    child_baseline = child_meta.get("baseline_coverage", {})
    child_edges: set[int] = set()
    child_rare: set[int] = set()
    for harness_data in child_baseline.values():
        if isinstance(harness_data, dict):
            edges = harness_data.get("edges", [])
            child_edges.update(edges if isinstance(edges, set) else set(edges))
            rare = harness_data.get("rare_events", [])
            child_rare.update(rare if isinstance(rare, set) else set(rare))

    new_edges = child_edges - parent_edges
    new_rare = child_rare - parent_rare

    if not new_edges and not new_rare:
        return []

    # Build reverse maps for human-readable names
    edge_map = state.get("edge_map", {})
    rare_event_map = state.get("rare_event_map", {})
    rev_edge = {v: k for k, v in edge_map.items()} if edge_map else {}
    rev_rare = {v: k for k, v in rare_event_map.items()} if rare_event_map else {}

    discoveries: list[str] = []

    # Prefer rare events (more meaningful)
    for rid in sorted(new_rare)[:2]:
        name = rev_rare.get(rid, str(rid))
        discoveries.append(f"+RARE:{name}")

    # Then edges
    remaining = 3 - len(discoveries)
    for eid in sorted(new_edges)[:remaining]:
        name = rev_edge.get(eid, str(eid))
        discoveries.append(f"+{name}")

    return discoveries


# ---------------------------------------------------------------------------
# Decoration
# ---------------------------------------------------------------------------


def _build_node_label(
    node: str,
    metadata: dict,
    label_style: str,
    metrics: TreeMetrics | None = None,
    show_strahler: bool = False,
    show_success_rate: bool = False,
) -> str:
    """Build a node label based on the label style."""
    if label_style == "minimal":
        parts = [node]
        if show_strahler and metrics and node in metrics.strahler:
            parts.append(f"S={metrics.strahler[node]}")
        if show_success_rate and metrics:
            parts.extend(_success_rate_label_parts(node, metadata, metrics))
        return "\\n".join(parts) if len(parts) > 1 else node

    dm = metadata.get("discovery_mutation", {})
    strategy = dm.get("strategy", "?")
    transformers = dm.get("transformers", [])
    jit_stats = dm.get("jit_stats", {})
    depth = metadata.get("lineage_depth", 0)
    finds = metadata.get("total_finds", 0)
    density = jit_stats.get("max_exit_density", 0.0)
    edges_count = len(metadata.get("baseline_coverage", {}).get("h1", {}).get("edges", []))

    parts = [node]
    parts.append(f"{strategy} ({len(transformers)} transformers)")
    parts.append(f"depth={depth} finds={finds}")
    parts.append(f"density={density:.3f} edges={edges_count}")

    if show_strahler and metrics and node in metrics.strahler:
        parts.append(f"S={metrics.strahler[node]}")

    if show_success_rate and metrics:
        parts.extend(_success_rate_label_parts(node, metadata, metrics))

    if label_style == "verbose":
        exec_time = metadata.get("execution_time_ms", 0)
        file_size = metadata.get("file_size_bytes", 0)
        disc_time = metadata.get("discovery_time", "?")
        parts.append(f"exec={exec_time}ms size={file_size}B")
        parts.append(f"discovered={disc_time}")
        if transformers:
            parts.append("transformers: " + ", ".join(transformers))
        for key, val in sorted(jit_stats.items()):
            parts.append(f"  {key}={val}")

    return "\\n".join(parts)


def _success_rate_label_parts(node: str, metadata: dict, metrics: TreeMetrics) -> list[str]:
    """Build success rate label parts for a node."""
    if metadata.get("parent_id") is None:
        return []  # Seed — skip
    rate = metrics.success_rates.get(node)
    if rate is None:
        return []
    total_mutations = metadata.get("total_mutations_against", 0)
    total_finds = metadata.get("total_finds", 0)
    if total_mutations > 0:
        return [f"rate={total_finds}/{total_mutations} ({rate:.1%})"]
    else:
        denom = max(1, total_finds + metadata.get("mutations_since_last_find", 0))
        return [f"rate\\u2265{total_finds}/{denom} (\\u2264{rate:.1%})"]


def _build_tooltip(metadata: dict) -> str:
    """Build a tooltip with full metadata dump."""
    dm = metadata.get("discovery_mutation", {})
    jit_stats = dm.get("jit_stats", {})
    transformers = dm.get("transformers", [])
    watched_deps = jit_stats.get("watched_dependencies", dm.get("watched_dependencies", []))

    lines = [
        f"strategy: {dm.get('strategy', '?')}",
        f"transformers: {transformers}",
        f"depth: {metadata.get('lineage_depth', 0)}",
        f"total_finds: {metadata.get('total_finds', 0)}",
        f"total_mutations_against: {metadata.get('total_mutations_against', 0)}",
        f"execution_time_ms: {metadata.get('execution_time_ms', 0)}",
        f"file_size_bytes: {metadata.get('file_size_bytes', 0)}",
        f"content_hash: {metadata.get('content_hash', '?')}",
        f"coverage_hash: {metadata.get('coverage_hash', '?')}",
        f"discovery_time: {metadata.get('discovery_time', '?')}",
        f"watched_dependencies: {watched_deps}",
    ]
    for key, val in sorted(jit_stats.items()):
        lines.append(f"jit.{key}: {val}")
    return "\\n".join(lines)


def decorate(
    subgraph: Subgraph,
    graph: LineageGraph,
    label_style: str = "standard",
    no_color: bool = False,
    metrics: TreeMetrics | None = None,
    show_strahler: bool = False,
    show_success_rate: bool = False,
    show_discoveries: bool = False,
    state: dict | None = None,
) -> DecoratedGraph:
    """Assign visual properties to nodes and edges."""
    node_styles: dict[str, NodeStyle] = {}
    edge_list: list[tuple[str, str, EdgeStyle]] = []

    for node in subgraph.nodes:
        ns = NodeStyle()

        # Priority 1: special nodes
        if node in subgraph.special_nodes:
            role = subgraph.special_nodes[node]
            if role == "ghost":
                ns.shape = "box"
                ns.style = "dotted"
                ns.fillcolor = COLOR_GHOST
                ns.fontcolor = "gray"
                ns.label = f"{node}\\n[pruned]"
                ns.tooltip = ""
            elif role == "crash":
                ns.shape = "octagon"
                ns.fillcolor = COLOR_CRASH
                ns.fontcolor = "white"
                ns.label = node
                ns.tooltip = ""
            elif role == "collapsed":
                count = subgraph.collapsed.get(node, 0)
                ns.shape = "note"
                ns.fillcolor = COLOR_COLLAPSED
                ns.label = f"{count} sterile leaves"
                ns.tooltip = ""
            elif role == "mrca":
                # MRCA gets normal node styling plus blue border overlay
                metadata = graph.metadata.get(node, {})
                ns = _decorate_corpus_node(
                    node, metadata, label_style, metrics, show_strahler, show_success_rate
                )
                ns.color = BORDER_MRCA
                ns.penwidth = 3.0
                node_styles[node] = ns
                continue
            node_styles[node] = ns
            continue

        # Priority 2: normal corpus nodes
        metadata = graph.metadata.get(node, {})
        ns = _decorate_corpus_node(
            node, metadata, label_style, metrics, show_strahler, show_success_rate
        )
        node_styles[node] = ns

    # Edge decoration
    for parent_node, child_node in subgraph.edges:
        es = EdgeStyle()
        child_meta = graph.metadata.get(child_node, {})
        dm = child_meta.get("discovery_mutation", {})
        strategy = dm.get("strategy", "")
        transformers = dm.get("transformers", [])

        es.color = STRATEGY_COLORS.get(strategy, "#000000")
        es.style = STRATEGY_STYLES.get(strategy, "solid")

        if label_style == "minimal":
            es.label = strategy
        elif label_style == "verbose":
            es.label = f"{strategy}\\n{', '.join(transformers)}" if transformers else strategy
        else:
            es.label = f"{strategy} ({len(transformers)})" if transformers else strategy

        # Append discovery labels
        if show_discoveries and state is not None:
            discoveries = compute_edge_discoveries(parent_node, child_node, graph, state)
            if discoveries:
                es.label = es.label + "\\n" + "\\n".join(discoveries)

        # Make fertile edges more prominent
        if child_meta.get("total_finds", 0) >= FERTILE_THRESHOLD:
            es.penwidth = 2.0

        edge_list.append((parent_node, child_node, es))

    # no_color override
    if no_color:
        for ns in node_styles.values():
            ns.fillcolor = "white"
            ns.fontcolor = "black"
            if ns.color:
                ns.color = "black"
        for _, _, es in edge_list:
            es.color = "black"

    graph_attrs = {
        "rankdir": "LR",
        "fontname": "Helvetica",
    }

    return DecoratedGraph(nodes=node_styles, edges=edge_list, graph_attrs=graph_attrs)


def _decorate_corpus_node(
    node: str,
    metadata: dict,
    label_style: str,
    metrics: TreeMetrics | None,
    show_strahler: bool,
    show_success_rate: bool,
) -> NodeStyle:
    """Build NodeStyle for a normal corpus node."""
    ns = NodeStyle()
    parent_id = metadata.get("parent_id")
    is_pruned = metadata.get("is_pruned", False)
    is_sterile = metadata.get("is_sterile", False)
    total_finds = metadata.get("total_finds", 0)

    if parent_id is None and not is_pruned:
        ns.shape = "doubleoctagon"
        ns.fillcolor = COLOR_SEED
    elif is_sterile:
        ns.fillcolor = COLOR_STERILE
        ns.style = "filled,dashed"
    elif total_finds >= FERTILE_THRESHOLD:
        ns.fillcolor = COLOR_FERTILE
        ns.fontcolor = "white"
    else:
        ns.fillcolor = COLOR_NORMAL

    # Border overlays
    dm = metadata.get("discovery_mutation", {})
    jit_stats = dm.get("jit_stats", {})

    if jit_stats.get("zombie_traces", 0) > 0:
        ns.color = BORDER_ZOMBIE
        ns.penwidth = 3.0

    if jit_stats.get("max_exit_density", 0.0) > 0.1:
        ns.color = BORDER_TACHYCARDIA
        ns.penwidth = 2.0

    ns.label = _build_node_label(
        node, metadata, label_style, metrics, show_strahler, show_success_rate
    )
    ns.tooltip = _build_tooltip(metadata)
    return ns


# ---------------------------------------------------------------------------
# DOT emission
# ---------------------------------------------------------------------------


def _escape_dot(text: str) -> str:
    """Escape special characters for DOT labels/tooltips."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def emit_dot(decorated: DecoratedGraph) -> str:
    """Generate a Graphviz DOT string from a decorated graph."""
    lines: list[str] = []
    lines.append("digraph lineage {")

    # Graph-level attributes
    for key, val in decorated.graph_attrs.items():
        lines.append(f"  {key}={_quote(val)};")

    lines.append('  node [fontname="Helvetica", fontsize=10];')
    lines.append('  edge [fontname="Helvetica", fontsize=8];')
    lines.append("")

    # Nodes
    for node_id, ns in decorated.nodes.items():
        attrs: list[str] = []
        attrs.append(f'label="{_escape_dot(ns.label)}"')
        attrs.append(f"shape={ns.shape}")
        attrs.append(f'fillcolor="{ns.fillcolor}"')
        attrs.append(f'fontcolor="{ns.fontcolor}"')
        attrs.append(f'style="{ns.style}"')
        if ns.color:
            attrs.append(f'color="{ns.color}"')
        if ns.penwidth != 1.0:
            attrs.append(f"penwidth={ns.penwidth}")
        if ns.tooltip:
            attrs.append(f'tooltip="{_escape_dot(ns.tooltip)}"')
        attrs_str = ", ".join(attrs)
        lines.append(f"  {_quote(node_id)} [{attrs_str}];")

    lines.append("")

    # Edges
    for parent_node, child_node, es in decorated.edges:
        attrs = []
        attrs.append(f'label="{_escape_dot(es.label)}"')
        attrs.append(f'color="{es.color}"')
        if es.style != "solid":
            attrs.append(f'style="{es.style}"')
        if es.penwidth != 1.0:
            attrs.append(f"penwidth={es.penwidth}")
        attrs_str = ", ".join(attrs)
        lines.append(f"  {_quote(parent_node)} -> {_quote(child_node)} [{attrs_str}];")

    lines.append("}")
    return "\n".join(lines)


def _quote(text: str) -> str:
    """Quote a DOT identifier."""
    return f'"{_escape_dot(text)}"'


# ---------------------------------------------------------------------------
# JSON emission
# ---------------------------------------------------------------------------


def emit_json(
    decorated: DecoratedGraph,
    graph: LineageGraph,
    subgraph: Subgraph,
    metrics: TreeMetrics | None = None,
    edge_discoveries: dict[tuple[str, str], list[str]] | None = None,
) -> str:
    """Emit the decorated graph as JSON."""
    nodes_list = []
    for node_id, ns in decorated.nodes.items():
        meta = graph.metadata.get(node_id, {})
        node_entry: dict = {
            "id": node_id,
            "metadata": meta,
            "style": asdict(ns),
        }
        if metrics is not None:
            node_entry["metrics"] = {
                "strahler": metrics.strahler.get(node_id, 0),
                "subtree_size": metrics.subtree_sizes.get(node_id, 0),
                "branching_factor": metrics.branching_factors.get(node_id, 0),
                "imbalance_cv": metrics.imbalance_cv.get(node_id, 0.0),
                "success_rate": metrics.success_rates.get(node_id),
                "success_rate_exact": (
                    graph.metadata.get(node_id, {}).get("total_mutations_against", 0) > 0
                    if node_id in graph.metadata
                    else False
                ),
            }
        nodes_list.append(node_entry)

    edges_list = []
    for parent_node, child_node, es in decorated.edges:
        edge_entry: dict = {
            "source": parent_node,
            "target": child_node,
            "style": asdict(es),
        }
        if edge_discoveries and (parent_node, child_node) in edge_discoveries:
            edge_entry["discoveries"] = edge_discoveries[(parent_node, child_node)]
        edges_list.append(edge_entry)

    stats: dict = {
        "node_count": len(subgraph.nodes),
        "edge_count": len(subgraph.edges),
        "collapsed_count": len(subgraph.collapsed),
    }
    if metrics is not None:
        stats["max_strahler"] = metrics.max_strahler
        stats["mean_branching"] = round(metrics.mean_branching, 1)
        stats["mean_imbalance"] = round(metrics.mean_imbalance, 2)
        rates = [r for r in metrics.success_rates.values() if r is not None]
        stats["mean_success_rate"] = round(mean(rates), 4) if rates else None

    result = {
        "nodes": nodes_list,
        "edges": edges_list,
        "statistics": stats,
    }
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Graphviz rendering
# ---------------------------------------------------------------------------


def render_graphviz(dot_string: str, output_path: Path, fmt: str = "png") -> bool:
    """Invoke Graphviz dot to render the DOT string to an image file.

    Returns True on success, False on failure.
    """
    if shutil.which("dot") is None:
        print(
            "Error: Graphviz 'dot' command not found. "
            "Install Graphviz (e.g. 'apt install graphviz') to use --render.",
            file=sys.stderr,
        )
        return False

    try:
        result = subprocess.run(
            ["dot", f"-T{fmt}", "-o", str(output_path)],
            input=dot_string,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            print(f"Graphviz error: {result.stderr}", file=sys.stderr)
            return False
        return True
    except subprocess.TimeoutExpired:
        print("Error: Graphviz rendering timed out after 60 seconds.", file=sys.stderr)
        return False
    except OSError as e:
        print(f"Error running Graphviz: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Statistics summary
# ---------------------------------------------------------------------------


def print_ancestry_stats(chain: list[str], graph: LineageGraph) -> None:
    """Print ancestry-mode statistics to stderr."""
    if not chain:
        return

    seed = chain[0]
    target = chain[-1]
    depth = len(chain) - 1

    strategies: list[str] = []
    total_edges = 0
    first_zombie: str | None = None
    first_zombie_depth: int | None = None

    for i, node in enumerate(chain):
        meta = graph.metadata.get(node, {})
        dm = meta.get("discovery_mutation", {})
        strategy = dm.get("strategy", "?")
        strategies.append(strategy)

        # Count edges from baseline coverage
        bc = meta.get("baseline_coverage", {})
        for harness_data in bc.values():
            if isinstance(harness_data, dict):
                total_edges += len(harness_data.get("edges", []))

        # Check for zombie traces
        jit_stats = dm.get("jit_stats", {})
        if first_zombie is None and jit_stats.get("zombie_traces", 0) > 0:
            first_zombie = node
            first_zombie_depth = i

    strategy_path = " → ".join(strategies)

    print(f"Lineage for {target} (depth={depth}):", file=sys.stderr)
    print(f"  Seed: {seed}", file=sys.stderr)
    print(f"  Path: {' → '.join(chain)}", file=sys.stderr)
    print(f"  Strategies: {strategy_path}", file=sys.stderr)
    print(f"  Total edges discovered along path: {total_edges}", file=sys.stderr)
    if first_zombie is not None:
        print(
            f"  Zombie traces first appeared at: {first_zombie} (depth={first_zombie_depth})",
            file=sys.stderr,
        )


def print_descendants_stats(
    subgraph: Subgraph, graph: LineageGraph, metrics: TreeMetrics | None = None
) -> None:
    """Print descendants-mode statistics to stderr."""
    seed_count = 0
    mutation_count = 0
    depths: list[int] = []
    strategy_counts: dict[str, int] = defaultdict(int)
    fertile_count = 0
    sterile_count = 0
    zombie_count = 0
    tachycardia_count = 0

    real_nodes = [n for n in subgraph.nodes if not n.startswith("__collapsed_")]
    for node in real_nodes:
        meta = graph.metadata.get(node, {})
        if not meta:
            continue

        parent_id = meta.get("parent_id")
        if parent_id is None:
            seed_count += 1
        else:
            mutation_count += 1

        depths.append(meta.get("lineage_depth", 0))

        dm = meta.get("discovery_mutation", {})
        strategy = dm.get("strategy", "unknown")
        strategy_counts[strategy] += 1

        total_finds = meta.get("total_finds", 0)
        if total_finds >= FERTILE_THRESHOLD:
            fertile_count += 1
        if meta.get("is_sterile", False):
            sterile_count += 1

        jit_stats = dm.get("jit_stats", {})
        if jit_stats.get("zombie_traces", 0) > 0:
            zombie_count += 1
        if jit_stats.get("max_exit_density", 0.0) > 0.1:
            tachycardia_count += 1

    # Add collapsed counts to sterile
    for count in subgraph.collapsed.values():
        sterile_count += count

    total_nodes = len(real_nodes) + sum(subgraph.collapsed.values())
    max_depth = max(depths) if depths else 0
    mean_depth = sum(depths) / len(depths) if depths else 0.0

    fertile_pct = (fertile_count / total_nodes * 100) if total_nodes else 0.0
    sterile_pct = (sterile_count / total_nodes * 100) if total_nodes else 0.0

    strategy_str = ", ".join(f"{k}={v}" for k, v in sorted(strategy_counts.items()))

    print("Lineage Statistics:", file=sys.stderr)
    print(
        f"  Nodes: {total_nodes} ({seed_count} seeds, {mutation_count} mutations)", file=sys.stderr
    )
    print(f"  Depth: max={max_depth}, mean={mean_depth:.1f}", file=sys.stderr)
    print(f"  Strategies: {strategy_str}", file=sys.stderr)
    print(f"  Fertile nodes: {fertile_count} ({fertile_pct:.0f}%)", file=sys.stderr)
    print(f"  Sterile nodes: {sterile_count} ({sterile_pct:.0f}%)", file=sys.stderr)
    print(f"  Zombie traces: {zombie_count} nodes", file=sys.stderr)
    print(f"  Tachycardia events: {tachycardia_count} nodes", file=sys.stderr)

    if metrics is not None:
        print(
            f"  Branching factor: mean={metrics.mean_branching:.1f}, max={metrics.max_branching}",
            file=sys.stderr,
        )
        print(f"  Imbalance (CV): mean={metrics.mean_imbalance:.2f}", file=sys.stderr)
        print(f"  Strahler order: max={metrics.max_strahler}", file=sys.stderr)
        rates = [r for r in metrics.success_rates.values() if r is not None]
        if rates:
            mean_rate = mean(rates) * 100
            sorted_rates = sorted(rates)
            mid = len(sorted_rates) // 2
            median_rate = (
                sorted_rates[mid] * 100
                if len(sorted_rates) % 2
                else (sorted_rates[mid - 1] + sorted_rates[mid]) / 2 * 100
            )
            print(
                f"  Success rate: mean={mean_rate:.1f}%, median={median_rate:.1f}%",
                file=sys.stderr,
            )


def print_mrca_stats(
    targets: list[str],
    mrca: str | None,
    subgraph: Subgraph,
    graph: LineageGraph,
) -> None:
    """Print MRCA-mode statistics to stderr."""
    target_names = " and ".join(targets)
    print(f"MRCA of {target_names}:", file=sys.stderr)

    if mrca is None:
        print("  No common ancestor — targets descend from different seeds.", file=sys.stderr)
        for t in targets:
            ancestors = _get_ancestor_list(graph, t)
            seed = ancestors[-1] if ancestors else "?"
            depth = len(ancestors) - 1
            print(f"  {t}: seed={seed}, depth={depth}", file=sys.stderr)
        return

    mrca_meta = graph.metadata.get(mrca, {})
    mrca_depth = mrca_meta.get("lineage_depth", 0)
    # Find seed
    ancestors = _get_ancestor_list(graph, mrca)
    seed = ancestors[-1] if ancestors else mrca

    print(f"  Common ancestor: {mrca} (depth={mrca_depth}, seed={seed})", file=sys.stderr)

    for t in targets:
        t_ancestors = _get_ancestor_list(graph, t)
        # Count mutations from MRCA to target
        branch: list[str] = []
        for a in t_ancestors:
            branch.append(a)
            if a == mrca:
                break
        branch.reverse()  # mrca → ... → target
        strategies = []
        for n in branch[1:]:  # skip mrca itself
            dm = graph.metadata.get(n, {}).get("discovery_mutation", {})
            strategies.append(dm.get("strategy", "?"))
        strategy_path = "→".join(strategies) if strategies else "(none)"
        print(
            f"  Branch to {t}: {len(branch) - 1} mutations ({strategy_path})",
            file=sys.stderr,
        )

    dm = mrca_meta.get("discovery_mutation", {})
    print(
        f"  Divergence point strategy: {dm.get('strategy', '?')} at {mrca}",
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------


def resolve_target(target_str: str, per_file_coverage: dict[str, dict]) -> tuple[str, str]:
    """Resolve a CLI target argument to a corpus filename and mode hint.

    Handles:
    - Plain corpus filenames: "1234.py" → ("1234.py", "file")
    - Corpus file paths: "corpus/jit_interesting_tests/1234.py" → ("1234.py", "file")
    - Crash directory paths: "crashes/session_crash_..." → resolved from metadata

    Returns (corpus_filename, target_type) where target_type is "file" or "crash_dir".
    """
    target_path = Path(target_str)

    # Check if it's a crash directory
    metadata_json = target_path / "metadata.json"
    if target_path.is_dir() and metadata_json.exists():
        with open(metadata_json) as f:
            crash_meta = json.load(f)
        # Try session_corpus_files first, then parent_id
        session_files = crash_meta.get("session_corpus_files", {})
        warmup = session_files.get("warmup")
        if warmup:
            if warmup not in per_file_coverage:
                print(
                    f"Error: crash warmup file '{warmup}' not found in coverage state.",
                    file=sys.stderr,
                )
                sys.exit(1)
            return warmup, "crash_dir"
        parent_id = crash_meta.get("parent_id")
        if parent_id:
            if parent_id not in per_file_coverage:
                print(
                    f"Error: crash parent '{parent_id}' not found in coverage state.",
                    file=sys.stderr,
                )
                sys.exit(1)
            return parent_id, "crash_dir"
        print(
            f"Error: crash metadata in '{target_str}' has no parent_id or session_corpus_files.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Extract basename from file path
    filename = target_path.name if target_path.suffix else target_str

    if filename not in per_file_coverage:
        print(f"Error: '{filename}' not found in coverage state.", file=sys.stderr)
        sys.exit(1)

    return filename, "file"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Main entry point for lafleur-lineage."""
    parser = argparse.ArgumentParser(
        description="Visualize corpus lineage trees from coverage_state.pkl.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ancestry 1234.py                      # Trace a file back to its seed
  %(prog)s ancestry crashes/session_crash_XXX/    # Trace a crash's lineage
  %(prog)s descendants 0001.py                    # Show a seed's family tree
  %(prog)s descendants 0001.py --max-depth 5      # Limit depth
  %(prog)s descendants 0001.py --render -o tree.png  # Render to PNG
        """,
    )

    # Common options
    parser.add_argument(
        "--state-path",
        type=Path,
        default=Path("coverage/coverage_state.pkl"),
        help="Path to coverage_state.pkl",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output file path (default: stdout)",
    )
    parser.add_argument(
        "--render",
        action="store_true",
        help="Render to image via Graphviz (requires dot)",
    )
    parser.add_argument(
        "--format",
        choices=["png", "svg", "pdf"],
        default="png",
        help="Image format for --render (default: png)",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of DOT")
    parser.add_argument("--no-color", action="store_true", help="Monochrome output")
    parser.add_argument(
        "--label-style",
        choices=["minimal", "standard", "verbose"],
        default="standard",
        help="Node label detail level",
    )
    parser.add_argument(
        "--highlight",
        type=str,
        default=None,
        help="Highlight a specific file and its path to root",
    )
    parser.add_argument(
        "--layout",
        choices=["LR", "TB"],
        default="LR",
        help="Graph direction (default: LR)",
    )
    parser.add_argument(
        "--show-strahler",
        action="store_true",
        help="Display Strahler stream order numbers on nodes",
    )
    parser.add_argument(
        "--show-success-rate",
        action="store_true",
        help="Display success rate (finds/attempts) on nodes",
    )
    parser.add_argument(
        "--show-discoveries",
        action="store_true",
        help="Label edges with specific coverage discoveries (ancestry/mrca modes only)",
    )

    subparsers = parser.add_subparsers(dest="mode", help="Visualization mode")

    # Ancestry subcommand
    ancestry_parser = subparsers.add_parser(
        "ancestry", help="Trace a file's lineage back to its seed"
    )
    ancestry_parser.add_argument("target", help="Corpus filename, file path, or crash directory")

    # Descendants subcommand
    desc_parser = subparsers.add_parser("descendants", help="Show what a file produced")
    desc_parser.add_argument("root", help="Corpus filename or file path")
    desc_parser.add_argument("--max-depth", type=int, default=None, help="Maximum tree depth")
    desc_parser.add_argument(
        "--no-collapse-sterile",
        action="store_true",
        help="Don't collapse sterile leaf clusters",
    )

    # MRCA subcommand
    mrca_parser = subparsers.add_parser(
        "mrca",
        help="Find the most recent common ancestor of two or more files",
    )
    mrca_parser.add_argument(
        "targets",
        nargs="+",
        help="Two or more corpus filenames or paths",
    )

    args = parser.parse_args()

    if args.mode is None:
        parser.print_help()
        sys.exit(0)

    # Load state
    state = load_coverage_state(args.state_path)
    per_file_coverage = state.get("per_file_coverage", {})

    # Build graph
    graph = build_adjacency_graph(per_file_coverage)

    # Extract subgraph based on mode
    mrca_node: str | None = None
    mrca_targets: list[str] = []
    chain: list[str] | None = None

    if args.mode == "ancestry":
        target, _ = resolve_target(args.target, per_file_coverage)
        subgraph = extract_ancestry(graph, target)
        chain = _extract_ancestry_chain(graph, target)
    elif args.mode == "descendants":
        root, _ = resolve_target(args.root, per_file_coverage)
        subgraph = extract_descendants(
            graph,
            root,
            max_depth=args.max_depth,
            collapse_sterile=not args.no_collapse_sterile,
        )
    elif args.mode == "mrca":
        mrca_targets = [resolve_target(t, per_file_coverage)[0] for t in args.targets]
        subgraph = extract_mrca(graph, mrca_targets)
        # Identify MRCA node
        for node, role in subgraph.special_nodes.items():
            if role == "mrca":
                mrca_node = node
                break
    else:
        parser.print_help()
        sys.exit(0)

    # Compute metrics
    metrics = compute_tree_metrics(subgraph, graph)

    # Only show discoveries for ancestry/mrca modes
    effective_show_discoveries = args.show_discoveries and args.mode in ("ancestry", "mrca")

    # Decorate
    decorated = decorate(
        subgraph,
        graph,
        label_style=args.label_style,
        no_color=args.no_color,
        metrics=metrics,
        show_strahler=args.show_strahler,
        show_success_rate=args.show_success_rate,
        show_discoveries=effective_show_discoveries,
        state=state if effective_show_discoveries else None,
    )
    decorated.graph_attrs["rankdir"] = args.layout

    # Compute edge discoveries for JSON output
    edge_discoveries: dict[tuple[str, str], list[str]] | None = None
    if effective_show_discoveries and state is not None:
        edge_discoveries = {}
        for parent_node, child_node in subgraph.edges:
            disc = compute_edge_discoveries(parent_node, child_node, graph, state)
            if disc:
                edge_discoveries[(parent_node, child_node)] = disc

    # Emit
    if args.json:
        output = emit_json(
            decorated, graph, subgraph, metrics=metrics, edge_discoveries=edge_discoveries
        )
    else:
        output = emit_dot(decorated)

    # Render or write
    if args.render:
        output_path = args.output or Path(f"lineage.{args.format}")
        dot_output = emit_dot(decorated)
        success = render_graphviz(dot_output, output_path, fmt=args.format)
        if success:
            print(f"Rendered to {output_path}", file=sys.stderr)
        else:
            sys.exit(1)
    elif args.output:
        args.output.write_text(output)
    else:
        print(output)

    # Print statistics to stderr
    if args.mode == "ancestry" and chain is not None:
        print_ancestry_stats(chain, graph)
    elif args.mode == "descendants":
        print_descendants_stats(subgraph, graph, metrics=metrics)
    elif args.mode == "mrca":
        print_mrca_stats(mrca_targets, mrca_node, subgraph, graph)


def _extract_ancestry_chain(graph: LineageGraph, target: str) -> list[str]:
    """Extract ordered ancestry chain (seed first, target last) for stats."""
    chain: list[str] = []
    current = target
    visited: set[str] = set()

    for _ in range(ANCESTRY_DEPTH_LIMIT):
        if current in visited:
            break
        visited.add(current)
        chain.append(current)

        if current not in graph.metadata:
            break

        parent_id = graph.parent.get(current)
        if parent_id is None:
            break
        current = parent_id

    chain.reverse()
    return chain
