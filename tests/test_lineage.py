"""Tests for lafleur.lineage — corpus lineage visualization tool."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from lafleur.lineage import (
    COLOR_COLLAPSED,
    COLOR_GHOST,
    COLOR_SEED,
    BORDER_TACHYCARDIA,
    BORDER_ZOMBIE,
    STRATEGY_COLORS,
    build_adjacency_graph,
    decorate,
    emit_dot,
    emit_json,
    extract_ancestry,
    extract_descendants,
    print_ancestry_stats,
    print_descendants_stats,
    render_graphviz,
    resolve_target,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


def make_simple_chain() -> dict:
    """Create a 3-node chain: seed → middle → leaf."""
    return {
        "seed.py": {
            "parent_id": None,
            "lineage_depth": 0,
            "total_finds": 2,
            "mutations_since_last_find": 10,
            "total_mutations_against": 50,
            "is_sterile": False,
            "is_pruned": False,
            "discovery_mutation": {
                "strategy": "generative_seed",
                "transformers": [],
                "jit_stats": {},
            },
            "discovery_time": "2025-01-01T00:00:00Z",
            "execution_time_ms": 100,
            "file_size_bytes": 500,
            "baseline_coverage": {"h1": {"edges": [1, 2], "uops": [10], "rare_events": []}},
        },
        "middle.py": {
            "parent_id": "seed.py",
            "lineage_depth": 1,
            "total_finds": 1,
            "mutations_since_last_find": 5,
            "total_mutations_against": 20,
            "is_sterile": False,
            "is_pruned": False,
            "discovery_mutation": {
                "strategy": "havoc",
                "transformers": ["OperatorSwapMutator", "GuardInjector"],
                "jit_stats": {"max_exit_density": 0.05, "zombie_traces": 0},
            },
            "discovery_time": "2025-01-01T01:00:00Z",
            "execution_time_ms": 150,
            "file_size_bytes": 800,
            "baseline_coverage": {"h1": {"edges": [1, 2, 3], "uops": [10, 11], "rare_events": []}},
        },
        "leaf.py": {
            "parent_id": "middle.py",
            "lineage_depth": 2,
            "total_finds": 0,
            "mutations_since_last_find": 100,
            "total_mutations_against": 100,
            "is_sterile": True,
            "is_pruned": False,
            "discovery_mutation": {
                "strategy": "sniper",
                "transformers": ["SniperMutator"],
                "jit_stats": {"max_exit_density": 0.3, "zombie_traces": 2},
            },
            "discovery_time": "2025-01-01T02:00:00Z",
            "execution_time_ms": 200,
            "file_size_bytes": 1200,
            "baseline_coverage": {
                "h1": {
                    "edges": [1, 2, 3, 4],
                    "uops": [10, 11, 12],
                    "rare_events": [100],
                }
            },
        },
    }


def make_branching_tree() -> dict:
    """Create a tree: seed → [child_a, child_b, child_c, child_d, child_e]
    where child_c, child_d, child_e are sterile leaves.
    child_a has two children of its own.
    """
    base = {
        "strategy": "havoc",
        "transformers": ["OpSwap"],
        "jit_stats": {"max_exit_density": 0.01, "zombie_traces": 0},
    }
    return {
        "seed.py": {
            "parent_id": None,
            "lineage_depth": 0,
            "total_finds": 10,
            "total_mutations_against": 200,
            "is_sterile": False,
            "is_pruned": False,
            "discovery_mutation": {
                "strategy": "generative_seed",
                "transformers": [],
                "jit_stats": {},
            },
            "discovery_time": "2025-01-01T00:00:00Z",
            "execution_time_ms": 100,
            "file_size_bytes": 500,
            "baseline_coverage": {},
            "mutations_since_last_find": 0,
        },
        "child_a.py": {
            "parent_id": "seed.py",
            "lineage_depth": 1,
            "total_finds": 3,
            "total_mutations_against": 50,
            "is_sterile": False,
            "is_pruned": False,
            "discovery_mutation": base,
            "discovery_time": "2025-01-01T01:00:00Z",
            "execution_time_ms": 120,
            "file_size_bytes": 600,
            "baseline_coverage": {},
            "mutations_since_last_find": 0,
        },
        "child_b.py": {
            "parent_id": "seed.py",
            "lineage_depth": 1,
            "total_finds": 1,
            "total_mutations_against": 30,
            "is_sterile": False,
            "is_pruned": False,
            "discovery_mutation": base,
            "discovery_time": "2025-01-01T01:01:00Z",
            "execution_time_ms": 110,
            "file_size_bytes": 550,
            "baseline_coverage": {},
            "mutations_since_last_find": 0,
        },
        "child_c.py": {
            "parent_id": "seed.py",
            "lineage_depth": 1,
            "total_finds": 0,
            "total_mutations_against": 100,
            "is_sterile": True,
            "is_pruned": False,
            "discovery_mutation": base,
            "discovery_time": "2025-01-01T01:02:00Z",
            "execution_time_ms": 90,
            "file_size_bytes": 400,
            "baseline_coverage": {},
            "mutations_since_last_find": 100,
        },
        "child_d.py": {
            "parent_id": "seed.py",
            "lineage_depth": 1,
            "total_finds": 0,
            "total_mutations_against": 80,
            "is_sterile": True,
            "is_pruned": False,
            "discovery_mutation": base,
            "discovery_time": "2025-01-01T01:03:00Z",
            "execution_time_ms": 85,
            "file_size_bytes": 380,
            "baseline_coverage": {},
            "mutations_since_last_find": 80,
        },
        "child_e.py": {
            "parent_id": "seed.py",
            "lineage_depth": 1,
            "total_finds": 0,
            "total_mutations_against": 90,
            "is_sterile": True,
            "is_pruned": False,
            "discovery_mutation": base,
            "discovery_time": "2025-01-01T01:04:00Z",
            "execution_time_ms": 95,
            "file_size_bytes": 420,
            "baseline_coverage": {},
            "mutations_since_last_find": 90,
        },
        "grandchild_1.py": {
            "parent_id": "child_a.py",
            "lineage_depth": 2,
            "total_finds": 0,
            "total_mutations_against": 10,
            "is_sterile": True,
            "is_pruned": False,
            "discovery_mutation": {
                "strategy": "sniper",
                "transformers": ["SniperMutator"],
                "jit_stats": {"max_exit_density": 0.02, "zombie_traces": 0},
            },
            "discovery_time": "2025-01-01T02:00:00Z",
            "execution_time_ms": 200,
            "file_size_bytes": 1000,
            "baseline_coverage": {},
            "mutations_since_last_find": 10,
        },
        "grandchild_2.py": {
            "parent_id": "child_a.py",
            "lineage_depth": 2,
            "total_finds": 0,
            "total_mutations_against": 15,
            "is_sterile": False,
            "is_pruned": False,
            "discovery_mutation": {
                "strategy": "spam",
                "transformers": ["SpamMutator"],
                "jit_stats": {"max_exit_density": 0.01, "zombie_traces": 0},
            },
            "discovery_time": "2025-01-01T02:01:00Z",
            "execution_time_ms": 180,
            "file_size_bytes": 900,
            "baseline_coverage": {},
            "mutations_since_last_find": 5,
        },
    }


# ---------------------------------------------------------------------------
# TestBuildAdjacencyGraph
# ---------------------------------------------------------------------------


class TestBuildAdjacencyGraph(unittest.TestCase):
    def test_basic_chain(self):
        pfc = make_simple_chain()
        graph = build_adjacency_graph(pfc)

        self.assertEqual(graph.parent["seed.py"], None)
        self.assertEqual(graph.parent["middle.py"], "seed.py")
        self.assertEqual(graph.parent["leaf.py"], "middle.py")
        self.assertIn("middle.py", graph.children["seed.py"])
        self.assertIn("leaf.py", graph.children["middle.py"])
        self.assertEqual(graph.roots, ["seed.py"])
        self.assertEqual(graph.metadata, pfc)

    def test_branching_tree(self):
        pfc = make_branching_tree()
        graph = build_adjacency_graph(pfc)

        children_of_seed = graph.children["seed.py"]
        self.assertEqual(len(children_of_seed), 5)
        children_of_a = graph.children["child_a.py"]
        self.assertEqual(len(children_of_a), 2)

    def test_with_tombstone(self):
        pfc = make_simple_chain()
        # Make middle a tombstone
        pfc["middle.py"]["is_pruned"] = True
        graph = build_adjacency_graph(pfc)

        # Tombstones participate in parent/children but not roots
        self.assertIn("middle.py", graph.parent)
        self.assertIn("leaf.py", graph.children["middle.py"])
        self.assertNotIn("middle.py", graph.roots)

    def test_empty_corpus(self):
        graph = build_adjacency_graph({})

        self.assertEqual(graph.children, {})
        self.assertEqual(graph.parent, {})
        self.assertEqual(graph.roots, [])

    def test_orphaned_file(self):
        """File with parent_id referencing nonexistent file doesn't crash."""
        pfc = {
            "orphan.py": {
                "parent_id": "nonexistent.py",
                "lineage_depth": 1,
                "is_pruned": False,
                "discovery_mutation": {"strategy": "havoc", "transformers": [], "jit_stats": {}},
            }
        }
        graph = build_adjacency_graph(pfc)
        self.assertEqual(graph.parent["orphan.py"], "nonexistent.py")
        self.assertIn("orphan.py", graph.children["nonexistent.py"])
        self.assertEqual(graph.roots, [])

    def test_children_sorted(self):
        """Children lists are sorted by filename for determinism."""
        pfc = {
            "seed.py": {
                "parent_id": None,
                "is_pruned": False,
                "discovery_mutation": {},
            },
            "z.py": {
                "parent_id": "seed.py",
                "is_pruned": False,
                "discovery_mutation": {},
            },
            "a.py": {
                "parent_id": "seed.py",
                "is_pruned": False,
                "discovery_mutation": {},
            },
            "m.py": {
                "parent_id": "seed.py",
                "is_pruned": False,
                "discovery_mutation": {},
            },
        }
        graph = build_adjacency_graph(pfc)
        self.assertEqual(graph.children["seed.py"], ["a.py", "m.py", "z.py"])


# ---------------------------------------------------------------------------
# TestExtractAncestry
# ---------------------------------------------------------------------------


class TestExtractAncestry(unittest.TestCase):
    def test_simple_chain(self):
        pfc = make_simple_chain()
        graph = build_adjacency_graph(pfc)
        sub = extract_ancestry(graph, "leaf.py")

        self.assertEqual(sub.nodes, {"seed.py", "middle.py", "leaf.py"})
        self.assertEqual(sub.edges, [("seed.py", "middle.py"), ("middle.py", "leaf.py")])

    def test_seed_only(self):
        pfc = make_simple_chain()
        graph = build_adjacency_graph(pfc)
        sub = extract_ancestry(graph, "seed.py")

        self.assertEqual(sub.nodes, {"seed.py"})
        self.assertEqual(sub.edges, [])

    def test_ghost_node_with_tombstone(self):
        """Ghost node inserted for missing parent that has tombstone metadata."""
        pfc = make_simple_chain()
        # Remove middle from metadata but keep its parent_id reference in leaf
        del pfc["middle.py"]
        graph = build_adjacency_graph(pfc)

        sub = extract_ancestry(graph, "leaf.py")
        self.assertIn("middle.py", sub.nodes)
        self.assertEqual(sub.special_nodes["middle.py"], "ghost")

    def test_ghost_node_no_tombstone(self):
        """Ghost node for completely missing file terminates the chain."""
        pfc = {
            "leaf.py": {
                "parent_id": "ghost.py",
                "lineage_depth": 1,
                "is_pruned": False,
                "discovery_mutation": {"strategy": "havoc", "transformers": [], "jit_stats": {}},
            }
        }
        graph = build_adjacency_graph(pfc)
        sub = extract_ancestry(graph, "leaf.py")

        self.assertIn("ghost.py", sub.nodes)
        self.assertEqual(sub.special_nodes["ghost.py"], "ghost")
        # Chain terminates at ghost
        self.assertEqual(len(sub.nodes), 2)

    def test_depth_limit(self):
        """Chain of 250 nodes — ancestry walk is capped at ANCESTRY_DEPTH_LIMIT."""
        pfc = {}
        for i in range(250):
            name = f"{i:04d}.py"
            parent = f"{i - 1:04d}.py" if i > 0 else None
            pfc[name] = {
                "parent_id": parent,
                "lineage_depth": i,
                "is_pruned": False,
                "discovery_mutation": {"strategy": "havoc", "transformers": [], "jit_stats": {}},
            }
        graph = build_adjacency_graph(pfc)
        sub = extract_ancestry(graph, "0249.py")

        # Should be capped at ~200 nodes (ANCESTRY_DEPTH_LIMIT)
        self.assertLessEqual(len(sub.nodes), 201)


# ---------------------------------------------------------------------------
# TestExtractDescendants
# ---------------------------------------------------------------------------


class TestExtractDescendants(unittest.TestCase):
    def test_simple_chain(self):
        pfc = make_simple_chain()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", collapse_sterile=False)

        self.assertEqual(sub.nodes, {"seed.py", "middle.py", "leaf.py"})

    def test_max_depth(self):
        pfc = make_simple_chain()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", max_depth=1, collapse_sterile=False)

        # depth=0 is seed, depth=1 explores children of seed only
        self.assertIn("seed.py", sub.nodes)
        self.assertIn("middle.py", sub.nodes)
        self.assertNotIn("leaf.py", sub.nodes)

    def test_sterile_collapsing(self):
        """Tree with 3 sterile childless siblings → collapsed into one summary."""
        pfc = make_branching_tree()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", collapse_sterile=True)

        # child_c, child_d, child_e are sterile and childless BUT
        # child_a and child_b are also children of seed, so only the sterile ones collapse
        collapsed_keys = list(sub.collapsed.keys())
        self.assertEqual(len(collapsed_keys), 1)
        self.assertEqual(list(sub.collapsed.values())[0], 3)

        # The individual sterile nodes should be gone
        self.assertNotIn("child_c.py", sub.nodes)
        self.assertNotIn("child_d.py", sub.nodes)
        self.assertNotIn("child_e.py", sub.nodes)

    def test_sterile_collapsing_threshold(self):
        """Only 2 sterile siblings → NOT collapsed."""
        pfc = make_branching_tree()
        # Remove one sterile child
        del pfc["child_e.py"]
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", collapse_sterile=True)

        # child_c and child_d remain (only 2, below threshold of 3)
        self.assertIn("child_c.py", sub.nodes)
        self.assertIn("child_d.py", sub.nodes)
        self.assertEqual(len(sub.collapsed), 0)

    def test_collapsing_disabled(self):
        pfc = make_branching_tree()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", collapse_sterile=False)

        # All sterile nodes preserved
        self.assertIn("child_c.py", sub.nodes)
        self.assertIn("child_d.py", sub.nodes)
        self.assertIn("child_e.py", sub.nodes)

    def test_from_non_root(self):
        pfc = make_branching_tree()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "child_a.py", collapse_sterile=False)

        self.assertIn("child_a.py", sub.nodes)
        self.assertIn("grandchild_1.py", sub.nodes)
        self.assertIn("grandchild_2.py", sub.nodes)
        self.assertNotIn("seed.py", sub.nodes)


# ---------------------------------------------------------------------------
# TestDecorate
# ---------------------------------------------------------------------------


class TestDecorate(unittest.TestCase):
    def _make_graph_and_subgraph(self, pfc=None):
        pfc = pfc or make_simple_chain()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", collapse_sterile=False)
        return graph, sub

    def test_seed_node_styling(self):
        graph, sub = self._make_graph_and_subgraph()
        decorated = decorate(sub, graph)

        seed_style = decorated.nodes["seed.py"]
        self.assertEqual(seed_style.shape, "doubleoctagon")
        self.assertEqual(seed_style.fillcolor, COLOR_SEED)

    def test_sterile_node_styling(self):
        graph, sub = self._make_graph_and_subgraph()
        decorated = decorate(sub, graph)

        leaf_style = decorated.nodes["leaf.py"]
        # leaf.py is sterile BUT also has zombie+tachycardia overlays
        # The fill is sterile since sterile takes priority over normal
        # But zombie border overrides to BORDER_ZOMBIE... then tachycardia overrides
        self.assertIn("dashed", leaf_style.style)

    def test_fertile_node_styling(self):
        pfc = make_branching_tree()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", collapse_sterile=False)
        decorated = decorate(sub, graph)

        # seed has 10 finds (≥ FERTILE_THRESHOLD=5) but is also a seed → seed wins
        seed_style = decorated.nodes["seed.py"]
        self.assertEqual(seed_style.shape, "doubleoctagon")

    def test_zombie_border(self):
        graph, sub = self._make_graph_and_subgraph()
        decorated = decorate(sub, graph)

        # leaf.py has zombie_traces=2
        leaf_style = decorated.nodes["leaf.py"]
        # Tachycardia (0.3 > 0.1) applies after zombie, overriding color
        # Both zombie and tachycardia are checked but tachycardia overwrites
        self.assertIn(leaf_style.color, [BORDER_ZOMBIE, BORDER_TACHYCARDIA])
        self.assertGreater(leaf_style.penwidth, 1.0)

    def test_ghost_node_styling(self):
        pfc = {
            "leaf.py": {
                "parent_id": "ghost.py",
                "lineage_depth": 1,
                "is_pruned": False,
                "discovery_mutation": {"strategy": "havoc", "transformers": [], "jit_stats": {}},
            }
        }
        graph = build_adjacency_graph(pfc)
        sub = extract_ancestry(graph, "leaf.py")
        decorated = decorate(sub, graph)

        ghost_style = decorated.nodes["ghost.py"]
        self.assertEqual(ghost_style.style, "dotted")
        self.assertEqual(ghost_style.fontcolor, "gray")
        self.assertEqual(ghost_style.fillcolor, COLOR_GHOST)
        self.assertIn("[pruned]", ghost_style.label)

    def test_collapsed_node_styling(self):
        pfc = make_branching_tree()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", collapse_sterile=True)
        decorated = decorate(sub, graph)

        # Find the collapsed node
        collapsed_nodes = [n for n in decorated.nodes if n.startswith("__collapsed_")]
        self.assertEqual(len(collapsed_nodes), 1)
        ns = decorated.nodes[collapsed_nodes[0]]
        self.assertEqual(ns.shape, "note")
        self.assertEqual(ns.fillcolor, COLOR_COLLAPSED)
        self.assertIn("sterile leaves", ns.label)

    def test_edge_colors(self):
        graph, sub = self._make_graph_and_subgraph()
        decorated = decorate(sub, graph)

        edge_map = {(p, c): es for p, c, es in decorated.edges}
        # middle.py was created by "havoc"
        havoc_edge = edge_map.get(("seed.py", "middle.py"))
        self.assertIsNotNone(havoc_edge)
        self.assertEqual(havoc_edge.color, STRATEGY_COLORS["havoc"])

        # leaf.py was created by "sniper"
        sniper_edge = edge_map.get(("middle.py", "leaf.py"))
        self.assertIsNotNone(sniper_edge)
        self.assertEqual(sniper_edge.color, STRATEGY_COLORS["sniper"])

    def test_label_style_minimal(self):
        graph, sub = self._make_graph_and_subgraph()
        decorated = decorate(sub, graph, label_style="minimal")

        # Minimal: just the filename
        self.assertEqual(decorated.nodes["seed.py"].label, "seed.py")
        self.assertEqual(decorated.nodes["middle.py"].label, "middle.py")

    def test_label_style_standard(self):
        graph, sub = self._make_graph_and_subgraph()
        decorated = decorate(sub, graph, label_style="standard")

        label = decorated.nodes["middle.py"].label
        self.assertIn("middle.py", label)
        self.assertIn("havoc", label)
        self.assertIn("depth=1", label)

    def test_no_color(self):
        graph, sub = self._make_graph_and_subgraph()
        decorated = decorate(sub, graph, no_color=True)

        for ns in decorated.nodes.values():
            self.assertEqual(ns.fillcolor, "white")
            self.assertEqual(ns.fontcolor, "black")
        for _, _, es in decorated.edges:
            self.assertEqual(es.color, "black")


# ---------------------------------------------------------------------------
# TestEmitDot
# ---------------------------------------------------------------------------


class TestEmitDot(unittest.TestCase):
    def _make_decorated(self):
        pfc = make_simple_chain()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", collapse_sterile=False)
        return decorate(sub, graph)

    def test_basic_structure(self):
        dot = emit_dot(self._make_decorated())
        self.assertTrue(dot.startswith("digraph lineage {"))
        self.assertTrue(dot.rstrip().endswith("}"))

    def test_nodes_emitted(self):
        dot = emit_dot(self._make_decorated())
        self.assertIn('"seed.py"', dot)
        self.assertIn('"middle.py"', dot)
        self.assertIn('"leaf.py"', dot)

    def test_edges_emitted(self):
        dot = emit_dot(self._make_decorated())
        self.assertIn('"seed.py" -> "middle.py"', dot)
        self.assertIn('"middle.py" -> "leaf.py"', dot)

    def test_edge_labels(self):
        dot = emit_dot(self._make_decorated())
        # Edges should have strategy labels
        self.assertIn("havoc", dot)
        self.assertIn("sniper", dot)

    def test_tooltips_included(self):
        dot = emit_dot(self._make_decorated())
        self.assertIn("tooltip=", dot)


# ---------------------------------------------------------------------------
# TestEmitJson
# ---------------------------------------------------------------------------


class TestEmitJson(unittest.TestCase):
    def _make_json_output(self):
        pfc = make_simple_chain()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", collapse_sterile=False)
        decorated = decorate(sub, graph)
        return emit_json(decorated, graph, sub)

    def test_valid_json(self):
        output = self._make_json_output()
        data = json.loads(output)
        self.assertIsInstance(data, dict)

    def test_schema(self):
        data = json.loads(self._make_json_output())
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("statistics", data)

    def test_node_entries(self):
        data = json.loads(self._make_json_output())
        for node in data["nodes"]:
            self.assertIn("id", node)
            self.assertIn("metadata", node)
            self.assertIn("style", node)

    def test_edge_entries(self):
        data = json.loads(self._make_json_output())
        for edge in data["edges"]:
            self.assertIn("source", edge)
            self.assertIn("target", edge)
            self.assertIn("style", edge)


# ---------------------------------------------------------------------------
# TestResolveTarget
# ---------------------------------------------------------------------------


class TestResolveTarget(unittest.TestCase):
    def test_plain_filename(self):
        pfc = {"1234.py": {"parent_id": None}}
        filename, target_type = resolve_target("1234.py", pfc)
        self.assertEqual(filename, "1234.py")
        self.assertEqual(target_type, "file")

    def test_path_to_file(self):
        pfc = {"1234.py": {"parent_id": None}}
        filename, target_type = resolve_target("corpus/jit_interesting_tests/1234.py", pfc)
        self.assertEqual(filename, "1234.py")
        self.assertEqual(target_type, "file")

    def test_nonexistent_file(self):
        pfc = {"1234.py": {"parent_id": None}}
        with self.assertRaises(SystemExit):
            resolve_target("nonexistent.py", pfc)

    def test_crash_directory(self, *_args):
        """Crash directory with metadata.json resolves to warmup file."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            crash_dir = Path(tmpdir) / "crash_001"
            crash_dir.mkdir()
            meta = {"session_corpus_files": {"warmup": "parent.py"}}
            (crash_dir / "metadata.json").write_text(json.dumps(meta))

            pfc = {"parent.py": {"parent_id": None}}
            filename, target_type = resolve_target(str(crash_dir), pfc)
            self.assertEqual(filename, "parent.py")
            self.assertEqual(target_type, "crash_dir")


# ---------------------------------------------------------------------------
# TestRenderGraphviz
# ---------------------------------------------------------------------------


class TestRenderGraphviz(unittest.TestCase):
    @patch("lafleur.lineage.shutil.which", return_value=None)
    def test_dot_not_installed(self, mock_which):
        result = render_graphviz("digraph {}", Path("out.png"))
        self.assertFalse(result)

    @patch("lafleur.lineage.subprocess.run")
    @patch("lafleur.lineage.shutil.which", return_value="/usr/bin/dot")
    def test_correct_command_args(self, mock_which, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        result = render_graphviz("digraph {}", Path("out.svg"), fmt="svg")

        self.assertTrue(result)
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, ["dot", "-Tsvg", "-o", "out.svg"])


# ---------------------------------------------------------------------------
# TestStatistics
# ---------------------------------------------------------------------------


class TestStatistics(unittest.TestCase):
    @patch("sys.stderr")
    def test_ancestry_stats(self, mock_stderr):
        pfc = make_simple_chain()
        graph = build_adjacency_graph(pfc)
        chain = ["seed.py", "middle.py", "leaf.py"]
        print_ancestry_stats(chain, graph)

        output = "".join(call.args[0] for call in mock_stderr.write.call_args_list)
        self.assertIn("Lineage for leaf.py", output)
        self.assertIn("Seed: seed.py", output)
        self.assertIn("depth=2", output)

    @patch("sys.stderr")
    def test_descendants_stats(self, mock_stderr):
        pfc = make_branching_tree()
        graph = build_adjacency_graph(pfc)
        sub = extract_descendants(graph, "seed.py", collapse_sterile=False)
        print_descendants_stats(sub, graph)

        output = "".join(call.args[0] for call in mock_stderr.write.call_args_list)
        self.assertIn("Lineage Statistics:", output)
        self.assertIn("Nodes:", output)
        self.assertIn("Strategies:", output)

    @patch("sys.stderr")
    def test_ancestry_stats_empty_chain(self, mock_stderr):
        """Empty chain produces no output."""
        graph = build_adjacency_graph({})
        print_ancestry_stats([], graph)
        mock_stderr.write.assert_not_called()


# ---------------------------------------------------------------------------
# TestCLI
# ---------------------------------------------------------------------------


class TestCLI(unittest.TestCase):
    def test_no_mode_shows_help(self):
        """No subcommand shows help and exits 0."""
        with patch("sys.argv", ["lafleur-lineage"]):
            from lafleur.lineage import main

            with patch("sys.exit", side_effect=SystemExit(0)) as mock_exit:
                with patch("argparse.ArgumentParser.print_help"):
                    with self.assertRaises(SystemExit):
                        main()
                mock_exit.assert_called_with(0)

    @patch("lafleur.lineage.load_coverage_state")
    def test_ancestry_mode_e2e(self, mock_load):
        """End-to-end ancestry mode produces DOT output."""
        mock_load.return_value = {"per_file_coverage": make_simple_chain()}

        with patch(
            "sys.argv",
            ["lafleur-lineage", "--state-path", "fake.pkl", "ancestry", "leaf.py"],
        ):
            from lafleur.lineage import main

            with patch("builtins.print") as mock_print:
                main()

            # The first positional print call should be the DOT output
            printed = mock_print.call_args_list
            dot_calls = [c for c in printed if c.kwargs.get("file") is not sys.stderr]
            self.assertTrue(any("digraph lineage" in str(c) for c in dot_calls))

    @patch("lafleur.lineage.load_coverage_state")
    def test_descendants_mode_e2e(self, mock_load):
        """End-to-end descendants mode produces DOT output."""
        mock_load.return_value = {"per_file_coverage": make_simple_chain()}

        with patch(
            "sys.argv",
            ["lafleur-lineage", "--state-path", "fake.pkl", "descendants", "seed.py"],
        ):
            from lafleur.lineage import main

            with patch("builtins.print") as mock_print:
                main()

            printed = mock_print.call_args_list
            dot_calls = [c for c in printed if c.kwargs.get("file") is not sys.stderr]
            self.assertTrue(any("digraph lineage" in str(c) for c in dot_calls))

    @patch("lafleur.lineage.load_coverage_state")
    def test_json_mode(self, mock_load):
        """--json flag emits valid JSON."""
        mock_load.return_value = {"per_file_coverage": make_simple_chain()}

        with patch(
            "sys.argv",
            [
                "lafleur-lineage",
                "--state-path",
                "fake.pkl",
                "--json",
                "descendants",
                "seed.py",
            ],
        ):
            from lafleur.lineage import main

            with patch("builtins.print") as mock_print:
                main()

            printed = mock_print.call_args_list
            json_calls = [c for c in printed if c.kwargs.get("file") is not sys.stderr]
            # Should have at least one call with JSON content
            json_output = str(json_calls[0])
            self.assertIn("nodes", json_output)


if __name__ == "__main__":
    unittest.main()
