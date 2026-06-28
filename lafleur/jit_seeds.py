"""
Native JIT seed generation for lafleur (DRAFT — MVP of the fusil seed-gen port).

Background
----------
Until now lafleur produced new corpus seeds by shelling out to the *classic fusil*
executable (`CorpusManager.generate_new_seed` → `fusil-python-threaded --jit-fuzz
--jit-target-uop=ALL ...`). An analysis of what that subprocess actually does
(see fusil `doc/jit-seed-generation.md`) showed lafleur exercises only ONE slice of
fusil's 4,483-LOC JIT subsystem: the **uop-targeted** path —

    pick 3–7 Tier-2 micro-ops → fill each from a recipe template → declare the
    typed operands → wrap in a JIT-warming hot loop.

This module re-implements that slice natively, so lafleur no longer needs the fusil
subprocess for seeds. It is intentionally small:

* ``UOP_RECIPES`` — the 38-entry recipe table (ported verbatim from fusil's
  ``ast_pattern_generator.py``; pure data).
* simple value generators (``int``/``float``/``str``/``bytes``/collections) — a
  trimmed copy of fusil's ``ArgumentGenerator`` simple half (the only part not
  already in lafleur).
* the **object / "evil" generators are reused from lafleur itself**
  (``lafleur.mutators.utils.gen_*``) — fusil already imported these back from
  lafleur, so there is nothing to port for that half.

Output contract
---------------
``generate_jit_seed()`` returns the **core** seed (setup + ``uop_harness`` + hot
loop) — i.e. the ``core_code`` lafleur stores in the corpus. It is NOT standalone:
it assumes lafleur's boilerplate is prepended at execution time, which provides
``import sys`` and the ``fuzzer_rng`` RNG that the evil objects reference. This
matches how fusil-generated seeds already work today.

NOT in scope for this MVP (later "better seeds" work): fusil's ``BUG_PATTERNS``
(variational mode) and the from-scratch ``generate_pattern`` synthesize grammar.
"""

from __future__ import annotations

import random
from textwrap import dedent, indent
from typing import Callable

from lafleur.jit_bug_patterns import BUG_PATTERNS

# The object/"evil" generators already live in lafleur. Map each object "kind" to
# the lafleur generator that realizes it; the object_with_* variants all use the
# generic simple object (it has .x, .get_value, and __getitem__). When this module
# is used outside a full lafleur runtime (e.g. unit tests), degrade to simple values
# so the generator still produces parseable output.
try:
    from lafleur.mutators.utils import (
        gen_simple_object,
        gen_stateful_bool_object,
        gen_stateful_getattr_object,
        gen_stateful_getitem_object,
        gen_stateful_index_object,
        gen_stateful_iter_object,
        gen_stateful_len_object,
        gen_unstable_hash_object,
    )

    _OBJECT_GENERATORS: dict[str, Callable[[str], str]] = {
        "object": gen_simple_object,
        "object_with_attr": gen_simple_object,
        "object_with_getitem": gen_simple_object,
        "object_with_method": gen_simple_object,
        "stateful_getattr_object": gen_stateful_getattr_object,
        "stateful_getitem_object": gen_stateful_getitem_object,
        "stateful_index_object": gen_stateful_index_object,
        "stateful_bool_object": gen_stateful_bool_object,
        "stateful_iter_object": gen_stateful_iter_object,
        "stateful_len_object": gen_stateful_len_object,
        "unstable_hash_object": gen_unstable_hash_object,
    }
    HAS_OBJECTS = True
except ImportError:  # pragma: no cover - exercised only without lafleur installed
    _OBJECT_GENERATORS = {}
    HAS_OBJECTS = False


# ==============================================================================
# UOP recipe table (ported verbatim from fusil ast_pattern_generator.UOP_RECIPES)
# ==============================================================================
# Each entry: a `pattern` (a str.format template) and `placeholders` mapping each
# template field to a tuple of acceptable operand "kinds". "new_variable" means a
# fresh result name (an assignment/loop target); every other kind is realized by a
# value or object generator.
UOP_RECIPES: dict[str, dict] = {
    # --- Attribute and Subscript Operations ---
    "_STORE_ATTR": {
        "pattern": "{target_obj}.x = {value}",
        "placeholders": {
            "target_obj": ("object", "object_with_attr", "stateful_getattr_object"),
            "value": ("any",),
        },
    },
    "_LOAD_ATTR_METHOD_WITH_VALUES": {
        "pattern": "{result_var} = {target_obj}.get_value()",
        "placeholders": {
            "result_var": ("new_variable",),
            "target_obj": ("object_with_method", "stateful_getattr_object"),
        },
    },
    "_BINARY_SUBSCR_LIST_INT": {
        "pattern": "{result_var} = {target_list}[{index}]",
        "placeholders": {
            "result_var": ("new_variable",),
            "target_list": ("list", "object_with_getitem", "stateful_getitem_object"),
            "index": ("small_int", "stateful_index_object"),
        },
    },
    "_BINARY_OP_SUBSCR_GETITEM": {
        "pattern": "{result_var} = {target_obj}[{key}]",
        "placeholders": {
            "result_var": ("new_variable",),
            "target_obj": ("object_with_getitem", "stateful_getitem_object"),
            "key": ("any", "stateful_index_object"),
        },
    },
    "_DELETE_ATTR": {
        "pattern": "del {target_obj}.x",
        "placeholders": {"target_obj": ("object_with_attr",), "value": ("int",)},
    },
    # --- Binary Operations ---
    "_BINARY_OP_ADD_INT": {
        "pattern": "{result_var} = {operand_a} + {operand_b}",
        "placeholders": {
            "result_var": ("new_variable",),
            "operand_a": ("int",),
            "operand_b": ("int",),
        },
    },
    "_BINARY_OP_ADD_FLOAT": {
        "pattern": "{result_var} = {operand_a} + {operand_b}",
        "placeholders": {
            "result_var": ("new_variable",),
            "operand_a": ("float",),
            "operand_b": ("float",),
        },
    },
    "_BINARY_OP_MULTIPLY_TUPLE_INT": {
        "pattern": "{result_var} = {operand_a} * {operand_b}",
        "placeholders": {
            "result_var": ("new_variable",),
            "operand_a": ("tuple",),
            "operand_b": ("small_int", "stateful_index_object"),
        },
    },
    # --- Collection and Iteration ---
    "_BUILD_LIST": {
        "pattern": "{result_var} = [" + "{val_a}, {val_b}, {val_c}," * 50 + "]",
        "placeholders": {
            "result_var": ("new_variable",),
            "val_a": ("any",),
            "val_b": ("any",),
            "val_c": ("any",),
        },
    },
    "_CONTAINS_OP_DICT": {
        "pattern": "{result_var} = {key} in {target_dict}",
        "placeholders": {
            "result_var": ("new_variable",),
            "key": ("any", "unstable_hash_object"),
            "target_dict": ("dict",),
        },
    },
    # --- Compare and Boolean Operations ---
    "_COMPARE_OP_INT": {
        "pattern": "{result_var} = {operand_a} > {operand_b}",
        "placeholders": {
            "result_var": ("new_variable",),
            "operand_a": ("int",),
            "operand_b": ("int", "stateful_index_object"),
        },
    },
    "_TO_BOOL_INT": {
        "pattern": "if {target_int}: pass",
        "placeholders": {"target_int": ("int", "stateful_index_object", "stateful_len_object")},
    },
    "_LOAD_ATTR": {
        "pattern": "{target_obj}.x",
        "placeholders": {"target_obj": ("object_with_attr", "stateful_getattr_object")},
    },
    "_BINARY_SUBSCR_TUPLE_INT": {
        "pattern": "{target_tuple}[{index}]",
        "placeholders": {
            "target_tuple": ("tuple",),
            "index": ("small_int", "stateful_index_object"),
        },
    },
    "_BINARY_OP_SUB_INT": {"pattern": "{a} - {b}", "placeholders": {"a": ("int",), "b": ("int",)}},
    "_BINARY_OP_MUL_INT": {
        "pattern": "{a} * {b}",
        "placeholders": {"a": ("int",), "b": ("int", "stateful_index_object")},
    },
    "_BINARY_OP_SUB_FLOAT": {
        "pattern": "{a} - {b}",
        "placeholders": {"a": ("float",), "b": ("float",)},
    },
    "_BINARY_OP_MUL_FLOAT": {
        "pattern": "{a} * {b}",
        "placeholders": {"a": ("float",), "b": ("float",)},
    },
    "_BINARY_OP_AND_INT": {
        "pattern": "{a} & {b}",
        "placeholders": {
            "a": ("int", "stateful_index_object"),
            "b": ("int", "stateful_index_object"),
        },
    },
    "_BINARY_OP_OR_INT": {
        "pattern": "{a} | {b}",
        "placeholders": {
            "a": ("int", "stateful_index_object"),
            "b": ("int", "stateful_index_object"),
        },
    },
    "_BINARY_OP_XOR_INT": {
        "pattern": "{a} ^ {b}",
        "placeholders": {"a": ("int",), "b": ("int", "stateful_index_object")},
    },
    "_COMPARE_OP_EQ_INT": {
        "pattern": "{a} == {b}",
        "placeholders": {"a": ("int",), "b": ("int", "stateful_index_object")},
    },
    "_COMPARE_OP_LT_INT": {"pattern": "{a} < {b}", "placeholders": {"a": ("int",), "b": ("int",)}},
    "_COMPARE_OP_GT_INT": {"pattern": "{a} > {b}", "placeholders": {"a": ("int",), "b": ("int",)}},
    "_COMPARE_OP_EQ_STR": {"pattern": "{a} == {b}", "placeholders": {"a": ("str",), "b": ("str",)}},
    "_COMPARE_OP_LT_STR": {"pattern": "{a} < {b}", "placeholders": {"a": ("str",), "b": ("str",)}},
    "_COMPARE_OP_GT_STR": {"pattern": "{a} > {b}", "placeholders": {"a": ("str",), "b": ("str",)}},
    "_UNARY_NOT": {
        "pattern": "not {value}",
        "placeholders": {"value": ("any", "stateful_index_object")},
    },
    "_TO_BOOL": {
        "pattern": "if {obj}: pass",
        "placeholders": {
            "obj": (
                "object",
                "stateful_bool_object",
                "stateful_len_object",
                "stateful_index_object",
            )
        },
    },
    "_BUILD_TUPLE": {
        "pattern": "(" + "{a}, {b}," * 50 + ")",
        "placeholders": {"a": ("any",), "b": ("any",)},
    },
    "_BUILD_SET": {
        "pattern": "{{ {a}, {b} }}",
        "placeholders": {
            "a": ("any", "unstable_hash_object"),
            "b": ("any", "unstable_hash_object"),
        },
    },
    "_BUILD_MAP": {
        "pattern": "{{ {key}: {value} }}",
        "placeholders": {"key": ("str", "int", "unstable_hash_object"), "value": ("any",)},
    },
    "_UNPACK_SEQUENCE_TUPLE": {
        "pattern": "x, *y = {iterable}",
        "placeholders": {"iterable": ("tuple", "stateful_iter_object")},
    },
    "_UNPACK_SEQUENCE_LIST": {
        "pattern": "x, *y = {iterable}",
        "placeholders": {"iterable": ("list", "stateful_iter_object")},
    },
    "_FOR_ITER_LIST": {
        "pattern": "for {result_var} in {iterable}: pass",
        "placeholders": {
            "result_var": ("new_variable",),
            "iterable": ("list", "stateful_iter_object"),
        },
    },
    "_FOR_ITER_TUPLE": {
        "pattern": "for {result_var} in {iterable}: pass",
        "placeholders": {
            "result_var": ("new_variable",),
            "iterable": ("tuple", "stateful_iter_object"),
        },
    },
    "_CALL_LIST_APPEND": {
        "pattern": "{target_list}.append({value})",
        "placeholders": {"target_list": ("list",), "value": ("any",)},
    },
    # NOTE: `_YIELD_VALUE` ("yield {value}") is intentionally excluded from the
    # default selectable set: it turns the harness into a generator that the hot
    # loop never actually runs (so it never warms the JIT). Kept in the table for
    # parity; handle it specially before re-enabling.
    "_YIELD_VALUE": {"pattern": "yield {value}", "placeholders": {"value": ("any",)}},
}

#: uops safe to drop into a plain hot-loop harness (see _YIELD_VALUE note above).
SELECTABLE_UOPS: tuple[str, ...] = tuple(k for k in UOP_RECIPES if k != "_YIELD_VALUE")

# Two curated patterns call into a fuzzed target module that lafleur seeds don't have.
_MODULE_COUPLED_PATTERNS = frozenset({"generator_method_call", "evil_deep_calls_correctness"})
#: bug patterns usable as self-contained seeds (module-coupled ones excluded).
SELECTABLE_BUG_PATTERNS: tuple[str, ...] = tuple(
    name for name in BUG_PATTERNS if name not in _MODULE_COUPLED_PATTERNS
)

# Concrete kinds that "any" can expand to.
_ANY_SIMPLE = ("int", "float", "str", "list", "tuple", "dict", "bool", "none")
_ANY_KINDS = _ANY_SIMPLE + tuple(_OBJECT_GENERATORS)


# ==============================================================================
# Simple value generators (trimmed copy of fusil ArgumentGenerator's simple half)
# ==============================================================================
# Each returns a Python *literal/expression string*. Using repr() guarantees a
# valid literal without manual escaping.

_INTERESTING_INTS = (
    0,
    1,
    -1,
    2,
    8,
    255,
    256,
    1024,
    -(2**31),
    2**31 - 1,
    2**31,
    -(2**63),
    2**63 - 1,
    2**63,
    10**18,
)
_TRICKY_STRS = ("", "a", "abc", "\x00", "\U0010ffff", "𝒜", "A" * 64)


def _gen_int(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return repr(rng.choice(_INTERESTING_INTS))
    return repr(rng.randint(-(2**70), 2**70))


def _gen_small_int(rng: random.Random) -> str:
    return repr(rng.randint(-19, 19))


def _gen_float(rng: random.Random) -> str:
    special = ("float('inf')", "float('-inf')", "float('nan')", "0.0", "-0.0", "1e308")
    if rng.random() < 0.3:
        return rng.choice(special)
    return repr(round(rng.uniform(-1e6, 1e6), 4))


def _gen_str(rng: random.Random) -> str:
    if rng.random() < 0.4:
        return repr(rng.choice(_TRICKY_STRS))
    n = rng.randint(0, 12)
    return repr("".join(chr(rng.randint(32, 126)) for _ in range(n)))


def _gen_bytes(rng: random.Random) -> str:
    n = rng.randint(0, 12)
    return repr(bytes(rng.randint(0, 255) for _ in range(n)))


def _gen_bool(rng: random.Random) -> str:
    return rng.choice(("True", "False"))


def _gen_none(_rng: random.Random) -> str:
    return "None"


def _gen_scalar(rng: random.Random) -> str:
    """A hashable scalar literal, for collection elements / dict keys."""
    return rng.choice(
        (_gen_int, _gen_small_int, _gen_float, _gen_str, _gen_bytes, _gen_bool, _gen_none)
    )(rng)


def _gen_list(rng: random.Random) -> str:
    return "[" + ", ".join(_gen_scalar(rng) for _ in range(rng.randint(0, 6))) + "]"


def _gen_tuple(rng: random.Random) -> str:
    items = [_gen_scalar(rng) for _ in range(rng.randint(0, 6))]
    if len(items) == 1:
        return f"({items[0]},)"
    return "(" + ", ".join(items) + ")"


def _gen_set(rng: random.Random) -> str:
    n = rng.randint(0, 6)
    if not n:
        return "set()"
    return "{" + ", ".join(_gen_scalar(rng) for _ in range(n)) + "}"


def _gen_dict(rng: random.Random) -> str:
    n = rng.randint(0, 6)
    return "{" + ", ".join(f"{_gen_scalar(rng)}: {_gen_scalar(rng)}" for _ in range(n)) + "}"


_SIMPLE_GENERATORS: dict[str, Callable[[random.Random], str]] = {
    "int": _gen_int,
    "small_int": _gen_small_int,
    "float": _gen_float,
    "str": _gen_str,
    "bytes": _gen_bytes,
    "bool": _gen_bool,
    "none": _gen_none,
    "list": _gen_list,
    "tuple": _gen_tuple,
    "set": _gen_set,
    "dict": _gen_dict,
}


# ==============================================================================
# Pattern assembly
# ==============================================================================


class _VarPool:
    """Tracks declared operand variables so uops in a chain can reuse them."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self._counter = 0
        self.by_kind: dict[str, list[str]] = {}
        self.setup_lines: list[str] = []

    def _fresh_name(self, base: str) -> str:
        self._counter += 1
        return f"{base}_v{self._counter}"

    def fresh_result(self) -> str:
        """A new assignment/loop target (the 'new_variable' kind)."""
        return self._fresh_name("res")

    def _declare(self, kind: str) -> str:
        """Create a variable of a concrete kind, emitting its setup, and return it."""
        name = self._fresh_name(kind)
        if kind in _SIMPLE_GENERATORS:
            self.setup_lines.append(f"{name} = {_SIMPLE_GENERATORS[kind](self.rng)}")
        elif kind in _OBJECT_GENERATORS:
            self.setup_lines.append(dedent(_OBJECT_GENERATORS[kind](name)).strip())
        else:  # object kind requested but lafleur unavailable -> degrade to a scalar
            self.setup_lines.append(f"{name} = {_gen_scalar(self.rng)}")
        self.by_kind.setdefault(kind, []).append(name)
        return name

    def get(self, kinds: tuple[str, ...]) -> str:
        """Pick (reuse ~70% of the time) or create a variable of an acceptable kind."""
        existing = [name for k in kinds for name in self.by_kind.get(k, [])]
        if existing and self.rng.random() > 0.3:
            return self.rng.choice(existing)
        kind = self.rng.choice([k for k in kinds if k != "new_variable"])
        if kind == "any":
            kind = self.rng.choice(_ANY_KINDS)
        return self._declare(kind)


def _render_recipe(uop: str, recipe: dict, pool: _VarPool) -> str:
    """Build the substitution map and render one recipe's statement text."""
    subs: dict[str, str] = {}
    for pname, kinds in recipe["placeholders"].items():
        if "new_variable" in kinds:
            subs[pname] = pool.fresh_result()
        else:
            subs[pname] = pool.get(kinds)

    if uop == "_DELETE_ATTR":
        # Robust del/set pair so the attribute exists to be deleted (fusil parity).
        target = subs["target_obj"]
        value = pool.get(("int",))
        return dedent(
            f"""
            try:
                del {target}.x
            except AttributeError:
                pass
            {target}.x = {value}
            """
        ).strip()

    return recipe["pattern"].format(**subs)


def generate_uop_targeted_pattern(uop_names: list[str], rng: random.Random) -> tuple[str, str]:
    """
    Build a setup block + harness body that stresses the given uops.

    Returns ``(setup_code, body_code)`` where ``setup_code`` declares the operands
    and ``body_code`` is the sequence of (repeated) uop statements destined for the
    harness function body.
    """
    pool = _VarPool(rng)
    body_blocks: list[str] = []
    for uop in uop_names:
        recipe = UOP_RECIPES.get(uop)
        if not recipe:
            body_blocks.append(f"# ERROR: no recipe for {uop}")
            continue
        rendered = _render_recipe(uop, recipe, pool)
        # Repeat each op a few times so it gets hot / specialized.
        for _ in range(rng.randint(3, 5)):
            body_blocks.append(rendered)

    setup_code = "\n".join(pool.setup_lines)
    body_code = "\n".join(body_blocks) if body_blocks else "pass"
    return setup_code, body_code


def generate_uop_seed(
    rng: random.Random,
    *,
    num_uops: tuple[int, int] = (3, 7),
    loop_iterations: int = 300,
    prefix: str = "f1",
) -> str:
    """Generate a uop-targeted hot-loop seed (the ``core_code``)."""
    uops = rng.choices(SELECTABLE_UOPS, k=rng.randint(*num_uops))
    setup_code, body_code = generate_uop_targeted_pattern(uops, rng)

    harness = f"uop_harness_{prefix}"
    loop_var = f"_loop_{prefix}"
    return (
        f"# JIT seed: targeted uops {uops}\n"
        f"{setup_code}\n\n"
        f"def {harness}():\n"
        f"{indent(body_code, '    ')}\n\n"
        f"for {loop_var} in range({loop_iterations}):\n"
        f"    try:\n"
        f"        {harness}()\n"
        f"    except Exception:\n"
        f"        break\n"
    )


# Tricky "corruption payloads" (flip a variable's type/value mid-loop) and numeric
# interesting values + simple expressions used to fill the bug-pattern templates.
_CORRUPTION_PAYLOADS = (
    "None",
    "b'corrupt'",
    "'corrupt'",
    "3.14",
    "[]",
    "()",
    "object()",
    "float('nan')",
)
_NUMERIC_INTERESTING = (
    "0",
    "1",
    "-1",
    "2",
    "255",
    "2**31",
    "2**63",
    "10**18",
    "1.5",
    "-1.5",
    "float('inf')",
)
_BUG_EXPRESSIONS = ("{v} + 1", "{v} * 2", "{v} - 3", "{v} % 7", "{v} & 255", "{v} ^ 1")


def _fill_bug_pattern(name: str, rng: random.Random, loop_iterations: int, prefix: str) -> dict:
    """Build the placeholder substitution dict for a bug-pattern template.

    Supplies the union of placeholders used by the selectable patterns with
    self-contained values; ``str.format`` ignores any extra keys.
    """
    loop_var = f"i_{prefix}"
    sub: dict[str, object] = {
        "prefix": prefix,
        "loop_var": loop_var,
        "loop_iterations": loop_iterations,
        "trigger_iteration": rng.randint(loop_iterations // 3, max(2, loop_iterations - 2)),
        "corruption_payload": rng.choice(_CORRUPTION_PAYLOADS),
        "expression": rng.choice(_BUG_EXPRESSIONS).format(v=loop_var),
        "inheritance_depth": rng.randint(5, 50),
        "str_d": _gen_str(rng),
        "val_a": rng.choice(_NUMERIC_INTERESTING),
        "val_b": rng.choice(_NUMERIC_INTERESTING),
        "val_c": rng.choice(_NUMERIC_INTERESTING),
    }
    if name == "many_vars_base":
        n = 260
        sub["var_definitions"] = "\n".join(f"var_{i}_{prefix} = {i}" for i in range(n))
        sub["expression"] = f"var_0_{prefix} + var_{n - 1}_{prefix}"
    return sub


def generate_bug_pattern_seed(
    rng: random.Random,
    *,
    name: str | None = None,
    loop_iterations: int = 300,
    prefix: str = "p1",
) -> str:
    """Generate a seed from a curated JIT bug pattern (the ``core_code``).

    The template's ``setup_code`` + ``body_code`` contain ``return`` and their own
    hot loop, so they are wrapped in a harness function that is called once.
    """
    name = name or rng.choice(SELECTABLE_BUG_PATTERNS)
    pattern = BUG_PATTERNS[name]
    sub = _fill_bug_pattern(name, rng, loop_iterations, prefix)

    # Templates have inconsistent base indentation; dedent each before wrapping.
    setup_code = dedent(pattern.get("setup_code", "")).format(**sub)
    body_code = dedent(pattern.get("body_code", "")).format(**sub)
    inner = f"{setup_code}\n{body_code}".strip("\n")

    harness = f"jit_harness_{prefix}"
    return (
        f"# JIT seed: bug pattern {name!r}\n"
        f"def {harness}():\n"
        f"    try:\n"
        f"{indent(inner, '        ')}\n"
        f"    except Exception:\n"
        f"        pass\n\n"
        f"{harness}()\n"
    )


#: relative weights for the default family dispatch in ``generate_jit_seed``.
_FAMILY_WEIGHTS = {"uop": 3, "bug_pattern": 2}


def generate_jit_seed(
    rng: random.Random | None = None,
    *,
    family: str | None = None,
    num_uops: tuple[int, int] = (3, 7),
    loop_iterations: int = 300,
    prefix: str | None = None,
) -> str:
    """
    Generate one JIT seed (the corpus ``core_code``).

    ``family`` selects the seed family (``"uop"`` or ``"bug_pattern"``); when
    ``None`` one is chosen at random (weighted by ``_FAMILY_WEIGHTS``). The result
    assumes lafleur's boilerplate is prepended at run time (it provides ``import
    sys`` and ``fuzzer_rng``). Deterministic for a given ``rng`` seed.
    """
    rng = rng or random.Random()
    if family is None:
        families = list(_FAMILY_WEIGHTS)
        family = rng.choices(families, weights=[_FAMILY_WEIGHTS[f] for f in families])[0]
    if family == "uop":
        return generate_uop_seed(
            rng, num_uops=num_uops, loop_iterations=loop_iterations, prefix=prefix or "f1"
        )
    if family == "bug_pattern":
        return generate_bug_pattern_seed(
            rng, loop_iterations=loop_iterations, prefix=prefix or "p1"
        )
    raise ValueError(f"unknown seed family: {family!r}")


def main() -> None:
    """CLI demo: print one seed (optionally seeded for reproducibility)."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate a JIT corpus seed.")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed for reproducibility")
    parser.add_argument("--loop-iterations", type=int, default=300)
    parser.add_argument(
        "--family", choices=("uop", "bug_pattern"), default=None, help="Force a seed family"
    )
    args = parser.parse_args()
    rng = random.Random(args.seed)
    print(generate_jit_seed(rng, family=args.family, loop_iterations=args.loop_iterations))


if __name__ == "__main__":
    main()
