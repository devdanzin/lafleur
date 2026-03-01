# Seed Generation and Management

A fuzzer is only as good as the corpus it mutates. In the context of the CPython Tier 2 JIT, "fuzzing" is fundamentally different from fuzzing a parser or an image library. You cannot simply feed the interpreter random bytes; you must provide structurally sound, semantically valid Python code that survives long enough to trigger the JIT compiler.

In `lafleur`, these initial Python scripts are called **seeds**. This document explains how `lafleur` generates these seeds using `fusil`, why they are structured the way they are, and how you can hand-roll your own seeds to target specific JIT behaviors.

## The Seed Factory: Fusil

`lafleur` does not generate seeds from scratch. It delegates the creation of the initial corpus to [fusil](https://github.com/devdanzin/fusil), a specialized Python code generator.

When `lafleur` starts a new campaign, it checks the target minimum corpus size. If the corpus is too small, it invokes `fusil` in a loop until the quota is met. `lafleur` uses a very specific, constrained command to ask `fusil` for seeds:

```bash
<python_executable> <fusil_path> \
    --jit-fuzz \
    --jit-target-uop=ALL \
    --source-output-path=<tmp_source> \
    --functions-number=1 \
    --classes-number=0 \
    --methods-number=0 \
    --objects-number=0 \
    --sessions=1 \
    --python=<target_python> \
    --no-jit-external-references \
    --no-threads \
    --no-async \
    --jit-loop-iterations=300 \
    --no-numpy \
    --modules=encodings.ascii \
    --only-generate

```

### How Fusil Generates Seeds

Based on this command (`--jit-target-uop=ALL`), `fusil` generates seeds using two primary strategies:

1. **UOP Targeting (`ASTPatternGenerator`)**: `fusil` maps specific JIT micro-ops (UOPs) to Python AST recipes. If it randomly decides to target `_BINARY_SUBSCR_LIST_INT`, it explicitly generates an AST pattern like `res = target_list[index]`. It uses a stateful, two-pass generation process: first creating the core logic, then prepending variable initializations (e.g., `var_1 = None`) so the code doesn't immediately crash with an `UnboundLocalError`.
2. **Bug Patterns (`BUG_PATTERNS`)**: `fusil` also contains templates of known JIT-stressing scenarios, heavily inspired by CPython's own `test_opt.py`. These templates contain placeholders for variables, expressions, and "corruption payloads." `fusil` takes these templates and injects random but type-aware payloads (e.g., swapping a `dict` for an object with `__slots__`).

*Note: While `fusil` historically contained an AST mutator engine, that engine has been completely ported to and is solely maintained within `lafleur`. `fusil`'s job is strictly to generate the base ASTs; `lafleur` handles all subsequent evolutionary mutations.*

## The Seeding Workflow

The lifecycle of a seed before it enters the evolutionary loop looks like this:

1. **Generation:** `fusil` writes the `.py` files containing the core logic wrapped in a `uop_harness_f1` function and a 300-iteration loop.
2. **Tuning:** By default, the CPython JIT requires over 4,000 iterations of a hot loop to compile a trace. Because `fusil` generates loops with only 300 iterations, `lafleur` uses its `jit_tuner.py` utility to configure the target interpreter with a much lower threshold (typically < 70 iterations).
3. **Baseline Evaluation:** `lafleur` runs these generated seeds, measures their baseline UOP and edge coverage, and adds them to the `CorpusManager`.
4. **Evolution:** Once the minimum corpus size is met, `lafleur`'s Mutation Engine takes over. `fusil` is not invoked again during the campaign unless the operator restarts `lafleur` with a larger minimum corpus size configuration.

## Rolling Your Own Seeds

While `fusil` provides excellent chaotic coverage, you may want to hand-roll a seed to target a newly merged CPython PR or a specific JIT optimization you are researching.

`lafleur` can easily ingest hand-rolled seeds. The only strict requirements are:

1. The core logic must be inside a function named with the prefix `uop_harness_` (e.g., `uop_harness_f1`).
2. There must be a loop that calls this function enough times to trigger the JIT.

### Basic Template

```python
def uop_harness_f1():
    # Setup variables
    a = 10
    b = 20

    # Target logic
    res = a + b
    return res

# Warmup loop (lafleur tunes the JIT threshold, so 300 is plenty)
for i in range(300):
    try:
        uop_harness_f1()
    except Exception as e:
        # Logging exceptions can be helpful for debugging the seed
        # print(f"Exception: {e}")
        pass

```

### Best Practices and Anti-Patterns for Hand-Rolled Seeds

To ensure your hand-rolled seed is effective and doesn't poison the campaign, follow these guidelines:

* **DO catch exceptions:** Always wrap your harness call in a `try/except` block inside the loop. If your code raises an unhandled exception on iteration 0, it will abort before the JIT ever sees it.
* **DO decide on loop continuation:** When catching an exception, decide if it makes sense to `break` the loop (if the exception will just happen repeatedly with no state change) or `pass` (if the code might recover or enter interesting new states after the exception).
* **DO use polymorphism:** The JIT heavily optimizes based on object types. Passing different types (int, float, custom objects) to the same operation inside your loop forces the JIT to insert guards and side-exits, creating rich targets for `lafleur` to mutate later.
* **DO NOT use infinite loops:** `lafleur` employs timeouts, but an infinite loop (`while True: pass`) wastes valuable fuzzing cycles. Always bound your loops.
* **DO NOT trigger Out-Of-Memory (OOM):** Avoid operations that scale exponentially in memory, such as `my_str = "A" * (10**9)` or infinitely appending to a global list. OOM kills the process ungracefully and pollutes the crash logs.
* **DO NOT create busy loops:** Avoid operations that lock the CPU for seconds at a time without executing many Python opcodes (e.g., calculating massive powers like `999999999 ** 999999999`).
* **DO NOT use unseeded randomness:** If your seed relies on random values, initialize the `random` module with a hardcoded seed at the top of the file. `lafleur` relies on determinism during its differential analysis phases.
* **DO NOT use tracing/instrumentation:** Calling `sys.settrace()` or `sys.setprofile()` will disable the Tier 2 JIT entirely in CPython, rendering the seed useless for JIT fuzzing.
* **DO NOT call `sys.exit()`:** This will immediately terminate the fuzzer's worker process and register as an uninteresting failure.
