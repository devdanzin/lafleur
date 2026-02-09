"""
Session Fuzzing Driver for lafleur.

This driver executes multiple Python scripts sequentially in the same process,
allowing JIT state (traces, global watchers, caches) to persist between scripts.
This enables "warm JIT" fuzzing scenarios where one script warms up the JIT and
another script attacks the warmed state.

Usage:
    python -m lafleur.driver script1.py script2.py ...

Output Protocol:
    [DRIVER:START] <script_path>   - Emitted before executing each script
    [DRIVER:STATS] <json>          - Emitted after each script with JIT statistics
    [DRIVER:ERROR] <script_path>   - Emitted when a script raises an exception
"""

from __future__ import annotations

import argparse
import collections.abc
import ctypes
import json
import sys
import traceback
from pathlib import Path
from types import CodeType, FunctionType, MethodType, ModuleType

# Try to import JIT introspection modules
try:
    import _opcode

    HAS_OPCODE = True
except ImportError:
    HAS_OPCODE = False

try:
    import _testinternalcapi  # noqa: F401

    HAS_TESTINTERNALCAPI = True
except ImportError:
    HAS_TESTINTERNALCAPI = False


# Bloom filter constants
BLOOM_SEED = 20221211
PyHASH_MULTIPLIER = 1000003
BLOOM_K = 6
BLOOM_WORDS = 8


class _PyBloomFilter(ctypes.Structure):
    _fields_ = [("bits", ctypes.c_uint32 * BLOOM_WORDS)]


class _PyExecutorLinkListNode(ctypes.Structure):
    # Forward declaration for linked list
    pass


_PyExecutorLinkListNode._fields_ = [
    ("next", ctypes.c_void_p),  # _PyExecutorObject *next
    ("previous", ctypes.c_void_p),  # _PyExecutorObject *previous
]


class PyVMData(ctypes.Structure):
    # Matches _PyVMData in pycore_optimizer.h
    _fields_ = [
        ("opcode", ctypes.c_uint8),
        ("oparg", ctypes.c_uint8),
        ("valid", ctypes.c_uint8),
        ("chain_depth", ctypes.c_uint8),
        ("warm", ctypes.c_bool),
        ("pending_deletion", ctypes.c_uint8),
        ("index", ctypes.c_int32),
        ("bloom", _PyBloomFilter),
        ("links", _PyExecutorLinkListNode),  # 16 bytes (2 pointers)
        ("code", ctypes.c_void_p),  # 8 bytes (PyCodeObject *)
    ]


class PyExecutorObject(ctypes.Structure):
    # Matches _PyExecutorObject in pycore_optimizer.h
    _fields_ = [
        ("ob_refcnt", ctypes.c_ssize_t),
        ("ob_type", ctypes.c_void_p),
        ("ob_size", ctypes.c_ssize_t),
        ("trace", ctypes.c_void_p),
        ("vm_data", PyVMData),  # Nested structure
        ("exit_count", ctypes.c_uint32),
        ("code_size", ctypes.c_uint32),
        ("jit_size", ctypes.c_size_t),
        ("jit_code", ctypes.c_void_p),
    ]


def check_bloom(bloom_filter: _PyBloomFilter, obj_address: int, debug_name: str = "") -> bool:
    """Replicate CPython's bloom_filter_may_contain."""
    uhash = BLOOM_SEED
    addr = obj_address
    for _ in range(8):  # SIZEOF_VOID_P
        uhash ^= addr & 255
        uhash = (uhash * PyHASH_MULTIPLIER) & 0xFFFFFFFFFFFFFFFF  # Keep 64-bit
        addr >>= 8

    # Check K bits
    bits_to_check = []
    for _ in range(BLOOM_K):
        bit_index = uhash & 255
        word_idx = bit_index >> 5
        bit_mask = 1 << (bit_index & 31)
        bits_to_check.append((word_idx, bit_index, bit_mask))
        if not (bloom_filter.bits[word_idx] & bit_mask):
            # if debug_name:
            #     print(f"[DEBUG] {debug_name}: bit {bit_index} (word {word_idx}) NOT SET", flush=True)
            return False
        uhash >>= 8

    if debug_name:
        print(f"[DEBUG] {debug_name}: ALL {BLOOM_K} bits matched! {bits_to_check}", flush=True)
    return True


def scan_watched_variables(
    executor_ptr: ctypes.POINTER(PyExecutorObject),  # type: ignore[valid-type]
    namespace: dict,
) -> list[str]:
    """Identify which globals/builtins are watched by this executor."""
    watched = []
    bloom = executor_ptr.contents.vm_data.bloom
    print(f"[DEBUG] Scanning watched vars. Bloom bits: {list(bloom.bits)[:4]}...", flush=True)

    def is_watched(obj, name: str = "") -> bool:
        if check_bloom(bloom, id(obj), f"{name}_obj"):
            return True
        # Also check code object for functions
        if hasattr(obj, "__code__") and check_bloom(bloom, id(obj.__code__), f"{name}_code"):
            return True
        return False

    try:
        # First, check if the namespace dict itself is watched
        if check_bloom(bloom, id(namespace), "namespace_dict"):
            print("[DEBUG] The globals() dict itself is watched!", flush=True)

        # Check globals
        print(f"[DEBUG] Checking {len(namespace)} globals...", flush=True)
        for name, obj in namespace.items():
            if isinstance(name, str) and is_watched(obj, f"global_{name}"):
                print(f"[DEBUG] Global match: {name}", flush=True)
                watched.append(name)

        # Check builtins from the namespace (can be dict or module)
        builtins_val = namespace.get("__builtins__")
        if builtins_val:
            # Check if the builtins dict/module itself is watched
            if check_bloom(bloom, id(builtins_val), "builtins_dict_or_module"):
                print("[DEBUG] The __builtins__ dict/module itself is watched!", flush=True)

            builtins_dict = builtins_val
            if isinstance(builtins_val, ModuleType):
                builtins_dict = vars(builtins_val)

            if isinstance(builtins_dict, dict):
                print(f"[DEBUG] Checking {len(builtins_dict)} builtins...", flush=True)
                for name, obj in builtins_dict.items():
                    if isinstance(name, str) and is_watched(obj, f"builtin_{name}"):
                        print(f"[DEBUG] Builtin match: {name}", flush=True)
                        watched.append(name)
    except Exception as e:
        print(f"[DEBUG] scan_watched_variables failed: {e}", flush=True)
        pass
    return watched


# Limit integer string conversion to prevent DOS attacks
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(4300)


def walk_code_objects(
    code_obj: CodeType, visited: set | None = None
) -> collections.abc.Generator[CodeType, None, None]:
    """Recursively yield a code object and all its nested code objects."""
    if visited is None:
        visited = set()
    if code_obj in visited:
        return
    visited.add(code_obj)
    yield code_obj
    for const in code_obj.co_consts:
        if isinstance(const, CodeType):
            yield from walk_code_objects(const, visited)


def snapshot_executor_state(namespace: dict) -> dict[tuple[int, int], int]:
    """Record exit_count for all JIT executors currently in the namespace.

    Walks the shared namespace and records the current exit_count for every
    executor, keyed by (id(code_object), bytecode_offset). This snapshot is
    taken BEFORE a script runs so that after execution, get_jit_stats can
    compute delta metrics isolating that script's contribution.

    Args:
        namespace: The shared globals dict from the session.

    Returns:
        A dict mapping (id(code_obj), bytecode_offset) -> exit_count.
        Empty dict if _opcode is unavailable.
    """
    if not HAS_OPCODE:
        return {}

    snapshot: dict[tuple[int, int], int] = {}

    for name, obj in namespace.items():
        if not isinstance(name, str) or name.startswith("_"):
            continue

        root_code_objs: list[CodeType] = []
        if isinstance(obj, FunctionType):
            root_code_objs.append(obj.__code__)
        elif isinstance(obj, MethodType):
            root_code_objs.append(obj.__func__.__code__)
        elif isinstance(obj, type):
            for method in vars(obj).values():
                if isinstance(method, FunctionType):
                    root_code_objs.append(method.__code__)

        for root_code in root_code_objs:
            for code in walk_code_objects(root_code):
                co_code = code.co_code
                for offset in range(0, len(co_code), 2):
                    try:
                        executor = _opcode.get_executor(code, offset)
                        if executor:
                            executor_ptr = ctypes.cast(
                                id(executor), ctypes.POINTER(PyExecutorObject)
                            )
                            snapshot[(id(code), offset)] = executor_ptr.contents.exit_count
                    except (ValueError, TypeError):
                        pass

    return snapshot


def get_jit_stats(namespace: dict, baseline: dict[tuple[int, int], int] | None = None) -> dict:
    """
    Scan a namespace for functions and count active JIT executors.

    Uses _opcode.get_executor() to check if functions have been JIT-compiled.
    Scans all bytecode offsets looking for executors.

    When *baseline* is provided (from snapshot_executor_state), delta metrics
    are computed isolating this script's contribution to executor instability.

    Args:
        namespace: The globals dict from the executed script.
        baseline: Optional snapshot of executor exit counts taken before the
            script ran. When provided, delta metrics are included in the result.

    Returns:
        A dict with executor count and other JIT metrics.
    """
    executor_count = 0
    functions_scanned = 0
    zombie_traces = 0
    valid_traces = 0
    warm_traces = 0
    max_exit_count = 0
    max_chain_depth = 0
    min_code_size = float("inf")
    max_exit_density = 0.0

    # Delta metrics (only computed when baseline is provided)
    delta_max_exit_count = 0
    delta_max_exit_density = 0.0
    delta_total_exits = 0
    delta_new_executors = 0
    delta_new_zombies = 0

    if not HAS_OPCODE:
        return {
            "executors": 0,
            "functions_scanned": 0,
            "jit_available": False,
            "zombie_traces": 0,
            "max_exit_count": 0,
            "max_chain_depth": 0,
            "min_code_size": 0,
            "max_exit_density": 0.0,
        }

    def inspect_executor(executor, code_id: int, offset: int):
        nonlocal zombie_traces, valid_traces, warm_traces
        nonlocal max_exit_count, max_chain_depth, min_code_size, max_exit_density
        nonlocal delta_max_exit_count, delta_max_exit_density, delta_total_exits
        nonlocal delta_new_executors, delta_new_zombies
        try:
            executor_ptr = ctypes.cast(id(executor), ctypes.POINTER(PyExecutorObject))

            # --- Existing absolute metrics (unchanged) ---
            if executor_ptr.contents.vm_data.pending_deletion:
                zombie_traces += 1
            if executor_ptr.contents.vm_data.valid:
                valid_traces += 1
            if executor_ptr.contents.vm_data.warm:
                warm_traces += 1

            exit_count = executor_ptr.contents.exit_count
            chain_depth = executor_ptr.contents.vm_data.chain_depth
            code_size = executor_ptr.contents.code_size

            max_exit_count = max(max_exit_count, exit_count)
            max_chain_depth = max(max_chain_depth, chain_depth)
            if code_size > 0:
                min_code_size = min(min_code_size, code_size)
                density = exit_count / code_size
                max_exit_density = max(max_exit_density, density)

                print(
                    f"[DEBUG] Executor: exit={exit_count} size={code_size} density={density:.2f}",
                    flush=True,
                )

                if density >= 0.0:  # DEBUG: Forced scan for testing
                    print(f"[DEBUG] Triggering scan for density {density:.2f} >= 0.0", flush=True)
                    watched = scan_watched_variables(executor_ptr, namespace)
                    if watched:
                        print(f"[EKG] WATCHED: {', '.join(watched)}", flush=True)

            # --- Delta metrics (only when baseline provided) ---
            if baseline is not None:
                key = (code_id, offset)
                if key in baseline:
                    # Pre-existing executor: compute exit count increase
                    delta_exits = exit_count - baseline[key]
                    if delta_exits > 0:
                        delta_max_exit_count = max(delta_max_exit_count, delta_exits)
                        delta_total_exits += delta_exits
                        if code_size > 0:
                            delta_density = delta_exits / code_size
                            delta_max_exit_density = max(delta_max_exit_density, delta_density)
                else:
                    # New executor created by this script
                    delta_new_executors += 1
                    delta_max_exit_count = max(delta_max_exit_count, exit_count)
                    delta_total_exits += exit_count
                    if code_size > 0:
                        delta_density = exit_count / code_size
                        delta_max_exit_density = max(delta_max_exit_density, delta_density)

                    # Track new zombies (didn't exist before, now pending_deletion)
                    if executor_ptr.contents.vm_data.pending_deletion:
                        delta_new_zombies += 1

        except Exception as e:
            print(f"DEBUG: Introspection failed: {e}")

    for name, obj in namespace.items():
        if not isinstance(name, str) or name.startswith("_"):
            continue

        # Extract root code objects from Functions and Methods
        root_code_objs = []
        if isinstance(obj, FunctionType):
            root_code_objs.append(obj.__code__)
        elif isinstance(obj, MethodType):
            root_code_objs.append(obj.__func__.__code__)
        elif isinstance(obj, type):
            for method in vars(obj).values():
                if isinstance(method, FunctionType):
                    root_code_objs.append(method.__code__)

        # Recursively scan all code objects found
        for root_code in root_code_objs:
            for code in walk_code_objects(root_code):
                functions_scanned += 1
                co_code = code.co_code
                for offset in range(0, len(co_code), 2):
                    try:
                        executor = _opcode.get_executor(code, offset)
                        if executor:
                            executor_count += 1
                            inspect_executor(executor, id(code), offset)
                    except (ValueError, TypeError):
                        pass

    result = {
        "executors": executor_count,
        "functions_scanned": functions_scanned,
        "jit_available": True,
        "zombie_traces": zombie_traces,
        "valid_traces": valid_traces,
        "warm_traces": warm_traces,
        "max_exit_count": max_exit_count,
        "max_chain_depth": max_chain_depth,
        "min_code_size": min_code_size if min_code_size != float("inf") else 0,
        "max_exit_density": max_exit_density,
    }

    if baseline is not None:
        result["delta_max_exit_count"] = delta_max_exit_count
        result["delta_max_exit_density"] = delta_max_exit_density
        result["delta_total_exits"] = delta_total_exits
        result["delta_new_executors"] = delta_new_executors
        result["delta_new_zombies"] = delta_new_zombies

    return result


def run_session(files: list[str]) -> int:
    """
    Execute a sequence of Python scripts in the same process.

    Scripts share a common globals dict, allowing state to leak between them.
    This is intentional - it allows one script to warm up the JIT and another
    to attack that warm state.

    Args:
        files: List of script paths to execute in order.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    # Shared globals dict for all scripts
    # Initialize with builtins and __name__
    shared_globals: dict = {
        "__name__": "__main__",
        "__builtins__": __builtins__,
    }

    errors_occurred = False

    for filepath in files:
        path = Path(filepath)

        # Journal: announce start of script
        print(f"[DRIVER:START] {filepath}", flush=True)

        if not path.exists():
            print(f"[DRIVER:ERROR] {filepath}: File not found", flush=True)
            errors_occurred = True
            continue

        # Save original sys.argv to restore later
        original_argv = sys.argv

        # Snapshot executor state before this script runs
        baseline = snapshot_executor_state(shared_globals)

        try:
            # Read and compile the script
            source = path.read_text(encoding="utf-8")
            code = compile(source, str(path), "exec")

            # Mock runtime environment to mimic standalone execution
            # This ensures `if __name__ == "__main__":` blocks execute
            shared_globals["__name__"] = "__main__"
            shared_globals["__file__"] = str(path.resolve())

            # Mock sys.argv so scripts see their own path, not the driver's
            sys.argv = [str(path)]

            # Execute in shared namespace
            exec(code, shared_globals)

            # Report JIT stats with delta from baseline
            stats = get_jit_stats(shared_globals, baseline=baseline)
            stats["file"] = path.name
            stats["status"] = "success"
            print(f"[DRIVER:STATS] {json.dumps(stats)}", flush=True)

        except SyntaxError as e:
            # Syntax errors are compilation failures
            print(f"[DRIVER:ERROR] {filepath}: SyntaxError: {e}", flush=True)
            stats = {"file": path.name, "status": "syntax_error", "error": str(e)}
            print(f"[DRIVER:STATS] {json.dumps(stats)}", flush=True)
            errors_occurred = True
            # Continue to next script

        except SystemExit as e:
            # Let SystemExit propagate - script requested exit
            print(
                f"[DRIVER:STATS] {json.dumps({'file': path.name, 'status': 'exit', 'code': e.code})}",
                flush=True,
            )
            raise

        except KeyboardInterrupt:
            # User interrupted
            print(
                f"[DRIVER:STATS] {json.dumps({'file': path.name, 'status': 'interrupted'})}",
                flush=True,
            )
            raise

        except Exception as e:
            # Catch all other exceptions and continue
            print(f"[DRIVER:ERROR] {filepath}: {type(e).__name__}: {e}", flush=True)
            traceback.print_exc()
            stats = {
                "file": path.name,
                "status": "error",
                "error": str(e),
                "type": type(e).__name__,
            }
            print(f"[DRIVER:STATS] {json.dumps(stats)}", flush=True)
            errors_occurred = True
            # Continue to next script - don't stop the session

        finally:
            # Always restore original sys.argv so driver logic doesn't break
            sys.argv = original_argv

    return 1 if errors_occurred else 0


def main() -> int:
    """Main entry point for the session fuzzing driver."""
    parser = argparse.ArgumentParser(
        description="Session fuzzing driver - executes scripts in a shared process."
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Python script files to execute in order.",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print additional debug information.",
    )

    args = parser.parse_args()

    if args.verbose:
        print(f"[DRIVER:INFO] JIT introspection available: {HAS_OPCODE}", flush=True)
        print(f"[DRIVER:INFO] Test internal API available: {HAS_TESTINTERNALCAPI}", flush=True)
        print(f"[DRIVER:INFO] Scripts to execute: {args.files}", flush=True)

    return run_session(args.files)


if __name__ == "__main__":
    sys.exit(main())
