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
import json
import sys
import traceback
from pathlib import Path
from types import FunctionType, MethodType

# Try to import JIT introspection modules
try:
    import _opcode

    HAS_OPCODE = True
except ImportError:
    HAS_OPCODE = False

try:
    import _testinternalcapi

    HAS_TESTINTERNALCAPI = True
except ImportError:
    HAS_TESTINTERNALCAPI = False

# Limit integer string conversion to prevent DOS attacks
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(4300)


def get_jit_stats(namespace: dict) -> dict:
    """
    Scan a namespace for functions and count active JIT executors.

    Uses _opcode.get_executor() to check if functions have been JIT-compiled.
    Scans bytecode offsets 0, 2, 4, ... up to 100 looking for executors.

    Args:
        namespace: The globals dict from the executed script.

    Returns:
        A dict with executor count and other JIT metrics.
    """
    executor_count = 0
    functions_scanned = 0

    if not HAS_OPCODE:
        return {
            "executors": 0,
            "functions_scanned": 0,
            "jit_available": False,
        }

    for name, obj in namespace.items():
        # Skip dunder names and imports
        if name.startswith("_"):
            continue

        code_obj = None
        if isinstance(obj, FunctionType):
            code_obj = obj.__code__
        elif isinstance(obj, MethodType):
            code_obj = obj.__func__.__code__
        elif isinstance(obj, type):
            # Check methods in classes
            for method_name, method in vars(obj).items():
                if isinstance(method, FunctionType):
                    try:
                        # Scan bytecode offsets for executors
                        for offset in range(0, 100, 2):
                            executor = _opcode.get_executor(method.__code__, offset)
                            if executor is not None:
                                executor_count += 1
                                break  # Only count once per function
                    except (ValueError, TypeError):
                        pass
                    functions_scanned += 1
            continue

        if code_obj is not None:
            functions_scanned += 1
            try:
                # Scan bytecode offsets for executors
                for offset in range(0, 100, 2):
                    executor = _opcode.get_executor(code_obj, offset)
                    if executor is not None:
                        executor_count += 1
                        break  # Only count once per function
            except (ValueError, TypeError):
                pass

    return {
        "executors": executor_count,
        "functions_scanned": functions_scanned,
        "jit_available": True,
    }


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

        try:
            # Read and compile the script
            source = path.read_text(encoding="utf-8")
            code = compile(source, str(path), "exec")

            # Execute in shared namespace
            exec(code, shared_globals)

            # Report JIT stats after successful execution
            stats = get_jit_stats(shared_globals)
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
            print(f"[DRIVER:STATS] {json.dumps({'file': path.name, 'status': 'exit', 'code': e.code})}", flush=True)
            raise

        except KeyboardInterrupt:
            # User interrupted
            print(f"[DRIVER:STATS] {json.dumps({'file': path.name, 'status': 'interrupted'})}", flush=True)
            raise

        except Exception as e:
            # Catch all other exceptions and continue
            print(f"[DRIVER:ERROR] {filepath}: {type(e).__name__}: {e}", flush=True)
            traceback.print_exc()
            stats = {"file": path.name, "status": "error", "error": str(e), "type": type(e).__name__}
            print(f"[DRIVER:STATS] {json.dumps(stats)}", flush=True)
            errors_occurred = True
            # Continue to next script - don't stop the session

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
