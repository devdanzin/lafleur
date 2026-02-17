"""
Generate and save run metadata for lafleur fuzzing sessions.

This module provides functionality to capture comprehensive metadata about
the fuzzing environment, including instance identity, hardware specs,
software configuration, and runtime settings.
"""

import argparse
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import sysconfig
import uuid
from importlib.metadata import distributions
from pathlib import Path

import psutil

# Docker-style name components for generating instance names
ADJECTIVES = [
    "admiring",
    "adoring",
    "agitated",
    "amazing",
    "angry",
    "awesome",
    "backstabbing",
    "bold",
    "boring",
    "clever",
    "cocky",
    "compassionate",
    "condescending",
    "cranky",
    "determined",
    "distracted",
    "dreamy",
    "eager",
    "ecstatic",
    "elastic",
    "elated",
    "elegant",
    "eloquent",
    "epic",
    "fervent",
    "festive",
    "flamboyant",
    "focused",
    "friendly",
    "frosty",
    "funny",
    "gallant",
    "gifted",
    "goofy",
    "gracious",
    "happy",
    "hardcore",
    "heuristic",
    "hopeful",
    "hungry",
    "infallible",
    "inspiring",
    "jolly",
    "jovial",
    "keen",
    "kind",
    "laughing",
    "loving",
    "lucid",
    "magical",
    "modest",
    "musing",
    "mystifying",
    "naughty",
    "nervous",
    "nice",
    "nifty",
    "nostalgic",
    "objective",
    "optimistic",
    "peaceful",
    "pedantic",
    "pensive",
    "practical",
    "priceless",
    "quirky",
    "quizzical",
    "recursing",
    "relaxed",
    "reverent",
    "romantic",
    "sad",
    "serene",
    "sharp",
    "silly",
    "sleepy",
    "stoic",
    "strange",
    "stupefied",
    "suspicious",
    "sweet",
    "tender",
    "thirsty",
    "trusting",
    "unruffled",
    "upbeat",
    "vibrant",
    "vigilant",
    "vigorous",
    "wizardly",
    "wonderful",
    "xenodochial",
    "youthful",
    "zealous",
    "zen",
]

NOUNS = [
    "albattani",
    "archimedes",
    "babbage",
    "bell",
    "blackwell",
    "bohr",
    "brahmagupta",
    "brown",
    "carson",
    "cori",
    "curie",
    "darwin",
    "diffie",
    "dijkstra",
    "einstein",
    "elion",
    "euclid",
    "fermat",
    "feynman",
    "franklin",
    "galileo",
    "gates",
    "goldberg",
    "hawking",
    "heisenberg",
    "hodgkin",
    "hopper",
    "hypatia",
    "johnson",
    "jones",
    "keller",
    "kepler",
    "kilby",
    "kowalevski",
    "lalande",
    "lamarr",
    "leakey",
    "leavitt",
    "lovelace",
    "mayer",
    "mccarthy",
    "mcclintock",
    "meitner",
    "mendel",
    "meninsky",
    "mirzakhani",
    "morse",
    "newton",
    "nightingale",
    "nobel",
    "noether",
    "payne",
    "perlman",
    "pike",
    "poitras",
    "ptolemy",
    "ramanujan",
    "ritchie",
    "rosalind",
    "sagan",
    "shannon",
    "shockley",
    "sinoussi",
    "snyder",
    "stallman",
    "stonebraker",
    "swartz",
    "tereshkova",
    "tesla",
    "thompson",
    "torvalds",
    "turing",
    "villani",
    "wescoff",
    "williams",
    "wing",
    "wozniak",
    "wright",
    "yalow",
    "yonath",
]


def generate_docker_style_name() -> str:
    """Generate a random Docker-style name (adjective-noun)."""
    adjective = random.choice(ADJECTIVES)
    noun = random.choice(NOUNS)
    return f"{adjective}-{noun}"


def get_git_info() -> dict[str, str | bool]:
    """Get git commit hash and dirty status for the lafleur repository."""
    try:
        # Get the directory where this file is located (lafleur package)
        package_dir = Path(__file__).parent.parent

        # Get commit hash
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=package_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        commit_hash = result.stdout.strip() if result.returncode == 0 else "unknown"

        # Check if dirty
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=package_dir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        is_dirty = bool(result.stdout.strip()) if result.returncode == 0 else False

        return {"commit": commit_hash, "dirty": is_dirty}
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {"commit": "unknown", "dirty": False}


def get_installed_packages() -> list[dict[str, str]]:
    """Get list of installed packages with their versions from the current interpreter."""
    packages = []
    for dist in distributions():
        packages.append({"name": dist.metadata["Name"], "version": dist.metadata["Version"]})
    # Sort by name for consistent output
    return sorted(packages, key=lambda p: p["name"].lower())


def get_target_python_info(python_path: str) -> dict:
    """
    Retrieve metadata from the target Python interpreter.

    Runs a subprocess to gather version, executable path, config args, and
    installed packages from the specified Python interpreter rather than
    the current one running lafleur.

    Args:
        python_path: Path to the target Python executable.

    Returns:
        Dictionary with keys: version, executable, config_args, packages, fallback.
        If subprocess fails, returns data from current interpreter with fallback=True.
    """
    # Python script to run in target interpreter
    script = """
import sys
import json
import sysconfig
try:
    from importlib.metadata import distributions
    packages = [{"name": d.metadata["Name"], "version": d.metadata["Version"]} for d in distributions()]
    packages = sorted(packages, key=lambda p: p["name"].lower())
except Exception:
    packages = []

result = {
    "version": sys.version,
    "executable": sys.executable,
    "config_args": sysconfig.get_config_var("CONFIG_ARGS"),
    "packages": packages,
}
print(json.dumps(result))
"""

    try:
        result = subprocess.run(
            [python_path, "-c", script],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode == 0:
            data = json.loads(result.stdout.strip())
            data["fallback"] = False
            return data
        else:
            print(
                f"[!] Warning: Failed to get info from target Python ({python_path}): "
                f"{result.stderr.strip()}",
                file=sys.stderr,
            )
    except subprocess.TimeoutExpired:
        print(
            f"[!] Warning: Timeout getting info from target Python ({python_path})",
            file=sys.stderr,
        )
    except (FileNotFoundError, OSError, json.JSONDecodeError) as e:
        print(
            f"[!] Warning: Error getting info from target Python ({python_path}): {e}",
            file=sys.stderr,
        )

    # Fallback to current interpreter
    print("[!] Warning: Falling back to host interpreter info", file=sys.stderr)
    return {
        "version": sys.version,
        "executable": sys.executable,
        "config_args": sysconfig.get_config_var("CONFIG_ARGS"),
        "packages": get_installed_packages(),
        "fallback": True,
    }


def load_existing_metadata(metadata_path: Path) -> dict | None:
    """
    Load existing metadata file if it exists.

    Args:
        metadata_path: Path to the run_metadata.json file.

    Returns:
        Dictionary with existing metadata, or None if file doesn't exist or is invalid.
    """
    if not metadata_path.exists():
        return None

    try:
        with open(metadata_path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[!] Warning: Could not load existing metadata: {e}", file=sys.stderr)
        return None


def generate_run_metadata(output_dir: Path, args: argparse.Namespace) -> dict:
    """
    Generate comprehensive run metadata and save to a JSON file.

    This function supports identity persistence: if run_metadata.json already exists
    in output_dir, the existing run_id and instance_name are preserved. Dynamic
    fields like hardware stats and configuration are always updated.

    The target Python interpreter (specified via --target-python) is queried for
    its version, config args, and packages, rather than using the host interpreter.

    Args:
        output_dir: Directory where run_metadata.json will be saved.
        args: Parsed command-line arguments.

    Returns:
        Dictionary containing all collected metadata.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = output_dir / "run_metadata.json"

    # Check for existing metadata to preserve identity
    existing_metadata = load_existing_metadata(metadata_path)

    if existing_metadata:
        # Preserve existing identity
        run_id = existing_metadata.get("run_id", str(uuid.uuid4()))
        instance_name = existing_metadata.get("instance_name") or generate_docker_style_name()
        print(
            f"[+] Reusing existing instance identity: {instance_name} ({run_id[:8]}...)",
            file=sys.stderr,
        )
    else:
        # Generate new identity
        run_id = str(uuid.uuid4())
        instance_name = getattr(args, "instance_name", None) or generate_docker_style_name()
        print(
            f"[+] Created new instance identity: {instance_name} ({run_id[:8]}...)",
            file=sys.stderr,
        )

    # Determine target Python (the interpreter being fuzzed)
    target_python = getattr(args, "target_python", None) or sys.executable

    # Get target interpreter info (version, config, packages)
    target_info = get_target_python_info(target_python)

    metadata = {
        # Instance Identity (preserved across runs)
        "run_id": run_id,
        "instance_name": instance_name,
        # Environment (from target Python, not host)
        "environment": {
            "hostname": platform.node(),
            "os": platform.platform(),
            "target_python": target_python,
            "python_version": target_info["version"],
            "python_executable": target_info["executable"],
            "python_config_args": target_info["config_args"],
            "target_info_fallback": target_info.get("fallback", False),
            "lafleur_version": get_git_info(),
            "packages": target_info["packages"],
        },
        # Hardware (always fresh - may change between runs)
        "hardware": {
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "total_ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "disk_free_gb": round(shutil.disk_usage(output_dir).free / (1024**3), 2),
        },
        # Configuration (always fresh - may change between runs)
        "configuration": {
            "execution_mode": "session" if getattr(args, "session_fuzz", False) else "legacy",
            "args": vars(args),
            "env_vars": {
                "PYTHON_JIT": os.environ.get("PYTHON_JIT"),
                "PYTHON_LLTRACE": os.environ.get("PYTHON_LLTRACE"),
                "ASAN_OPTIONS": os.environ.get("ASAN_OPTIONS"),
            },
        },
    }

    # Save metadata to file
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, default=str)

    return metadata
