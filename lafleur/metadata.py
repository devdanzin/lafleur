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
    """Get list of installed packages with their versions."""
    packages = []
    for dist in distributions():
        packages.append({"name": dist.metadata["Name"], "version": dist.metadata["Version"]})
    # Sort by name for consistent output
    return sorted(packages, key=lambda p: p["name"].lower())


def generate_run_metadata(output_dir: Path, args: argparse.Namespace) -> dict:
    """
    Generate comprehensive run metadata and save to a JSON file.

    Args:
        output_dir: Directory where run_metadata.json will be saved.
        args: Parsed command-line arguments.

    Returns:
        Dictionary containing all collected metadata.
    """
    # Get instance name from args or generate one
    instance_name = getattr(args, "instance_name", None) or generate_docker_style_name()

    metadata = {
        # Instance Identity
        "run_id": str(uuid.uuid4()),
        "instance_name": instance_name,
        # Environment
        "environment": {
            "hostname": platform.node(),
            "os": platform.platform(),
            "python_version": sys.version,
            "python_executable": sys.executable,
            "python_config_args": sysconfig.get_config_var("CONFIG_ARGS"),
            "lafleur_version": get_git_info(),
            "packages": get_installed_packages(),
        },
        # Hardware
        "hardware": {
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "total_ram_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "disk_free_gb": round(shutil.disk_usage(output_dir).free / (1024**3), 2),
        },
        # Configuration
        "configuration": {
            "args": vars(args),
            "env_vars": {
                "PYTHON_JIT": os.environ.get("PYTHON_JIT"),
                "PYTHON_LLTRACE": os.environ.get("PYTHON_LLTRACE"),
                "ASAN_OPTIONS": os.environ.get("ASAN_OPTIONS"),
            },
        },
    }

    # Save metadata to file
    output_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = output_dir / "run_metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, default=str)

    return metadata
