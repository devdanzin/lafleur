"""
This module provides the CorpusManager and CorpusScheduler classes.

These components are responsible for all high-level management of the fuzzing
corpus, including selecting parent test cases, adding new files, generating
initial seeds, and synchronizing the fuzzer's state with the files on disk.
"""

import hashlib
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from lafleur.coverage import save_coverage_state, CoverageManager
from lafleur.utils import ExecutionResult

TMP_DIR = Path("tmp_fuzz_run")
CORPUS_DIR = Path("corpus") / "jit_interesting_tests"

ENV = os.environ.copy()
ENV.update(
    {
        "PYTHON_LLTRACE": "2",
        "PYTHON_OPT_DEBUG": "4",
        "PYTHON_JIT": "1",
        "ASAN_OPTIONS": "detect_leaks=0",
    }
)


class CorpusScheduler:
    """Calculate a "fuzzing score" for each item in the corpus."""

    def __init__(self, coverage_state: CoverageManager):
        """Initialize the scheduler with the current coverage state."""
        self.coverage_state = coverage_state
        self.global_coverage = coverage_state.state.get("global_coverage", {})

    def _calculate_rarity_score(self, file_metadata: dict[str, Any]) -> float:
        """
        Calculate a score based on the rarity of the file's coverage.
        Rarer edges (lower global hit count) contribute more to the score.
        """
        rarity_score = 0.0
        baseline_coverage = file_metadata.get("baseline_coverage", {})

        for harness_data in baseline_coverage.values():
            for edge_tuple in harness_data.get("edges", []):
                # The score for an edge is the inverse of its global hit count.
                # We add 1 to the denominator to avoid division by zero.
                global_hits = self.global_coverage.get("edges", {}).get(edge_tuple, 0)
                rarity_score += 1.0 / (global_hits + 1)
        return rarity_score

    def calculate_scores(self) -> dict[str, float]:
        """Iterate through the corpus and calculate a score for each file."""
        scores = {}
        for filename, metadata in self.coverage_state.state.get("per_file_coverage", {}).items():
            # Start with a base score
            score = 100.0

            # --- Heuristic 1: Performance (lower is better) ---
            # Penalize slow and large files.
            score -= metadata.get("execution_time_ms", 100) * 0.1
            score -= metadata.get("file_size_bytes", 1000) * 0.01

            # --- Heuristic 2: Rarity (higher is better) ---
            # Reward files that contain globally rare coverage.
            rarity = self._calculate_rarity_score(metadata)
            score += rarity * 50.0

            # --- Heuristic 3: Fertility (higher is better) ---
            # Reward parents that have produced successful children.
            score += metadata.get("total_finds", 0) * 20.0
            # Heavily penalize sterile parents that haven't found anything new in a long time.
            if metadata.get("is_sterile", False):
                score *= 0.1

            # --- Heuristic 4: Depth (higher is better) ---
            # Slightly reward deeper mutation chains to encourage depth exploration.
            score += metadata.get("lineage_depth", 1) * 5.0

            total_trace_length = 0
            total_side_exits = 0
            baseline_coverage = metadata.get("baseline_coverage", {})
            for harness_data in baseline_coverage.values():
                total_trace_length += harness_data.get("trace_length", 0)
                total_side_exits += harness_data.get("side_exits", 0)

            # Reward files that produce long, optimized traces.
            score += total_trace_length * 0.2

            # Strongly reward files that explore many different side exits.
            score += total_side_exits * 5.0

            # Ensure score is non-negative
            scores[filename] = max(1.0, score)

        return scores


class CorpusManager:
    """
    Handle all interactions with the corpus on disk and the fuzzer's state.
    """

    def __init__(
        self,
        coverage_state: CoverageManager,
        run_stats: dict[str, Any],
        fusil_path: str,
        get_boilerplate_func: Callable[..., str],
        execution_timeout: int = 10,
        target_python: str = sys.executable,
    ):
        """Initialize the CorpusManager."""
        self.coverage_state = coverage_state
        self.run_stats = run_stats
        self.fusil_path = fusil_path
        self.get_boilerplate = get_boilerplate_func
        self.execution_timeout = execution_timeout
        self.target_python = target_python

        self.scheduler = CorpusScheduler(self.coverage_state)
        self.known_hashes: set[tuple[str, str]] = set()
        self.corpus_file_counter = self.run_stats.get("corpus_file_counter", 0)

        self.fusil_path_is_valid = False
        if self.fusil_path:
            fusil_exe = Path(self.fusil_path)
            if fusil_exe.is_file() and os.access(fusil_exe, os.X_OK):
                self.fusil_path_is_valid = True

        CORPUS_DIR.mkdir(parents=True, exist_ok=True)
        TMP_DIR.mkdir(parents=True, exist_ok=True)

        print(f"[*] Using execution timeout of {self.execution_timeout} seconds")

    def synchronize(
        self, orchestrator_analyze_run_func: Callable, orchestrator_build_lineage_func: Callable
    ) -> None:
        """
        Reconcile the state file with the corpus directory on disk.

        Ensure the fuzzer's state is consistent with the actual files in
        the corpus. Handle files that were deleted, added, or modified
        since the last run.
        """
        print("[*] Synchronizing corpus directory with state file...")
        if not CORPUS_DIR.exists():
            CORPUS_DIR.mkdir(parents=True, exist_ok=True)

        disk_files = {p.name for p in CORPUS_DIR.glob("*.py")}
        state_files = set(self.coverage_state.state["per_file_coverage"].keys())

        # 1. Prune state for files that were deleted from disk.
        missing_from_disk = state_files - disk_files
        if missing_from_disk:
            print(
                f"[-] Found {len(missing_from_disk)} files in state but not on disk. Pruning state."
            )
            for filename in missing_from_disk:
                del self.coverage_state.state["per_file_coverage"][filename]

        # 2. Identify new or modified files to be analyzed.
        files_to_analyze = self._get_files_to_analyze(disk_files, state_files)

        # 3. Run analysis on all new/modified files to generate their metadata.
        if files_to_analyze:
            self._analyze_and_add_files(
                files_to_analyze, orchestrator_analyze_run_func, orchestrator_build_lineage_func
            )

        # 4. Synchronize the global file counter to prevent overwrites.
        current_max_id = 0
        for filename in disk_files:
            try:
                file_id = int(Path(filename).stem)
                if file_id > current_max_id:
                    current_max_id = file_id
            except (ValueError, IndexError):
                continue  # Ignore non-integer filenames

        if current_max_id > self.corpus_file_counter:
            print(
                f"[*] Advancing file counter from {self.corpus_file_counter} to {current_max_id} to match corpus."
            )
            self.corpus_file_counter = current_max_id

        # Re-populate known_hashes after synchronization is complete.
        self.known_hashes = {
            (metadata.get("content_hash"), metadata.get("coverage_hash"))
            for metadata in self.coverage_state.state.get("per_file_coverage", {}).values()
            if "content_hash" in metadata and "coverage_hash" in metadata
        }

        # 5. Save the synchronized state.
        save_coverage_state(self.coverage_state.state)
        print("[*] Corpus synchronization complete.")

    def _analyze_and_add_files(
        self,
        files_to_analyze: set[str],
        orchestrator_analyze_run_func: Callable,
        orchestrator_build_lineage_func: Callable,
    ) -> None:
        """Analyze a set of new or modified files and add them to the corpus."""
        print(f"[*] Analyzing {len(files_to_analyze)} new or modified corpus files...")
        for filename in sorted(list(files_to_analyze)):
            source_path = CORPUS_DIR / filename
            log_path = TMP_DIR / f"sync_{source_path.stem}.log"
            print(f"  -> Analyzing {filename} (timeout: {self.execution_timeout}s)...")
            try:
                with open(log_path, "w") as log_file:
                    start_time = time.monotonic()
                    result = subprocess.run(
                        [self.target_python, str(source_path)],
                        stdout=log_file,
                        stderr=subprocess.STDOUT,
                        timeout=self.execution_timeout,  # Use configurable timeout
                        env=ENV,
                    )
                    end_time = time.monotonic()
                execution_time_ms = int((end_time - start_time) * 1000)
                analysis_data = orchestrator_analyze_run_func(
                    exec_result=ExecutionResult(
                        returncode=result.returncode,
                        log_path=log_path,
                        source_path=source_path,
                        execution_time_ms=execution_time_ms,
                    ),
                    parent_lineage_profile={},
                    parent_id=None,
                    mutation_info={"strategy": "seed"},
                    mutation_seed=0,
                    parent_file_size=0,
                    parent_lineage_edge_count=0,
                )
                if analysis_data["status"] == "NEW_COVERAGE":
                    self.add_new_file(
                        core_code=analysis_data["core_code"],
                        baseline_coverage=analysis_data["baseline_coverage"],
                        content_hash=analysis_data["content_hash"],
                        coverage_hash=analysis_data["coverage_hash"],
                        execution_time_ms=analysis_data["execution_time_ms"],
                        parent_id=analysis_data["parent_id"],
                        mutation_info=analysis_data["mutation_info"],
                        mutation_seed=analysis_data["mutation_seed"],
                        build_lineage_func=orchestrator_build_lineage_func,
                        filename_override=filename,
                    )

            except subprocess.TimeoutExpired:
                print(
                    f"  [!] Timeout ({self.execution_timeout}s) expired for seed file {filename}",
                    file=sys.stderr,
                )
            except Exception as e:
                print(f"  [!] Failed to analyze seed file {filename}: {e}", file=sys.stderr)

    def _get_files_to_analyze(self, disk_files: set[str], state_files: set[str]) -> set[str]:
        """Identify new or modified files on disk that require analysis."""
        files_to_analyze = set()
        for filename in disk_files:
            file_path = CORPUS_DIR / filename
            if filename not in state_files:
                print(f"[+] Discovered new file in corpus: {filename}")
                files_to_analyze.add(filename)
            else:
                # File exists in both, verify its hash.
                try:
                    content = file_path.read_text()
                    current_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                    if (
                        self.coverage_state.state["per_file_coverage"][filename].get("content_hash")
                        != current_hash
                    ):
                        print(f"[~] File content has changed for {filename}. Re-analyzing.")
                        del self.coverage_state.state["per_file_coverage"][filename]
                        files_to_analyze.add(filename)
                except (IOError, KeyError) as e:
                    print(f"[!] Error processing existing file {filename}: {e}. Re-analyzing.")
                    if filename in self.coverage_state.state["per_file_coverage"]:
                        del self.coverage_state.state["per_file_coverage"][filename]
                    files_to_analyze.add(filename)
        return files_to_analyze

    def select_parent(self) -> tuple[Path, float] | None:
        """
        Select a test case from the corpus using a weighted random choice.

        Return the path to the selected parent and its calculated score, or
        None if the corpus is empty.
        """
        corpus_files = list(self.coverage_state.state.get("per_file_coverage", {}).keys())
        if not corpus_files:
            return None

        print("[+] Calculating corpus scores for parent selection...")
        scores = self.scheduler.calculate_scores()

        corpus_weights = [scores.get(filename, 1.0) for filename in corpus_files]

        if not any(w > 0 for w in corpus_weights):
            chosen_filename = random.choice(corpus_files)
        else:
            chosen_filename = random.choices(corpus_files, weights=corpus_weights, k=1)[0]

        chosen_score = scores.get(chosen_filename, 1.0)
        return CORPUS_DIR / chosen_filename, chosen_score

    def add_new_file(
        self,
        core_code: str,
        baseline_coverage: dict[str, Any],
        execution_time_ms: int,
        parent_id: int,
        mutation_info: dict[str, Any],
        mutation_seed: int,
        content_hash: str,
        coverage_hash: str,
        build_lineage_func: Callable,
        filename_override: str | None = None,
    ) -> str:
        """
        Add a new file to the corpus and update all related state.

        Return the unique filename assigned to the new corpus file.
        """
        if filename_override:
            # When syncing, use the original filename of the seed file.
            new_filename = filename_override
        else:
            # For new mutations, generate a new filename from the counter.
            self.corpus_file_counter += 1
            new_filename = f"{self.corpus_file_counter}.py"

        corpus_filepath = CORPUS_DIR / new_filename
        corpus_filepath.write_text(core_code)
        print(f"[+] Added minimized file to corpus: {new_filename}")

        parent_metadata = (
            self.coverage_state.state["per_file_coverage"].get(parent_id, {}) if parent_id else {}
        )
        lineage_depth = parent_metadata.get("lineage_depth", 0) + 1
        parent_lineage_profile = parent_metadata.get("lineage_coverage_profile", {})
        new_lineage_profile = build_lineage_func(parent_lineage_profile, baseline_coverage)

        metadata = {
            "baseline_coverage": baseline_coverage,
            "lineage_coverage_profile": new_lineage_profile,
            "parent_id": parent_id,
            "lineage_depth": lineage_depth,
            "discovery_time": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": execution_time_ms,
            "file_size_bytes": len(core_code.encode("utf-8")),
            "mutations_since_last_find": 0,
            "total_finds": 0,
            "is_sterile": False,
            "discovery_mutation": mutation_info,
            "mutation_seed": mutation_seed,
            "content_hash": content_hash,
            "coverage_hash": coverage_hash,
        }
        self.coverage_state.state["per_file_coverage"][new_filename] = metadata
        self.known_hashes.add((content_hash, coverage_hash))

        # The manager is now responsible for saving the state it modifies.
        save_coverage_state(self.coverage_state.state)

        return new_filename

    def generate_new_seed(
        self, orchestrator_analyze_run_func: Callable, orchestrator_build_lineage_func: Callable
    ) -> None:
        """Run a single generative session to create a new seed file."""
        tmp_source = TMP_DIR / "gen_run.py"
        tmp_log = TMP_DIR / "gen_run.log"

        python_executable = sys.executable
        # Use fusil to generate a new file
        command = [
            python_executable,
            self.fusil_path,
            "--jit-fuzz",
            "--jit-target-uop=ALL",
            f"--source-output-path={tmp_source}",
            "--classes-number=0",
            "--functions-number=1",
            "--methods-number=0",
            "--objects-number=0",
            "--sessions=1",
            f"--python={self.target_python}",
            "--no-jit-external-references",
            "--no-threads",
            "--no-async",
            "--jit-loop-iterations=300",
            "--no-numpy",
            "--modules=encodings.ascii",
            "--only-generate",
            # "--keep-sessions",
        ]
        print(f"[*] Generating new seed with command: {' '.join(command)}")
        subprocess.run(command, capture_output=True, env=ENV)

        # Execute it to get a log (also using the configurable timeout)
        try:
            with open(tmp_log, "w") as log_file:
                result = subprocess.run(
                    [self.target_python, tmp_source],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=self.execution_timeout,  # Use configurable timeout here too
                    env=ENV,
                )
        except subprocess.TimeoutExpired:
            print(
                f"[!] Timeout ({self.execution_timeout}s) expired during seed generation",
                file=sys.stderr,
            )
            return

        # Analyze it for coverage
        execution_time_ms = 0  # This is a placeholder, as we don't time this run
        analysis_data = orchestrator_analyze_run_func(
            exec_result=ExecutionResult(
                returncode=result.returncode,
                log_path=tmp_log,
                source_path=tmp_source,
                execution_time_ms=execution_time_ms,
            ),
            parent_lineage_profile={},
            parent_id=None,
            mutation_info={"strategy": "generative_seed"},
            mutation_seed=0,
            parent_file_size=0,
            parent_lineage_edge_count=0,
        )
        if analysis_data["status"] == "NEW_COVERAGE":
            self.add_new_file(
                core_code=analysis_data["core_code"],
                baseline_coverage=analysis_data["baseline_coverage"],
                content_hash=analysis_data["content_hash"],
                coverage_hash=analysis_data["coverage_hash"],
                execution_time_ms=analysis_data["execution_time_ms"],
                parent_id=analysis_data["parent_id"],
                mutation_info=analysis_data["mutation_info"],
                mutation_seed=analysis_data["mutation_seed"],
                build_lineage_func=orchestrator_build_lineage_func,
            )

    def _get_edge_set_from_profile(self, lineage_profile: dict) -> set[int]:
        """A helper to extract the set of all unique edge IDs from a lineage profile."""
        all_edges = set()
        for harness_data in lineage_profile.values():
            all_edges.update(harness_data.get("edges", set()))
        return all_edges

    def _is_subsumed_by(self, file_a_meta: dict, file_b_meta: dict) -> bool:
        """
        Determine if file A is "subsumed" by file B.

        File A is subsumed if its coverage is a proper subset of B's,
        and B is more "efficient" (smaller or faster).
        """
        # 1. Get the full set of unique edges for each file's lineage.
        edges_a = self._get_edge_set_from_profile(file_a_meta.get("lineage_coverage_profile", {}))
        edges_b = self._get_edge_set_from_profile(file_b_meta.get("lineage_coverage_profile", {}))

        # We can't prune a file if its edge set is empty (e.g., a fresh seed).
        if not edges_a:
            return False

        # 2. Check for Coverage Subsumption.
        # Edges of A must be a proper (strict) subset of B's edges.
        # This means B covers everything A does, plus at least one more thing.
        if not edges_a.issubset(edges_b) or edges_a == edges_b:
            return False

        # 3. Check for Efficiency.
        # File B must be better than file A in at least one metric (size or speed),
        # without being worse in the other.
        size_a = file_a_meta.get("file_size_bytes", float("inf"))
        size_b = file_b_meta.get("file_size_bytes", float("inf"))

        time_a = file_a_meta.get("execution_time_ms", float("inf"))
        time_b = file_b_meta.get("execution_time_ms", float("inf"))

        if size_b <= size_a and time_b <= time_a:
            # If B is smaller/faster in both, it's definitely better.
            return True

        # We could add more nuanced heuristics here, but this is a solid start.
        return False

    def prune_corpus(self, dry_run: bool = True):
        """
        Scan the corpus and remove redundant files.
        A file is redundant if its coverage is a proper subset of another,
        more efficient file in the corpus.
        """
        print("[*] Starting corpus pruning scan...")
        if dry_run:
            print("[!] Running in DRY RUN mode. No files will be deleted.")

        all_files = list(self.coverage_state.state.get("per_file_coverage", {}).items())
        files_to_prune = set()
        prune_reasons = {}

        # Use a nested loop to compare every file against every other file
        for filename_a, meta_a in all_files:
            if filename_a in files_to_prune:
                continue

            for filename_b, meta_b in all_files:
                if filename_a == filename_b or filename_b in files_to_prune:
                    continue

                if self._is_subsumed_by(meta_a, meta_b):
                    files_to_prune.add(filename_a)
                    prune_reasons[filename_a] = f"subsumed by {filename_b}"

                    meta_b.setdefault("subsumed_children_count", 0)
                    meta_b["subsumed_children_count"] += 1

                    # Once a file is marked for pruning, we break the inner loop
                    # and move to the next candidate file.
                    break

        if not files_to_prune:
            print("[+] No prunable files found in the corpus.")
            return

        print(f"\n[*] Found {len(files_to_prune)} files to prune:")
        for filename in sorted(list(files_to_prune)):
            print(f"  - {filename} ({prune_reasons[filename]})")

        if not dry_run:
            print("\n[*] Deleting files and updating state...")
            for filename in files_to_prune:
                (CORPUS_DIR / filename).unlink()
                del self.coverage_state.state["per_file_coverage"][filename]
            save_coverage_state(self.coverage_state.state)
            print("[+] Corpus pruning complete.")
