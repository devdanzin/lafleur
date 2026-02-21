"""
This module provides the CorpusManager and CorpusScheduler classes.

These components are responsible for all high-level management of the fuzzing
corpus, including selecting parent test cases, adding new files, generating
initial seeds, and synchronizing the fuzzer's state with the files on disk.
"""

from collections import defaultdict
import hashlib
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from lafleur.coverage import save_coverage_state, CoverageManager
from lafleur.health import FILE_SIZE_WARNING_THRESHOLD
from lafleur.types import CorpusFileMetadata, MutationInfo, NewCoverageResult
from lafleur.utils import ExecutionResult, FUZZING_ENV

if TYPE_CHECKING:
    from lafleur.health import HealthMonitor

TMP_DIR = Path("tmp_fuzz_run")
CORPUS_DIR = Path("corpus") / "jit_interesting_tests"


class CorpusScheduler:
    """Calculate a "fuzzing score" for each item in the corpus."""

    # --- Scoring weight constants ---
    BASE_SCORE = 100.0
    TIME_PENALTY_WEIGHT = 0.1
    SIZE_PENALTY_WEIGHT = 0.01
    RARITY_BONUS_WEIGHT = 50.0
    FERTILITY_BONUS_WEIGHT = 20.0
    STERILITY_PENALTY_FACTOR = 0.1
    DEPTH_BONUS_WEIGHT = 5.0
    TRACE_LENGTH_BONUS_WEIGHT = 0.2
    SIDE_EXIT_BONUS_WEIGHT = 5.0
    MIN_SCORE = 1.0

    def __init__(self, coverage_state: CoverageManager):
        """Initialize the scheduler with the current coverage state."""
        self.coverage_state = coverage_state
        self._cached_scores: dict[str, float] | None = None

    def invalidate_scores(self) -> None:
        """Mark the score cache as stale.

        Call this whenever the corpus composition or global coverage changes.
        Slow-moving metadata changes (sterility, fertility) do NOT need to
        invalidate — a one-session lag in reflecting these is negligible
        for parent selection quality.
        """
        self._cached_scores = None

    def _calculate_rarity_score(self, file_metadata: CorpusFileMetadata) -> float:
        """
        Calculate a score based on the rarity of the file's coverage.
        Rarer edges (lower global hit count) contribute more to the score.
        """
        rarity_score = 0.0
        baseline_coverage = file_metadata.get("baseline_coverage", {})
        global_coverage = self.coverage_state.state.get("global_coverage", {})

        for harness_data in baseline_coverage.values():
            for edge_tuple in harness_data.get("edges", []):
                # The score for an edge is the inverse of its global hit count.
                # We add 1 to the denominator to avoid division by zero.
                global_hits = global_coverage.get("edges", {}).get(edge_tuple, 0)
                rarity_score += 1.0 / (global_hits + 1)
        return rarity_score

    def calculate_scores(self) -> dict[str, float]:
        """Return cached scores if available, otherwise recalculate."""
        if self._cached_scores is not None:
            return self._cached_scores

        scores = {}
        per_file: dict[str, CorpusFileMetadata] = self.coverage_state.state.get(
            "per_file_coverage", {}
        )
        for filename, metadata in per_file.items():
            score = self.BASE_SCORE

            # --- Heuristic 1: Performance (lower is better) ---
            score -= metadata.get("execution_time_ms", 100) * self.TIME_PENALTY_WEIGHT
            score -= metadata.get("file_size_bytes", 1000) * self.SIZE_PENALTY_WEIGHT

            # --- Heuristic 2: Rarity (higher is better) ---
            rarity = self._calculate_rarity_score(metadata)
            score += rarity * self.RARITY_BONUS_WEIGHT

            # --- Heuristic 3: Fertility (higher is better) ---
            score += metadata.get("total_finds", 0) * self.FERTILITY_BONUS_WEIGHT
            if metadata.get("is_sterile", False):
                score *= self.STERILITY_PENALTY_FACTOR

            # --- Heuristic 4: Depth (higher is better) ---
            score += metadata.get("lineage_depth", 1) * self.DEPTH_BONUS_WEIGHT

            total_trace_length = 0
            total_side_exits = 0
            baseline_coverage = metadata.get("baseline_coverage", {})
            for harness_data in baseline_coverage.values():
                total_trace_length += harness_data.get("trace_length", 0)
                total_side_exits += harness_data.get("side_exits", 0)

            # --- Heuristic 5: Trace quality (higher is better) ---
            score += total_trace_length * self.TRACE_LENGTH_BONUS_WEIGHT
            score += total_side_exits * self.SIDE_EXIT_BONUS_WEIGHT

            scores[filename] = max(self.MIN_SCORE, score)

        self._cached_scores = scores
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

        self.health_monitor: HealthMonitor | None = None

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

        # Invalidate score cache — corpus may have changed
        self.scheduler.invalidate_scores()

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
                        env=FUZZING_ENV,
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
                if isinstance(analysis_data, NewCoverageResult):
                    self.add_new_file(
                        core_code=analysis_data.core_code,
                        baseline_coverage=analysis_data.baseline_coverage,
                        content_hash=analysis_data.content_hash,
                        coverage_hash=analysis_data.coverage_hash,
                        execution_time_ms=analysis_data.execution_time_ms,
                        parent_id=analysis_data.parent_id,
                        mutation_info=analysis_data.mutation_info,
                        mutation_seed=analysis_data.mutation_seed,
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
        per_file: dict[str, CorpusFileMetadata] = self.coverage_state.state.get(
            "per_file_coverage", {}
        )

        # Filter out sterile files entirely — they can never produce interesting
        # children and waste full sessions when selected.
        corpus_files = [
            filename
            for filename, metadata in per_file.items()
            if not metadata.get("is_sterile", False)
        ]

        if not corpus_files:
            # Fall back to all files if everything is sterile (shouldn't happen
            # in practice, but prevents a dead-stop)
            corpus_files = list(per_file.keys())
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
        parent_id: str | None,
        mutation_info: MutationInfo,
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

        core_size = len(core_code.encode("utf-8"))
        if self.health_monitor and core_size > FILE_SIZE_WARNING_THRESHOLD:
            self.health_monitor.record_file_size_warning(new_filename, core_size)

        parent_metadata: CorpusFileMetadata = (
            self.coverage_state.state["per_file_coverage"].get(parent_id, {}) if parent_id else {}  # type: ignore[assignment]  # empty dict is valid total=False TypedDict
        )
        lineage_depth = parent_metadata.get("lineage_depth", 0) + 1
        parent_lineage_profile = parent_metadata.get("lineage_coverage_profile", {})
        new_lineage_profile = build_lineage_func(parent_lineage_profile, baseline_coverage)

        metadata: CorpusFileMetadata = {
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

        # Invalidate score cache — corpus composition has changed
        self.scheduler.invalidate_scores()

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
        subprocess.run(command, capture_output=True, env=FUZZING_ENV)

        # Execute it to get a log (also using the configurable timeout)
        try:
            with open(tmp_log, "w") as log_file:
                t0 = time.monotonic()
                result = subprocess.run(
                    [self.target_python, tmp_source],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=self.execution_timeout,  # Use configurable timeout here too
                    env=FUZZING_ENV,
                )
                execution_time_ms = int((time.monotonic() - t0) * 1000)
        except subprocess.TimeoutExpired:
            print(
                f"[!] Timeout ({self.execution_timeout}s) expired during seed generation",
                file=sys.stderr,
            )
            return

        # Analyze it for coverage
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
        if isinstance(analysis_data, NewCoverageResult):
            self.add_new_file(
                core_code=analysis_data.core_code,
                baseline_coverage=analysis_data.baseline_coverage,
                content_hash=analysis_data.content_hash,
                coverage_hash=analysis_data.coverage_hash,
                execution_time_ms=analysis_data.execution_time_ms,
                parent_id=analysis_data.parent_id,
                mutation_info=analysis_data.mutation_info,
                mutation_seed=analysis_data.mutation_seed,
                build_lineage_func=orchestrator_build_lineage_func,
            )

    def _get_edge_set_from_profile(self, lineage_profile: dict) -> set[int]:
        """A helper to extract the set of all unique edge IDs from a lineage profile."""
        all_edges = set()
        for harness_data in lineage_profile.values():
            all_edges.update(harness_data.get("edges", set()))
        return all_edges

    def _build_edge_index(
        self,
        all_files: dict[str, CorpusFileMetadata],
    ) -> tuple[dict[str, set[int]], dict[int, set[str]]]:
        """Pre-compute edge sets and build an inverted edge-to-files index.

        Args:
            all_files: Mapping of filename to metadata dict.

        Returns:
            A tuple of:
            - file_edges: mapping of filename to its set of edge IDs
            - edge_to_files: inverted index mapping each edge ID to the set
              of filenames that contain it
        """
        file_edges: dict[str, set[int]] = {}
        edge_to_files: dict[int, set[str]] = defaultdict(set)

        for filename, meta in all_files.items():
            edges = self._get_edge_set_from_profile(meta.get("lineage_coverage_profile", {}))
            file_edges[filename] = edges
            for edge in edges:
                edge_to_files[edge].add(filename)

        return file_edges, edge_to_files

    def _find_subsumer_candidates(
        self,
        filename_a: str,
        edges_a: set[int],
        file_edges: dict[str, set[int]],
        edge_to_files: dict[int, set[str]],
        files_to_prune: set[str],
    ) -> set[str]:
        """Use the inverted index to find files that could subsume file A.

        A valid subsumer candidate must:
        1. Contain ALL of A's edges (found via index intersection)
        2. Have at least as many edges as A (superset-or-equal requirement)
        3. Not be A itself
        4. Not already be marked for pruning

        Args:
            filename_a: The candidate file to find subsumers for.
            edges_a: Pre-computed edge set for file A.
            file_edges: Pre-computed edge sets for all files.
            edge_to_files: Inverted index from edge ID to containing files.
            files_to_prune: Files already marked for pruning (excluded).

        Returns:
            Set of filenames that are potential subsumers of A.
        """
        if not edges_a:
            return set()

        # Sort edge file-sets by size (smallest first) for fast intersection.
        # Starting with the rarest edge narrows candidates quickly.
        edge_file_sets = [edge_to_files[e] for e in edges_a if e in edge_to_files]
        if not edge_file_sets:
            return set()

        edge_file_sets.sort(key=len)

        # Intersect progressively — bail early if candidates empty
        candidates = edge_file_sets[0].copy()
        for file_set in edge_file_sets[1:]:
            candidates &= file_set
            if len(candidates) <= 1:
                # At most self remains — no subsumers possible
                break

        # Remove self, already-pruned files, and files without at least as many edges
        candidates.discard(filename_a)
        candidates -= files_to_prune
        candidates = {c for c in candidates if len(file_edges.get(c, set())) >= len(edges_a)}

        return candidates

    def prune_corpus(self, dry_run: bool = True) -> None:
        """Scan the corpus and remove redundant files.

        A file is redundant if its coverage is a proper subset of another,
        more efficient file in the corpus (Pareto dominance on size and speed).

        Uses an inverted edge index for efficient candidate lookup, avoiding
        O(N²) pairwise comparisons.
        """
        print("[*] Starting corpus pruning scan...")
        if dry_run:
            print("[!] Running in DRY RUN mode. No files will be deleted.")

        all_files: dict[str, CorpusFileMetadata] = dict(
            self.coverage_state.state.get("per_file_coverage", {}).items()
        )
        if not all_files:
            print("[+] Corpus is empty. Nothing to prune.")
            return

        # Phase 1 & 2: Pre-compute edge sets and build inverted index
        print(f"[*] Building edge index for {len(all_files)} files...")
        file_edges, edge_to_files = self._build_edge_index(all_files)

        # Sort files by edge count ascending — files with fewer edges are
        # more likely to be subsumed, and checking them first means their
        # subsumers (with more edges) are still available as candidates.
        files_by_edge_count = sorted(
            file_edges.items(),
            key=lambda item: len(item[1]),
        )

        # Phase 3: Targeted subsumption search
        files_to_prune: set[str] = set()
        prune_reasons: dict[str, str] = {}
        total = len(files_by_edge_count)

        for i, (filename_a, edges_a) in enumerate(files_by_edge_count):
            if i > 0 and i % 2000 == 0:
                print(
                    f"  [*] Pruning progress: {i}/{total} files checked, "
                    f"{len(files_to_prune)} prunable so far..."
                )

            if not edges_a or filename_a in files_to_prune:
                continue

            # Find files that contain all of A's edges (superset or equal)
            candidates = self._find_subsumer_candidates(
                filename_a, edges_a, file_edges, edge_to_files, files_to_prune
            )

            meta_a = all_files[filename_a]
            size_a = meta_a.get("file_size_bytes", float("inf"))
            time_a = meta_a.get("execution_time_ms", float("inf"))

            for filename_b in candidates:
                meta_b = all_files[filename_b]
                size_b = meta_b.get("file_size_bytes", float("inf"))
                time_b = meta_b.get("execution_time_ms", float("inf"))

                no_worse = (size_b <= size_a) and (time_b <= time_a)
                strictly_better = (size_b < size_a) or (time_b < time_a)

                if no_worse and strictly_better:
                    files_to_prune.add(filename_a)
                    prune_reasons[filename_a] = f"subsumed by {filename_b}"
                    break

        if not files_to_prune:
            print("[+] No prunable files found in the corpus.")
            return

        print(f"\n[{'!' if dry_run else '+'}] Found {len(files_to_prune)} prunable files:")
        for filename in sorted(files_to_prune):
            print(f"  - {filename}: {prune_reasons[filename]}")

        if dry_run:
            print(f"\n[!] DRY RUN complete. {len(files_to_prune)} files would be pruned.")
            return

        # Actually delete files
        for filename in files_to_prune:
            filepath = CORPUS_DIR / filename
            if filepath.exists():
                filepath.unlink()
            if filename in self.coverage_state.state["per_file_coverage"]:
                del self.coverage_state.state["per_file_coverage"][filename]

        # Track subsumer counts (only when actually pruning)
        subsumer_counts: dict[str, int] = {}
        for reason in prune_reasons.values():
            subsumer = reason.split("subsumed by ", 1)[1] if "subsumed by " in reason else None
            if subsumer:
                subsumer_counts[subsumer] = subsumer_counts.get(subsumer, 0) + 1

        for filename, count in subsumer_counts.items():
            meta: CorpusFileMetadata | None = self.coverage_state.state["per_file_coverage"].get(
                filename
            )
            if meta is not None:
                meta["subsumed_children_count"] = meta.get("subsumed_children_count", 0) + count

        self.scheduler.invalidate_scores()
        save_coverage_state(self.coverage_state.state)
        print(f"[+] Pruned {len(files_to_prune)} files from the corpus.")
