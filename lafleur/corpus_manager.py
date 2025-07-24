import hashlib
import logging
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from lafleur.coverage import save_coverage_state
from lafleur.utils import ExecutionResult

logger = logging.getLogger(__name__)

TMP_DIR = Path("tmp_fuzz_run")
CORPUS_DIR = Path("corpus") / "jit_interesting_tests"

ENV = os.environ.copy()
ENV.update(
    {
        "PYTHON_LLTRACE": "4",
        "PYTHON_OPT_DEBUG": "4",
        "PYTHON_JIT": "1",
    }
)


class CorpusScheduler:
    """Calculate a "fuzzing score" for each item in the corpus."""

    def __init__(self, coverage_state: dict[str, Any]):
        """Initialize the scheduler with the current coverage state."""
        self.coverage_state = coverage_state
        self.global_coverage = coverage_state.get("global_coverage", {})

    def _calculate_rarity_score(self, file_metadata: dict[str, Any]) -> float:
        """Calculate a score based on the rarity of the file's coverage."""
        rarity_score = 0.0
        baseline_coverage = file_metadata.get("baseline_coverage", {})

        for harness_data in baseline_coverage.values():
            for edge in harness_data.get("edges", []):
                global_hits = self.global_coverage.get("edges", {}).get(edge, 0)
                rarity_score += 1.0 / (global_hits + 1)
        return rarity_score

    def calculate_scores(self) -> dict[str, float]:
        """Iterate through the corpus and calculate a score for each file."""
        scores = {}
        for filename, metadata in self.coverage_state.get("per_file_coverage", {}).items():
            score = 100.0
            score -= metadata.get("execution_time_ms", 100) * 0.1
            score -= metadata.get("file_size_bytes", 1000) * 0.01
            rarity = self._calculate_rarity_score(metadata)
            score += rarity * 50.0
            score += metadata.get("total_finds", 0) * 20.0
            if metadata.get("is_sterile", False):
                score *= 0.1
            score += metadata.get("lineage_depth", 1) * 5.0
            scores[filename] = max(1.0, score)
        return scores


class CorpusManager:
    """Handle all interactions with the corpus on disk and the fuzzer's state."""

    def __init__(
        self,
        coverage_state: dict[str, Any],
        run_stats: dict[str, Any],
        fusil_path: str,
        get_boilerplate_func: Callable[..., str],
    ):
        self.coverage_state = coverage_state
        self.run_stats = run_stats
        self.fusil_path = fusil_path
        self.get_boilerplate = get_boilerplate_func

        self.scheduler = CorpusScheduler(self.coverage_state)
        self.known_hashes: set[str] = set()
        self.run_stats.get("corpus_file_counter", 0)
        self.corpus_file_counter = self.run_stats.get("corpus_file_counter", 0)

        self.fusil_path_is_valid = False
        if self.fusil_path:
            fusil_exe = Path(self.fusil_path)
            if fusil_exe.is_file() and os.access(fusil_exe, os.X_OK):
                self.fusil_path_is_valid = True

        CORPUS_DIR.mkdir(parents=True, exist_ok=True)
        TMP_DIR.mkdir(parents=True, exist_ok=True)

    def synchronize(
        self, orchestrator_analyze_run_func: Callable, orchestrator_build_lineage_func: Callable
    ) -> None:
        logger.info("[*] Synchronizing corpus directory with state file...")
        if not CORPUS_DIR.exists():
            CORPUS_DIR.mkdir(parents=True, exist_ok=True)

        disk_files = {p.name for p in CORPUS_DIR.glob("*.py")}
        state_files = set(self.coverage_state["per_file_coverage"].keys())

        missing_from_disk = state_files - disk_files
        if missing_from_disk:
            logger.warning(
                f"[-] Found {len(missing_from_disk)} files in state but not on disk. Pruning state."
            )
            for filename in missing_from_disk:
                del self.coverage_state["per_file_coverage"][filename]

        files_to_analyze = self._get_files_to_analyze(disk_files, state_files)

        if files_to_analyze:
            self._analyze_and_add_files(
                files_to_analyze, orchestrator_analyze_run_func, orchestrator_build_lineage_func
            )

        current_max_id = 0
        for filename in disk_files:
            try:
                file_id = int(Path(filename).stem)
                if file_id > current_max_id:
                    current_max_id = file_id
            except (ValueError, IndexError):
                continue

        if current_max_id > self.corpus_file_counter:
            logger.info(
                f"[*] Advancing file counter from {self.corpus_file_counter} to {current_max_id} to match corpus."
            )
            self.corpus_file_counter = current_max_id

        self.known_hashes = {
            metadata.get("content_hash")
            for metadata in self.coverage_state.get("per_file_coverage", {}).values()
            if "content_hash" in metadata
        }

        save_coverage_state(self.coverage_state)
        logger.info("[*] Corpus synchronization complete.")

    def _analyze_and_add_files(
        self,
        files_to_analyze: set[str],
        orchestrator_analyze_run_func: Callable,
        orchestrator_build_lineage_func: Callable,
    ) -> None:
        logger.info(f"[*] Analyzing {len(files_to_analyze)} new or modified corpus files...")
        for filename in sorted(list(files_to_analyze)):
            source_path = CORPUS_DIR / filename
            log_path = TMP_DIR / f"sync_{source_path.stem}.log"
            logger.info(f"  -> Analyzing {filename}...")
            try:
                with open(log_path, "w") as log_file:
                    start_time = time.monotonic()
                    result = subprocess.run(
                        ["python3", str(source_path)],
                        stdout=log_file,
                        stderr=subprocess.STDOUT,
                        timeout=10,
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
                )
                if analysis_data["status"] == "NEW_COVERAGE":
                    self.add_new_file(
                        core_code=analysis_data["core_code"],
                        baseline_coverage=analysis_data["baseline_coverage"],
                        content_hash=analysis_data["content_hash"],
                        execution_time_ms=analysis_data["execution_time_ms"],
                        parent_id=analysis_data["parent_id"],
                        mutation_info=analysis_data["mutation_info"],
                        mutation_seed=analysis_data["mutation_seed"],
                        build_lineage_func=orchestrator_build_lineage_func,
                    )
            except Exception as e:
                logger.error(f"  [!] Failed to analyze seed file {filename}: {e}")

    def _get_files_to_analyze(self, disk_files: set[str], state_files: set[str]) -> set[str]:
        files_to_analyze = set()
        for filename in disk_files:
            file_path = CORPUS_DIR / filename
            if filename not in state_files:
                logger.info(f"[+] Discovered new file in corpus: {filename}")
                files_to_analyze.add(filename)
            else:
                try:
                    content = file_path.read_text()
                    current_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
                    if (
                        self.coverage_state["per_file_coverage"][filename].get("content_hash")
                        != current_hash
                    ):
                        logger.info(f"[~] File content has changed for {filename}. Re-analyzing.")
                        del self.coverage_state["per_file_coverage"][filename]
                        files_to_analyze.add(filename)
                except (IOError, KeyError) as e:
                    logger.error(
                        f"[!] Error processing existing file {filename}: {e}. Re-analyzing."
                    )
                    if filename in self.coverage_state["per_file_coverage"]:
                        del self.coverage_state["per_file_coverage"][filename]
                    files_to_analyze.add(filename)
        return files_to_analyze

    def select_parent(self) -> tuple[Path, float] | None:
        corpus_files = list(self.coverage_state.get("per_file_coverage", {}).keys())
        if not corpus_files:
            return None

        logger.info("[+] Calculating corpus scores for parent selection...")
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
        build_lineage_func: Callable,
    ) -> str:
        self.corpus_file_counter += 1
        new_filename = f"{self.corpus_file_counter}.py"
        corpus_filepath = CORPUS_DIR / new_filename
        corpus_filepath.write_text(core_code)
        logger.info(f"[+] Added minimized file to corpus: {new_filename}")

        parent_metadata = (
            self.coverage_state["per_file_coverage"].get(parent_id, {}) if parent_id else {}
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
        }
        self.coverage_state["per_file_coverage"][new_filename] = metadata
        self.known_hashes.add(content_hash)

        save_coverage_state(self.coverage_state)

        return new_filename

    def generate_new_seed(
        self, orchestrator_analyze_run_func: Callable, orchestrator_build_lineage_func: Callable
    ) -> None:
        tmp_source = TMP_DIR / "gen_run.py"
        tmp_log = TMP_DIR / "gen_run.log"

        python_executable = sys.executable
        command = [
            "sudo",
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
            f"--python={python_executable}",
            "--no-jit-external-references",
            "--no-threads",
            "--no-async",
            "--jit-loop-iterations=300",
            "--no-numpy",
            "--modules=encodings.ascii",
        ]
        logger.info(f"[*] Generating new seed with command: {' '.join(command)}")
        subprocess.run(command, capture_output=True)

        with open(tmp_log, "w") as log_file:
            result = subprocess.run(
                ["python3", tmp_source], stdout=log_file, stderr=subprocess.STDOUT, env=ENV
            )

        execution_time_ms = 0
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
        )
        if analysis_data["status"] == "NEW_COVERAGE":
            self.add_new_file(
                core_code=analysis_data["core_code"],
                baseline_coverage=analysis_data["baseline_coverage"],
                content_hash=analysis_data["content_hash"],
                execution_time_ms=analysis_data["execution_time_ms"],
                parent_id=analysis_data["parent_id"],
                mutation_info=analysis_data["mutation_info"],
                mutation_seed=analysis_data["mutation_seed"],
                build_lineage_func=orchestrator_build_lineage_func,
            )
