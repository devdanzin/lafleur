# Lafleur Glossary

A comprehensive reference to the terminology, concepts, and jargon used throughout the lafleur project. Terms are grouped alphabetically. Where a term has a nickname used in code comments or developer conversation, it appears in parentheses.

See also: [Architecture Overview](./01_architecture_overview.md) for how these pieces fit together, and [The Evolutionary Loop](./02_the_evolutionary_loop.md) for a step-by-step walkthrough of a fuzzing session.

-----

## A

### Absolute Vitals
[JIT Executor](#jit-executor) metrics measured against a zero baseline — the raw values reported by the [EKG](#ekg-jit-electrocardiogram) without subtracting the parent/polluter contribution. Contrast with [Delta Vitals](#delta-vitals). The absolute path is used as a fallback when delta metrics aren't available (non-session mode or older corpus data).

### Adaptive Strategy Selection
The mechanism by which the [MutationController](#mutationcontroller) chooses which mutation strategy ([Deterministic](#deterministic-strategy), [Havoc](#havoc-strategy), [Spam](#spam-strategy), [Sniper](#sniper-strategy), [Helper+Sniper](#helpersniper-strategy)) to apply. Strategy weights are determined by the [MutatorScoreTracker](#mutatorscoretracker) using [Epsilon-Greedy](#epsilon-greedy) selection, so strategies that have recently produced [Corpus](#corpus) additions are favored while all strategies retain a minimum probability of being chosen.

### Alchemist, The
Nickname for the [MutationController](#mutationcontroller) class (`mutation_controller.py`). See [MutationController](#mutationcontroller).

### Artifact
A saved file produced when something noteworthy happens during execution — crashes, timeouts, [Divergences](#divergence), or performance regressions. Managed by the [ArtifactManager](#artifactmanager). Artifacts include the child script, execution log, and (in session mode) the full [Session Bundle](#session-bundle).

### ArtifactManager
The component (`artifacts.py`) responsible for saving crashes, timeouts, [Divergences](#divergence), and regressions to disk with accompanying metadata, compressed logs, and [Session Bundles](#session-bundle).

### AST (Abstract Syntax Tree)
A tree representation of the syntactic structure of Python code. Lafleur operates on ASTs rather than raw text to ensure syntactically valid [Mutations](#mutation). Python's `ast` module provides the parsing (`ast.parse`) and code generation (`ast.unparse`) infrastructure. All mutators are subclasses of [NodeTransformer](#nodetransformer).

### ASTMutator
The mutation engine class (`mutators/engine.py`) that maintains the pool of 76+ [Transformer](#transformer) classes and orchestrates applying them to an [AST](#ast-abstract-syntax-tree). It handles weighted random selection, seed-controlled determinism, and error recovery when individual transformers fail.

### Attack Script
In [Session Fuzzing](#session-fuzzing), the mutated [Child](#child--mutant) script that runs last in the [Session Bundle](#session-bundle). It "attacks" the JIT state established by the preceding [Warmup](#warmup) and [Polluter](#polluter) scripts.

## B

### Bloom Filter
A probabilistic data structure used internally by CPython's JIT optimizer. Each [JIT Executor](#jit-executor) contains a Bloom filter (`vm_data.bloom`) recording which globals and builtins the optimizer assumed were stable when compiling the [Trace](#trace). Lafleur's [Driver](#driver) probes these filters to discover [Watched Dependencies](#watched-dependencies).

### Bloom Filter Probing
The technique by which the [Driver](#driver) reimplements CPython's `bloom_filter_may_contain` algorithm in pure Python and tests each global and builtin in the namespace against every executor's [Bloom Filter](#bloom-filter). Produces a [Watched Dependencies](#watched-dependencies) list that feeds into the [Sniper](#sniper-strategy) strategy. This is lafleur's most distinctive architectural feature: closing the introspection → mutation feedback loop.

### Boilerplate
The static portion of a [Test Case](#test-case) that handles imports, setup code, and the [Harness](#harness) invocation loop. Delimited by `# FUSIL_BOILERPLATE_START` and `# FUSIL_BOILERPLATE_END` markers. The [MutationController](#mutationcontroller) extracts and caches the boilerplate once, then reattaches it to every [Child](#child--mutant) script to avoid mutating infrastructure code.

### Bounded Run
A fuzzing run with explicit limits on sessions and/or mutations, enabled via diagnostic mode options (`--max-sessions`, `--max-mutations-per-session`). Useful for smoke tests, CI integration, and mutator development.

### Branching Factor
A structural metric computed by [`lafleur-lineage`](#lafleur-lineage). The number of direct [Children](#child--mutant) of an internal [Corpus](#corpus) node. Reported as mean and max across all internal nodes in a subgraph. High branching indicates a [Parent](#parent) that spawned many successful mutations in parallel.

### Breadth-First
The default session strategy where the [Orchestrator](#lafleurorchestrator) selects a different [Parent](#parent) from the [Corpus](#corpus) for each session, exploring the coverage landscape broadly. Contrast with [Deepening / Depth-First](#deepening--depth-first).

## C

### Campaign
A coordinated fuzzing effort across multiple [Instances](#instance), typically running on many cores. The [`lafleur-campaign`](#lafleur-campaign) tool aggregates results from all instances into a fleet-wide dashboard with deduplicated crash counts, coverage totals, and strategy effectiveness rankings.

### Chain Depth
The number of linked [JIT Executor](#jit-executor) objects in a trace chain. Deep chains (depth > 3) earn a [Hyper-Extension](#hyper-extension) bonus in the [InterestingnessScorer](#interestingnessscorer). Deep chains indicate that the JIT has built complex multi-stage optimizations that are more fragile and interesting to stress-test.

### Child / Mutant
A [Test Case](#test-case) created by applying [Mutations](#mutation) to a [Parent](#parent) test case. If the child discovers new coverage or triggers interesting JIT behavior, it is added to the [Corpus](#corpus) and may itself become a parent in future sessions.

### Code Size
The compiled machine code size (in bytes) of a [JIT Executor](#jit-executor). Very small code sizes (< 5 bytes) earn a [Stub](#stub) bonus, as they often indicate degenerate compilation where the JIT produced a nearly empty [Trace](#trace).

### Cold JIT
A JIT state with no preexisting traces or type feedback. Achieved in [Solo Sessions](#solo-session) where only the [Child](#child--mutant) script runs. Contrast with [Warm JIT](#warm-jit) and [Hot JIT](#hot-jit).

### Content Hash
A SHA-256 hash of a [Child](#child--mutant)'s [Core Code](#core-code) (boilerplate stripped). Used in [Deduplication](#deduplication) to catch syntactically identical mutations. A child is only considered duplicate if both its content hash and [Coverage Hash](#coverage-hash) match an existing [Corpus](#corpus) entry.

### Core Code
The dynamic portion of a [Test Case](#test-case) — everything after the [Boilerplate](#boilerplate) end marker. This is the code that gets mutated. Extracted by `MutationController._get_core_code()`.

### Corpus
The collection of interesting [Test Cases](#test-case) that have discovered unique coverage or triggered notable JIT behavior. Stored on disk in `corpus/jit_interesting_tests/`. Each corpus file has associated metadata in `coverage_state.pkl` tracking its [Coverage Profile](#coverage-profile), [Lineage](#lineage), execution time, and JIT vitals.

### CorpusManager
The component (`corpus_manager.py`) that handles all interactions with the on-disk [Corpus](#corpus) — selecting [Parents](#parent) via the [CorpusScheduler](#corpusscheduler), adding new files, generating [Seeds](#seed) via [Fusil](#fusil), and synchronizing state at startup.

### CorpusScheduler
The scoring engine (`corpus_manager.py`) that calculates a [Fuzzing Score](#fuzzing-score) for every [Corpus](#corpus) file based on performance, [Rarity](#rarity), [Fertility](#fertile--fertility), [Lineage Depth](#lineage-depth), and [Structural Metrics](#structural-metrics). These scores drive weighted [Parent](#parent) selection.

### Coverage Edge
See [Stateful UOP Edge](#stateful-uop-edge).

### Coverage Hash
A SHA-256 hash of a [Child](#child--mutant)'s edge set. Used in [Deduplication](#deduplication) to catch mutations that look different syntactically but produce identical [Coverage Profiles](#coverage-profile). See also [Content Hash](#content-hash).

### Coverage Profile
A dictionary mapping each [Harness](#harness) ID to its coverage data: [UOPs](#uop-micro-operation), edges, [Rare Events](#rare-event), trace length, and [Side Exits](#side-exit). Produced by the [CoverageParser](#coverageparser) from JIT trace logs.

### CoverageManager
The component (`coverage.py`) that maintains the [Global Coverage](#global-coverage) state, assigns integer IDs to coverage items (see [Integer ID Compression](#integer-id-compression)), and provides the coverage comparison logic for the interestingness check.

### CoverageParser
The log parser (`coverage.py`) that extracts coverage signals from CPython's verbose JIT trace output. Uses regex patterns and a state machine to attribute edges to the correct JIT operational state (TRACING, OPTIMIZED, EXECUTING).

### Crash Attribution
When a crash occurs, the [MutatorScoreTracker](#mutatorscoretracker) rewards not just the strategy and [Transformers](#transformer) of the crashing [Mutation](#mutation) but also those of its ancestors (with a smaller multiplier). This incentivizes exploration of [Lineages](#lineage) that are "crash-adjacent."

### Crash Fingerprint
A normalized signature computed from crash output (signal, error type, stack frames) that allows deduplication across [Instances](#instance) and time. Managed by the `CrashFingerprinter` class in `analysis.py`.

### Crash Registry
A SQLite database (`registry.py`) that tracks [Crash Fingerprints](#crash-fingerprint), sighting counts, triage status, and links to reported CPython issues. Enables [Regression](#regression) detection across [Campaign](#campaign) runs.

## D

### Decay
The gradual reduction of mutator scores over time. Every `DECAY_INTERVAL` (50) attempts, all scores in the [MutatorScoreTracker](#mutatorscoretracker) are multiplied by a decay factor (default 0.995), favoring recently successful strategies over historically successful ones. Decay is attempt-based, not success-based.

### Deepening / Depth-First
A session mode (triggered with configurable probability, default 20%) where the [Orchestrator](#lafleurorchestrator) aggressively mutates a single promising [Lineage](#lineage). If a [Mutation](#mutation) discovers new coverage, the [Child](#child--mutant) immediately becomes the new [Parent](#parent) for the next mutation, creating deep lineages rapidly. Abandoned after `DEEPENING_STERILITY_LIMIT` (30) consecutive [Sterile](#sterile--sterility) mutations. Contrast with [Breadth-First](#breadth-first).

### Deduplication
The process of checking whether a [Child](#child--mutant) that passes the interestingness threshold is truly novel. Uses both [Content Hash](#content-hash) and [Coverage Hash](#coverage-hash). A child is only duplicate if the tuple `(content_hash, coverage_hash)` has been seen before — this allows the fuzzer to save multiple copies of syntactically identical code if they produce different coverage due to non-determinism.

### Delta Vitals
[JIT Executor](#jit-executor) metrics that isolate the [Child](#child--mutant)'s effect from inherited state by subtracting a pre-execution baseline snapshot. Available in [Session Fuzzing](#session-fuzzing) mode. Includes `delta_max_exit_density`, `delta_total_exits`, `delta_new_executors`, and `delta_new_zombies`. Preferred over [Absolute Vitals](#absolute-vitals) for scoring because they aren't inflated by [Polluter](#polluter)/[Warmup](#warmup) activity.

### Density Penalty
A scoring adjustment in the [InterestingnessScorer](#interestingnessscorer) that penalizes [Children](#child--mutant) whose file size grew significantly relative to their [Parent](#parent) but only produced [Relative Discoveries](#relative-discovery). Prevents [Corpus](#corpus) bloat from large, marginally interesting mutations.

### Deoptimization
The process by which the JIT abandons an optimized [Trace](#trace) and falls back to the interpreter. Triggered when a [Guard](#guard) fails — for example, a type assumption is violated or a [Watched Dependency](#watched-dependencies) changes. Many lafleur [Mutators](#transformer) specifically target deoptimization through techniques like type shadowing, global invalidation, and [Bloom Filter](#bloom-filter) saturation.

### Deterministic (Strategy)
A mutation strategy that applies 1–3 seed-controlled random [Transformers](#transformer) from the full pool. The lightest strategy, producing minimal changes to the [Parent](#parent). Useful for incremental exploration near known-interesting code.

### Differential Testing
An execution mode (`--differential-testing`) that runs each [Child](#child--mutant) twice — once with JIT enabled and once without — and compares exit codes, stdout, and stderr. Mismatches indicate [Divergences](#divergence): correctness bugs where the JIT produces different results than the interpreter.

### Divergence
A correctness bug where JIT-compiled code produces different behavior than interpreted code. Detected by [Differential Testing](#differential-testing). Categories include exit code mismatch, stdout mismatch, and stderr mismatch. Divergences are saved as [Artifacts](#artifact).

### Driver
The execution engine (`driver.py`) that runs inside the subprocess. Executes scripts sequentially in a shared process (in [Session Fuzzing](#session-fuzzing) mode), performs [EKG](#ekg-jit-electrocardiogram) introspection, probes [Bloom Filters](#bloom-filter), and emits structured `[DRIVER:STATS]` lines that the [ScoringManager](#scoringmanager) parses.

### Dry Run
A diagnostic mode (`--dry-run`) that generates mutated [Children](#child--mutant) and writes them to disk but skips execution entirely. Useful for inspecting what mutations produce without running subprocesses. Implies `--keep-children`.

### Dynamic Density Clamping
A scoring adjustment applied before saving JIT vitals to [Corpus](#corpus) metadata. If a [Child](#child--mutant)'s [Exit Density](#exit-density) spikes far above its [Parent](#parent)'s, the saved value is clamped to `min(parent_density × 5, child_density)`. This prevents a single extreme outlier from creating an impossible target for the next generation. See also [Tachycardia Decay](#tachycardia-decay).

### Dynamic Mutations
The mechanism by which the number of mutations per [Session](#session) scales with the [Parent](#parent)'s [Fuzzing Score](#fuzzing-score). Higher-scoring parents receive more mutation attempts. Controlled by `_calculate_mutations()` in the [MutationController](#mutationcontroller).

## E

### EKG (JIT Electrocardiogram)
The runtime introspection system in the [Driver](#driver) that uses Python's `ctypes` to inspect CPython's internal `_PyExecutorObject` C structs. Extracts vital signs including executor count, [Zombie Traces](#zombie-trace), trace validity, [Exit Counts](#exit-count), [Chain Depth](#chain-depth), and [Code Size](#code-size). Named by analogy with a medical EKG monitoring heart activity.

### EmptyBodySanitizer
A utility [Transformer](#transformer) (`mutators/utils.py`) that runs as a final pass after all mutations to ensure no control flow statements (`if`, `for`, `while`, `def`, `class`, etc.) have empty bodies, which would cause `IndentationError` at runtime.

### Epsilon-Greedy
The exploration/exploitation strategy used by the [MutatorScoreTracker](#mutatorscoretracker). With probability epsilon (default 0.1), uniform weights are returned for exploration (all strategies equally likely). Otherwise, learned weights are used for exploitation (favoring historically successful strategies).

### Evolutionary Fuzzing
A fuzzing approach where [Test Cases](#test-case) evolve over time through [Mutation](#mutation) and selection based on fitness. Lafleur implements a [Hill Climbing](#hill-climbing) search where the fitness signal is coverage novelty and JIT instability. Successful mutations survive (are added to the [Corpus](#corpus)) and become [Parents](#parent) for future mutations.

### ExecutionManager
The component (`execution.py`) that handles running child processes. Manages the three execution stages ([Differential Testing](#differential-testing), [Timing Fuzzing](#timing-fuzzing), coverage gathering), assembles [Session Bundles](#session-bundle), handles timeouts and crashes, and builds the subprocess environment.

### Exit Count
The number of times execution has exited a JIT [Trace](#trace) through a [Side Exit](#side-exit). High exit counts indicate the JIT's optimistic assumptions are frequently violated. See also [Exit Density](#exit-density).

### Exit Density
A normalized metric: `exit_count / code_size`. Measures JIT instability per instruction, avoiding bias towards large traces that naturally accumulate more exits. High exit density triggers the [Tachycardia](#tachycardia) bonus.

## F

### Feedback Loop
The core cycle of lafleur: select [Parent](#parent) → [Mutate](#mutation) → execute → analyze coverage → reward successful strategies → repeat. Each iteration uses the results of previous iterations to make smarter decisions about what to mutate and how.

### Fertile / Fertility
A [Corpus](#corpus) file that has historically produced many interesting [Children](#child--mutant) (new coverage discoveries). Fertility earns a scoring bonus in the [CorpusScheduler](#corpusscheduler), making the file more likely to be selected as a [Parent](#parent). Contrast with [Sterile](#sterile--sterility).

### FlowControl
An enum (`orchestrator.py`) used by the analysis pipeline to signal what should happen after analyzing a mutation result: `NONE` (continue), `BREAK` (major find, stop this session), or `CONTINUE` (crash found, continue to next mutation).

### Fusil
An external generative fuzzer used by lafleur to produce initial [Seed](#seed) files. Lafleur calls fusil with JIT-specific options to generate [Test Cases](#test-case) with hot loops suitable for triggering JIT compilation.

### FuzzerSetupNormalizer
A utility [Transformer](#transformer) (`mutators/utils.py`) that removes accumulated fuzzer-injected setup code (GC tuning, RNG initialization) and normalizes `random()` calls to use the seeded `fuzzer_rng` instance. Runs before mutation to prevent setup code from accumulating across generations.

### Fuzzing Score
A floating-point number assigned to each [Corpus](#corpus) file by the [CorpusScheduler](#corpusscheduler). Combines heuristics for performance, [Rarity](#rarity), [Fertility](#fertile--fertility), [Lineage Depth](#lineage-depth), and [Structural Metrics](#structural-metrics). Higher scores increase the probability of being selected as a [Parent](#parent). Minimum score is 1.0 to ensure no file is completely ignored.

## G

### Global Coverage
The union of all coverage ever seen across the entire [Corpus](#corpus). Maintained in `coverage_state.pkl`. A [Child](#child--mutant) that discovers coverage not in the global map has made a [Global Discovery](#global-discovery) — the most valuable type of find.

### Global Discovery
A coverage item (edge, [UOP](#uop-micro-operation), or [Rare Event](#rare-event)) never before seen by any [Corpus](#corpus) file. Heavily weighted in the [InterestingnessScorer](#interestingnessscorer) (10 points per global edge or rare event, 5 per global UOP). Contrast with [Relative Discovery](#relative-discovery).

### Grace Period
In the [MutatorScoreTracker](#mutatorscoretracker), new or rarely-used candidates (fewer than `min_attempts` uses) receive a neutral weight of 1.0 regardless of their score. This prevents the learning engine from prematurely dismissing a [Transformer](#transformer) that hasn't had enough attempts to prove itself.

### Ghost Node
In [`lafleur-lineage`](#lafleur-lineage) output, a placeholder node representing a [Corpus](#corpus) file that was removed by [Corpus Pruning](#corpus-pruning) but whose [Tombstone](#tombstone) metadata preserves the [Lineage](#lineage) chain. Rendered with dotted borders and gray text. Ghost nodes allow ancestry visualization to pass through pruned intermediates without breaking the chain.

### Guard
A runtime check inserted by the JIT compiler into optimized [Traces](#trace). Guards verify that the assumptions made during compilation still hold — for example, that a variable is still an integer, a global hasn't changed, or a type's version tag matches. Guard failure triggers [Deoptimization](#deoptimization). Many lafleur [Mutators](#transformer) specifically target guard failure.

## H

### Harness
The function (conventionally named `uop_harness_test` or similar) that contains the test logic in a [Test Case](#test-case). The harness is typically called in a loop by the [Boilerplate](#boilerplate) to trigger JIT compilation. Lafleur's [Mutations](#mutation) operate on the harness function's [AST](#ast-abstract-syntax-tree), leaving the boilerplate intact.

### HarnessInstrumentor
A utility [Transformer](#transformer) (`mutators/utils.py`) used in [Differential Testing](#differential-testing) mode that injects `return locals().copy()` at the end of [Harness](#harness) functions to capture variable state for comparison.

### Havoc (Strategy)
A mutation strategy that applies 15–50 weighted-random [Transformers](#transformer) from the full pool. Produces significantly different code from the [Parent](#parent), enabling large jumps in the search space. The workhorse strategy for broad exploration.

### Heartbeat
A lightweight timestamp file (`logs/heartbeat`) written periodically by the [Orchestrator](#lafleurorchestrator) to signal that the [Instance](#instance) is still alive. Used by monitoring tools to detect hung instances.

### HealthMonitor
The component (`health.py`) that tracks operational health events: mutation recursion errors, [Corpus](#corpus) sterility transitions, file size warnings, and [EKG](#ekg-jit-electrocardiogram) failures. Provides an event stream for diagnostics.

### Helper+Sniper (Strategy)
A combined mutation strategy that first injects `_jit_helper_*` functions (via the `HelperFunctionInjector`), then attacks them with the [SniperMutator](#snipermutator). Always available because it generates its own targets, unlike the plain [Sniper](#sniper-strategy) strategy which requires pre-existing [Watched Dependencies](#watched-dependencies).

### Hill Climbing
The search algorithm underlying lafleur's evolutionary approach. The fuzzer incrementally improves [Test Cases](#test-case) by keeping [Mutations](#mutation) that increase coverage or JIT stress, always moving "uphill" in the fitness landscape.

### Hit Count
The number of times a particular coverage item ([UOP](#uop-micro-operation), edge, or [Rare Event](#rare-event)) has been observed. Tracked as `Counter[int]` for compact storage. Enables the [Rarity](#rarity) heuristic in [Corpus](#corpus) scoring.

### Hot JIT
A JIT state with polluted caches, fragmented memory, and abundant type feedback from [Polluter](#polluter) scripts. Achieved in full sessions with the [Mixer](#mixer-the) strategy. Represents the most complex and bug-prone JIT state. Contrast with [Cold JIT](#cold-jit) and [Warm JIT](#warm-jit).

### Hygiene Mutators
A set of lightweight [Transformers](#transformer) applied probabilistically after the main mutation strategy: `ImportChaosMutator` (15%), `ImportPrunerMutator` (20%), `StatementDuplicator` (8%), and [RedundantStatementSanitizer](#redundantstatementsanitizer) (5%). These add low-level variety without requiring a full strategy slot.

### Hyper-Extension
A scoring term for [Children](#child--mutant) that produce deep JIT executor chains ([Chain Depth](#chain-depth) > 3). Earns a +10 bonus in the [InterestingnessScorer](#interestingnessscorer). Named by analogy with joints extending beyond their normal range — deep chains represent the JIT stretching its optimization capabilities.

## I

### Imbalance
A structural metric computed by [`lafleur-lineage`](#lafleur-lineage). Measures how unevenly a [Parent](#parent)'s [Children](#child--mutant) contributed to the [Lineage](#lineage) tree, calculated as the coefficient of variation of children's subtree sizes. High imbalance means one [Lineage](#lineage) branch dominates while siblings went [Sterile](#sterile--sterility).

### Instance
A single running lafleur process, identified by a UUID (`run_id`) and a human-readable name (`instance_name`). Multiple instances can run in parallel on different cores, each with its own working directory. See also [Campaign](#campaign).

### Integer ID Compression
The technique by which coverage items ([UOP](#uop-micro-operation) strings, edge strings, [Rare Event](#rare-event) strings) are mapped to monotonically increasing integers for compact storage. Managed by `CoverageManager.get_or_create_id()`. Reduces memory usage and speeds up set operations during the interestingness check.

### Interesting / Interestingness
A [Child](#child--mutant) is "interesting" if it scores at least `MIN_INTERESTING_SCORE` (10.0) in the [InterestingnessScorer](#interestingnessscorer). Interestingness is determined by new coverage ([Global](#global-discovery) or [Relative](#relative-discovery)), JIT vitals bonuses ([Tachycardia](#tachycardia), [Zombie](#zombie-trace), [Chain Depth](#chain-depth), [Stub](#stub)), and size/performance heuristics.

### InterestingnessScorer
The scoring engine (`scoring.py`) that evaluates whether a mutated [Child](#child--mutant) deserves to be added to the [Corpus](#corpus). Calculates a multifactor score from coverage novelty, JIT vital signs, timing data, and size heuristics. Part of the [ScoringManager](#scoringmanager).

## J

### JIT (Just-In-Time) Compiler
CPython's experimental compiler (`--enable-experimental-jit`) that converts frequently executed ("hot") Python bytecodes into optimized machine code via a [UOP](#uop-micro-operation) intermediate representation. Lafleur's primary fuzzing target.

### JIT Executor
An internal CPython object (`_PyExecutorObject`) representing a compiled [Trace](#trace) of optimized machine code. Executors contain the compiled code, exit information, [Bloom Filters](#bloom-filter), and lifecycle state (valid, warm, pending deletion). The [EKG](#ekg-jit-electrocardiogram) inspects these objects at runtime.

### JIT Hang
A [Differential Testing](#differential-testing) finding where code executes normally without JIT but hangs (times out) with JIT enabled. Saved as a distinct [Artifact](#artifact) type (`jit_hangs_found`) because it indicates an infinite loop introduced by JIT optimization.

### JIT Threshold
The number of times a bytecode must execute before the JIT considers it "hot" and compiles it. Lafleur's [`lafleur-jit-tweak`](#lafleur-jit-tweak) tool lowers this threshold to make the JIT compile more aggressively, increasing the surface area for bugs.

## L

### `lafleur-campaign`
CLI tool that aggregates metrics from multiple fuzzing [Instances](#instance) into a fleet-wide dashboard. Deduplicates crashes, produces coverage totals, generates HTML reports with visualizations, and integrates with the [Crash Registry](#crash-registry) for [Regression](#regression) detection. See also [Campaign](#campaign).

### `lafleur-lineage`
CLI tool (`lafleur/lineage.py`) that generates Graphviz DOT graphs from the [Corpus](#corpus)'s [Lineage](#lineage) relationships. Supports five modes: [Ancestry](#ancestry-mode) (trace a file back to its [Seed](#seed)), [Descendants](#descendants-mode) (show what a file produced), [MRCA](#mrca-most-recent-common-ancestor) (find the common ancestor of two files), [Forest](#forest-mode) (overview of all lineage trees), and multi-lineage session crash ancestry. Computes [Strahler Stream Order](#strahler-stream-order), [Branching Factor](#branching-factor), and [Imbalance](#imbalance) metrics. Supports DOT, JSON, and interactive HTML output.

### `lafleur-jit-tweak`
CLI tool that modifies CPython's internal JIT parameters ([JIT Threshold](#jit-threshold), `trace_stack_size`) to make the JIT more aggressive and easier to fuzz. Requires rebuilding CPython after running.

### `lafleur-report`
CLI tool that generates a human-readable health, coverage, and crash summary for a single fuzzing [Instance](#instance). Consumes `run_metadata.json`, `fuzz_run_stats.json`, and `corpus_stats.json`.

### `lafleur-triage`
Interactive CLI tool for managing the [Crash Registry](#crash-registry): triage new crashes, link [Crash Fingerprints](#crash-fingerprint) to GitHub issues, record issue status, and import/export registry data.

### LafleurOrchestrator
The "Brain" of the fuzzer (`orchestrator.py`). Manages the main evolutionary loop: [Parent](#parent) selection, session coordination, [Deepening](#deepening--depth-first) decisions, mutation delegation, result analysis, and [Corpus](#corpus) management. Delegates specialized work to the various managers.

### Lineage
The chain of [Parent](#parent)–[Child](#child--mutant) relationships from a [Test Case](#test-case) back to its original [Seed](#seed). Each corpus file's metadata records its `parent_id`, enabling the full ancestry to be reconstructed. Deep lineages represent sustained evolutionary progress along a single path.

### Lineage Coverage
The union of all coverage discovered by a [Test Case](#test-case) and all its ancestors. Used to determine [Relative Discoveries](#relative-discovery) — items new to this [Lineage](#lineage) but already known globally. Stored as `lineage_coverage_profile` in [Corpus](#corpus) metadata.

### Lineage Depth
How many generations separate a [Corpus](#corpus) file from its original [Seed](#seed). Deeper files have undergone more rounds of [Mutation](#mutation) and selection. Earns a small scoring bonus in the [CorpusScheduler](#corpusscheduler) to encourage continued exploration of productive [Lineages](#lineage).

## M

### Minimizer
The session minimizer tool (`minimize.py`) that takes a complex multi-script crash [Session Bundle](#session-bundle) and reduces it to a single [MRE](#mre-minimal-reproducible-example) using `ShrinkRay` and [Crash Fingerprinting](#crash-fingerprint) to verify the crash is preserved.

### Mixer, The
The [Session Bundle](#session-bundle) assembly strategy that probabilistically injects 1–3 random [Polluter](#polluter) scripts from the [Corpus](#corpus) before the main test case. Polluters fill [Bloom Filters](#bloom-filter), fragment memory, and stress the JIT's global watchers, creating a [Hot JIT](#hot-jit) state. Triggered with `MIXER_PROBABILITY` (30% of non-[Solo](#solo-session) sessions).

### MRCA (Most Recent Common Ancestor)
In [`lafleur-lineage`](#lafleur-lineage), the deepest [Corpus](#corpus) file that is an ancestor of two or more target files. Computed by intersecting the ancestry chains of each target. The MRCA represents the point where a productive [Lineage](#lineage) forked into independently evolving branches. Borrowed from phylogenetics.

### MRE (Minimal Reproducible Example)
The smallest possible [Test Case](#test-case) that still triggers a specific crash. Produced by the [Minimizer](#minimizer) from a full crash bundle.

### Mutation
A transformation applied to a [Test Case](#test-case)'s [AST](#ast-abstract-syntax-tree) to create a new variant. Lafleur's mutations range from simple (operator swapping) to complex (injecting self-modifying iterator protocols that invalidate JIT [Traces](#trace) mid-loop). See [Transformer](#transformer) for the individual mutation classes.

### MutationController
The "Alchemist" (`mutation_controller.py`). Coordinates the entire mutation pipeline: strategy selection via the [MutatorScoreTracker](#mutatorscoretracker), [AST](#ast-abstract-syntax-tree) transformation via the selected strategy, [Hygiene Mutator](#hygiene-mutators) application, [EmptyBodySanitizer](#emptybodysanitizer) pass, and final [Child](#child--mutant) script assembly from [Boilerplate](#boilerplate) + setup + mutated [Harness](#harness).

### MutationOutcome
A dataclass recording the result of running a single [Mutation](#mutation) through all its execution [Runs](#run). Contains the [FlowControl](#flowcontrol) signal and optional new filename if the [Child](#child--mutant) was added to the [Corpus](#corpus).

### MutatorScoreTracker
The adaptive learning engine (`learning.py`) that tracks the effectiveness of mutation strategies and individual [Transformers](#transformer) over time. Uses [Epsilon-Greedy](#epsilon-greedy) selection with attempt-based [Decay](#decay), a [Grace Period](#grace-period), and a [Weight Floor](#weight-floor). State persists across sessions via `mutator_scores.json`.

## N

### NodeTransformer
Python's `ast.NodeTransformer` base class. All lafleur [Mutators](#transformer) inherit from this class and implement `visit_*` methods to transform specific [AST](#ast-abstract-syntax-tree) node types. The preferred pattern is `visit_FunctionDef` with a [Harness](#harness)-name guard. See [Extending Lafleur](./07_extending_lafleur.md).

## O

### Orchestrator
See [LafleurOrchestrator](#lafleurorchestrator).

## P

### Parent
A [Test Case](#test-case) selected from the [Corpus](#corpus) to be mutated. Selection is weighted by the [Fuzzing Score](#fuzzing-score) calculated by the [CorpusScheduler](#corpusscheduler). Higher-scoring parents ([Rare](#rarity) coverage, [Fertile](#fertile--fertility), deep [Lineage](#lineage)) are selected more frequently.

### ParentContext
A dataclass containing all data needed to run [Mutations](#mutation) against a [Parent](#parent): paths, metadata, [Lineage](#lineage) profile, [Harness](#harness) [AST](#ast-abstract-syntax-tree), setup nodes, [Watched Dependencies](#watched-dependencies), and run/mutation counts.

### Polluter
In [Session Fuzzing](#session-fuzzing), a random [Corpus](#corpus) file executed before the [Parent](#parent) and [Child](#child--mutant) to stress the JIT's caches and state. Part of the [Mixer](#mixer-the) strategy. See [Session Bundle](#session-bundle).

### Proto-Trace
The initial, unoptimized [Trace](#trace) recorded by CPython's JIT during the TRACING phase. If the proto-trace is viable, it gets optimized into a full [JIT Executor](#jit-executor). Proto-traces that fail optimization generate [Rare Events](#rare-event).

## R

### Rare Event
A JIT trace event indicating unusual or problematic behavior. Extracted from JIT logs by the [CoverageParser](#coverageparser). Examples include trace optimization failures, [Guard](#guard) assertion errors, and executor invalidations. Rare events are weighted as heavily as new global edges in the [InterestingnessScorer](#interestingnessscorer) because they indicate the JIT has entered a stressed state.

### Rarity
A [CorpusScheduler](#corpusscheduler) heuristic that rewards [Corpus](#corpus) files containing globally rare coverage edges. Computed as the sum of inverse [Hit Counts](#hit-count) for each edge. Files with coverage that few other files share are more valuable as [Parents](#parent) because they explore under-tested JIT behavior.

### RedundantStatementSanitizer
A [Hygiene Mutator](#hygiene-mutators)-layer [Transformer](#transformer) that removes obviously redundant statements (back-to-back `pass` statements, duplicate imports) to keep generated code clean across mutation generations.

### Regression
A crash that was previously marked as fixed (linked to a resolved CPython issue in the [Crash Registry](#crash-registry)) but has reappeared. Detected by [`lafleur-campaign`](#lafleur-campaign) when cross-referencing current [Crash Fingerprints](#crash-fingerprint) against the registry. Regressions are highlighted prominently in [Campaign](#campaign) reports.

### Relative Discovery
A coverage item that is new to the current [Lineage](#lineage) but already known in the [Global Coverage](#global-coverage) map. Less valuable than a [Global Discovery](#global-discovery) but still indicates the [Test Case](#test-case) is exploring a different path through the JIT's state space than its ancestors. Weighted at 1.0 per edge vs. 10.0 for global edges.

### Richness Bonus
A scoring adjustment in the [InterestingnessScorer](#interestingnessscorer) that rewards [Children](#child--mutant) whose total edge count exceeds their [Parent](#parent)'s [Lineage](#lineage) edge count by more than 10%. Encourages mutations that produce richer [Coverage Profiles](#coverage-profile), not just novel individual edges.

### Run
A single execution of a [Child](#child--mutant) script (or [Session Bundle](#session-bundle)). Each [Mutation](#mutation) may have multiple runs (`--runs N`) to account for non-determinism. In [Dynamic Mutations](#dynamic-mutations) mode, the count scales with the [Parent](#parent)'s [Fuzzing Score](#fuzzing-score).

## S

### Scenario Injection
The preferred pattern for complex [Mutators](#transformer). Instead of modifying existing [AST](#ast-abstract-syntax-tree) nodes, the mutator injects a self-contained block of code at the beginning or end of the [Harness](#harness) function. This approach is robust and guaranteed not to create invalid syntax. See [Extending Lafleur](./07_extending_lafleur.md).

### ScoringManager
The component (`scoring.py`) that analyzes execution results. Parses [Coverage Profiles](#coverage-profile), determines [Interestingness](#interesting--interestingness), implements [Deduplication](#deduplication), applies [Dynamic Density Clamping](#dynamic-density-clamping) and [Tachycardia Decay](#tachycardia-decay), and coordinates the [Two-Pass System](#two-pass-system). Contains the [InterestingnessScorer](#interestingnessscorer) and the `parse_jit_stats` log parser.

### Seed
An initial [Test Case](#test-case) that forms the starting point for evolutionary exploration. Seeds are either generated by [Fusil](#fusil) or provided manually. They have no [Parent](#parent) ([Lineage Depth](#lineage-depth) 0) and are marked with `is_seed: True` in [Corpus](#corpus) metadata.

### Session
One iteration of the evolutionary loop: selecting a [Parent](#parent), applying a batch of [Mutations](#mutation), executing and analyzing each one, and updating [Corpus](#corpus) state. The [Orchestrator](#lafleurorchestrator) counts sessions in `run_stats["total_sessions"]`.

### Session Bundle
In [Session Fuzzing](#session-fuzzing) mode, the ordered sequence of scripts executed in a single shared process: (1) optional [Polluters](#polluter) ([Mixer](#mixer-the)), (2) [Parent](#parent) ([Warmup](#warmup)), (3) [Child](#child--mutant) ([Attack Script](#attack-script)). The shared process preserves JIT [Traces](#trace), type feedback, and memory layout across script boundaries. When a crash occurs, the entire bundle is saved for reproducibility.

### Session Fuzzing
An execution mode (`--session-fuzz`) where scripts run sequentially in a single shared process rather than each in a fresh interpreter. This preserves JIT state across script boundaries, enabling "warm JIT" attacks that are impossible with isolated execution. See [Session Bundle](#session-bundle).

### Side Exit
A point in an optimized JIT [Trace](#trace) where execution may leave the trace and return to the interpreter (via `_DEOPT` or `_EXIT_TRACE` [UOPs](#uop-micro-operation)). High side exit counts indicate trace instability. Tracked as a [Structural Metric](#structural-metrics) in [Coverage Profiles](#coverage-profile). See also [Exit Count](#exit-count).

### Slicing
An optimization for large [Corpus](#corpus) files. When the [Parent](#parent)'s [Harness](#harness) function body exceeds 100 statements, the [SlicingMutator](#slicingmutator) applies the mutation pipeline to a random 25-statement slice rather than the full [AST](#ast-abstract-syntax-tree). Prevents mutation time from scaling linearly with file size.

### SlicingMutator
A meta-mutator (`mutators/engine.py`) that extracts a random slice of the [Harness](#harness) body, applies weighted-random [Transformers](#transformer) to just that slice, then reinserts it. Used by [Havoc](#havoc-strategy) and [Spam](#spam-strategy) strategies when the harness is large. See [Slicing](#slicing).

### Sniper (Strategy)
A targeted mutation strategy that uses [Watched Dependencies](#watched-dependencies) from [Bloom Filter Probing](#bloom-filter-probing) to surgically invalidate precisely the globals the JIT is guarding. Only available when the [Parent](#parent)'s metadata contains `watched_keys` from a previous [EKG](#ekg-jit-electrocardiogram) pass. The most precise strategy, designed to force specific [Deoptimizations](#deoptimization).

### SniperMutator
The [Transformer](#transformer) class (`mutators/sniper.py`) that implements the [Sniper](#sniper-strategy) strategy. Given a list of [Watched Dependencies](#watched-dependencies), it injects code that modifies those variables mid-loop to invalidate JIT [Traces](#trace).

### Solo Session
A [Session Fuzzing](#session-fuzzing) variant (triggered with `SOLO_SESSION_PROBABILITY` = 15%) where only the [Child](#child--mutant) script runs, with no [Parent](#parent) [Warmup](#warmup) or [Polluter](#polluter) scripts. Tests the JIT in a [Cold JIT](#cold-jit) state.

### Spam (Strategy)
A mutation strategy that picks a single [Transformer](#transformer) and applies it 20–50 times. Produces code that is heavily transformed in one specific way. Useful for saturating a particular JIT behavior — for example, spamming `GCInjector` to stress the JIT's interaction with garbage collection.

### Stateful UOP Edge
The primary and most valuable coverage signal. An edge represents the control flow transition between two consecutive [UOPs](#uop-micro-operation), tagged with the JIT's operational state: e.g., `(OPTIMIZED, "_LOAD_FAST->_STORE_FAST")`. The statefulness means discovering a previously seen edge in a new JIT state counts as new coverage. This is what "coverage edge" refers to throughout the codebase.

### `state_tool`
A CLI utility (`state_tool.py`) for inspecting, migrating, and dumping the binary `coverage_state.pkl` file. Provides human-readable views of the [Integer ID Compression](#integer-id-compression) maps and [Corpus](#corpus) metadata.

### Sterile / Sterility
A [Corpus](#corpus) file that has been mutated many times (> `CORPUS_STERILITY_LIMIT` = 599) without producing any new coverage. Marked with `is_sterile: True` in metadata and heavily penalized in scoring (score × 0.1). Sterile files are effectively deprioritized without being deleted. Contrast with [Fertile](#fertile--fertility). See also [Sterility Limit](#sterility-limit).

### Sterility Limit
The threshold of consecutive unproductive [Mutations](#mutation) after which action is taken. Two limits exist: `DEEPENING_STERILITY_LIMIT` (30) causes a [Deepening](#deepening--depth-first) session to abandon its current [Lineage](#lineage), and `CORPUS_STERILITY_LIMIT` (599) marks a [Corpus](#corpus) file as permanently [Sterile](#sterile--sterility).

### Structural Metrics
Per-[Harness](#harness) measurements extracted from JIT trace logs: `trace_length` ([UOP](#uop-micro-operation) count in a successfully generated optimized [Trace](#trace)) and `side_exits` (count of [Deoptimization](#deoptimization)/exit UOPs). Used in [Corpus](#corpus) scoring to reward complex, branchy traces.

### Strahler Stream Order
A structural complexity metric computed by [`lafleur-lineage`](#lafleur-lineage), borrowed from hydrology. Leaves have order 1. An internal node's order equals its maximum child's order (if unique) or maximum + 1 (if two or more children share the maximum). High Strahler order indicates a "watershed" node in the [Lineage](#lineage) tree — the confluence of multiple deep, balanced subtrees representing independently productive evolutionary branches.

### Stub
A JIT-compiled [Trace](#trace) with very small [Code Size](#code-size) (< 5 bytes). Stubs often indicate degenerate compilation where the JIT produced nearly empty machine code. Earns a +5 bonus in the [InterestingnessScorer](#interestingnessscorer).

### Success Rate
In [`lafleur-lineage`](#lafleur-lineage), the ratio of a [Parent](#parent)'s [Fertile](#fertile--fertility) outputs to its total mutation attempts: `total_finds / total_mutations_against`. Distinguishes genuinely productive parents from those that produced many [Children](#child--mutant) simply because they were selected for [Mutation](#mutation) many times. Requires the `total_mutations_against` counter in [Corpus](#corpus) metadata.

## T

### Tachycardia
A scoring bonus (+20) for [Children](#child--mutant) that provoke high JIT [Exit Density](#exit-density). Named by medical analogy — just as cardiac tachycardia means an abnormally fast heart rate, JIT tachycardia means an abnormally high rate of trace exits, indicating the JIT's optimizations are under severe stress. Two scoring paths exist: the [Delta Vitals](#delta-vitals) path (preferred, [Session Fuzzing](#session-fuzzing) mode) and the [Absolute Vitals](#absolute-vitals) path (fallback). See also [Tachycardia Decay](#tachycardia-decay).

### Tachycardia Decay
After [Dynamic Density Clamping](#dynamic-density-clamping), the saved [Exit Density](#exit-density) is multiplied by a decay factor (0.95). This creates gentle downward pressure — the target for the next generation is 95% of the clamped value, preventing [Lineages](#lineage) from permanently riding a single high-density spike.

### Tombstone
A minimal metadata entry retained in `per_file_coverage` when a [Corpus](#corpus) file is removed by pruning. Contains only `parent_id`, `discovery_mutation`, `lineage_depth`, `discovery_time`, and `is_pruned: True`. Preserves [Lineage](#lineage) chain connectivity for [`lafleur-lineage`](#lafleur-lineage) [Ghost Nodes](#ghost-node) while releasing the bulk of the metadata (coverage data, hashes, etc.).

### TelemetryManager
The component (`telemetry.py`) that tracks [Run](#run) statistics, logs time-series datapoints for [Campaign](#campaign) analysis, records [Corpus](#corpus) evolution stats, and generates `corpus_stats.json`.

### Test Case
A Python script that exercises JIT behavior, consisting of [Boilerplate](#boilerplate) (setup and invocation loop) and [Core Code](#core-code) (the mutatable [Harness](#harness) function and its setup variables). Each [Corpus](#corpus) file is a complete, standalone test case.

### Tier 2
CPython's JIT compilation stage where frequently executed bytecodes are compiled into optimized [Traces](#trace). Also called the "optimizer" or "trace compiler." Lafleur primarily targets Tier 2 behavior.

### Timing Fuzzing
An execution mode (`--timing-fuzz`) that measures execution time with and without JIT, rewarding [Children](#child--mutant) that cause significant JIT slowdowns. Detects performance regressions where the JIT produces slower code than the interpreter.

### Trace
A linear sequence of [UOPs](#uop-micro-operation) recorded and optimized by the JIT. Traces start at a hot bytecode and follow the execution path, inserting [Guards](#guard) where assumptions are made. See also [Proto-Trace](#proto-trace), [JIT Executor](#jit-executor).

### Transformer
A Python [NodeTransformer](#nodetransformer) subclass that implements a specific [Mutation](#mutation). Lafleur maintains a pool of 76+ transformers covering generic mutations, type system attacks, data model attacks, control flow attacks, and runtime state attacks. See [The Mutation Engine](./04_mutation_engine.md).

### Two-Pass System
The analysis pipeline's approach to ensuring state consistency. Pass 1 (read-only) checks whether the [Child](#child--mutant) is [Interesting](#interesting--interestingness) without modifying [Global Coverage](#global-coverage) state. Pass 2 (commit) updates state only if the child passes the interestingness check and [Deduplication](#deduplication). This prevents partial state corruption if an error occurs mid-analysis.

## U

### UOP (Micro-Operation)
A low-level operation in CPython's JIT intermediate representation. Examples: `_LOAD_FAST`, `_STORE_ATTR`, `_GUARD_TYPE_VERSION`. UOPs are the building blocks of [Traces](#trace). Individual UOPs provide low-granularity coverage (many scripts hit the same UOPs), while [Stateful UOP Edges](#stateful-uop-edge) between them provide the primary coverage signal.

## V

### Viable
A [Corpus](#corpus) file that is not [Sterile](#sterile--sterility) — it still has potential to produce interesting [Children](#child--mutant). `viable_count = total_files - sterile_count`.

## W

### Warm JIT
A JIT state where the [Parent](#parent) script has already established [Traces](#trace) and type feedback. Achieved in standard sessions where the parent runs before the [Child](#child--mutant). The child's [Mutations](#mutation) attack the warm traces. Contrast with [Cold JIT](#cold-jit) and [Hot JIT](#hot-jit).

### Warmup
In [Session Fuzzing](#session-fuzzing), the execution of the [Parent](#parent) script before the [Child](#child--mutant). Warms the JIT by establishing [Traces](#trace) relevant to the [Lineage](#lineage). See [Session Bundle](#session-bundle).

### Watched Dependencies
The list of global and builtin variable names that the JIT is actively monitoring via [Bloom Filters](#bloom-filter). Discovered by the [Driver](#driver)'s [Bloom Filter Probing](#bloom-filter-probing) and saved to [Corpus](#corpus) metadata as `watched_dependencies`. Fed to the [Sniper](#sniper-strategy) strategy to enable targeted invalidation.

### Weight Floor
The minimum weight (`WEIGHT_FLOOR` = 0.05) applied in the [MutatorScoreTracker](#mutatorscoretracker) to ensure every strategy and [Transformer](#transformer) retains at least a small probability of being selected, even if its score has decayed to near zero. Prevents the learning engine from permanently abandoning any strategy.

## Z

### Zombie Trace
A [JIT Executor](#jit-executor) in the `pending_deletion` state — it has been invalidated but not yet cleaned up. Detected by the [EKG](#ekg-jit-electrocardiogram) via the `pending_deletion` flag on the `_PyExecutorObject` struct. Zombie traces earn the largest scoring bonus (+50) because they indicate potential use-after-free bugs in the JIT's executor lifecycle management.
