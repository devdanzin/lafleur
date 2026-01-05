# Lafleur Developer Documentation: 02. The Evolutionary Loop

### Introduction

The core of `lafleur` is its evolutionary loop, managed by the `LafleurOrchestrator` class in `orchestrator.py`. This document provides a detailed walkthrough of a single fuzzing "session".

The loop is now a highly adaptive process. For each session, it makes a probabilistic choice between a **breadth-first** strategy (exploring a wide variety of parents from the corpus) and a **depth-first** "deepening" strategy (aggressively mutating a single promising lineage). Furthermore, the selection of mutation strategies is guided by a learning engine, and the execution phase can now run complex **multi-script sessions** to stress the JIT's state persistence.

### Flowchart of a Fuzzing Session

The following diagram illustrates the complete logical flow, including the new session construction and differential scoring steps.

```mermaid
graph TD
    A[Start Session] --> A1{Breadth or Depth?};
    A1 -- Breadth --> B[Select Parent from Corpus];
    A1 -- Depth --> B;

    subgraph "Mutation Cycle (execute_mutation_and_analysis_cycle)"
        B --> C[Calculate Mutations & Runs for Parent];
        C --> D{Mutate Parent -> C1};
        D --> D1{Assemble Session Bundle};
        D1 --> E[Start Multi-Run Loop];
        subgraph " "
        E --> F{Execute Session (Mixer + Parent + C1)};
        F --> G{Analyze Result & JIT Vitals};
        G --> H{Interesting?};
        H -- No --> I{More Runs Left?};
        H -- Yes --> L[Update Mutator Scores];
        I -- Yes --> F2[Execute Session - Run #2];
        F2 --> G2{Analyze Result...};
        G2 --> H2{Interesting?};
        H2 -- No --> I2[...];
        I -- No --> J{More Mutations Left?};
        end
        H2 -- Yes --> L;
        J -- Yes --> D2(Mutate Parent -> C2);
        D2 --> E2[Start Multi-Run...];
        J -- No --> K[End Mutation Cycle];

        L --> M{Deepening Session?};
        M -- Yes --> B2(New Child Becomes Parent);
        M -- No --> K;
        B2 --> C;
    end

    K --> Z[End Session];

    style A fill:#d4edda,stroke:#333,stroke-width:2px
    style B2 fill:#cce5ff,stroke:#333,stroke-width:2px
    style D1 fill:#fff3cd,stroke:#333,stroke-width:2px

```

### **Step-by-Step Analysis of a Fuzzing Session**

The modern lafleur session is a dynamic, multi-stage process. The following steps detail the complete lifecycle, combining the foundational evolutionary model with advanced state-fuzzing strategies.

### Step 1: Parent and Strategy Selection

The fuzzing session begins in the `run_evolutionary_loop` method. The first step is to choose a parent test case to serve as the genetic material for this session's mutations.

  * **Scoring:** The orchestrator calls upon the `CorpusManager`, which uses a `CorpusScheduler` to calculate a "fuzzing score" for every file in the corpus. This score is a floating-point number derived from several heuristics:
      * **Performance:** Files that are smaller and execute faster are penalized less.
      * **Rarity:** Files that contain coverage features (specifically, stateful uop edges) that are globally rare receive a significant score bonus.
      * **Fertility:** Files that have historically produced many "interesting" children are considered more "fertile" and are rewarded. Conversely, files that have been mutated many times without producing new discoveries are marked as "sterile" and are heavily penalized.
      * **Depth:** Files that are the result of a long, successful chain of mutations (a deep lineage) receive a small score bonus to encourage exploration of deep states.
      * **JIT Instability:** Files that have previously demonstrated high JIT "Tachycardia" (high exit density) are rewarded to encourage further stress testing of that instability.
  * **Selection:** The orchestrator performs a weighted random selection on the corpus, where the weight for each file is the score calculated by the scheduler.
  * **Strategy Choice:** Once a parent is selected, the orchestrator makes a probabilistic choice (default 20%) to enter a **depth-first "deepening" session**, where the loop will immediately switch to mutating any interesting child found, creating deep lineages rapidly.

### Step 2: Adaptive Mutation

With a parent and a strategy selected, the orchestrator reads the parent's source code and parses its "core" part into an Abstract Syntax Tree (AST). The `base_harness_node` (e.g., `uop_harness_f1`) is identified and passed to the `apply_mutation_strategy` method.

* **Adaptive Strategy Selection:** This method consults the `MutatorScoreTracker` to get dynamic weights for each high-level strategy (Deterministic, Havoc, Spam) based on their recent success.
* **Code Normalization & Sanitization:** A `FuzzerSetupNormalizer` removes old setup code, and an `EmptyBodySanitizer` ensures no control flow statements have empty bodies, preventing syntax errors.
* **Tier 2 Aware Mutation:** The engine applies specific JIT-breaking patterns, such as `ZombieTraceMutator` (stressing executor lifecycles) or `GlobalOptimizationInvalidator` (breaking global assumptions mid-loop).

The result of this phase is a new, mutated AST for the harness function.

### Step 3: Session Assembly and Execution

Unlike simpler fuzzers that execute the child script in isolation, `lafleur` assembles a **Session Bundle** to test state persistence and JIT cache coherency.

1. **The Mixer (Pollution):** With a configurable probability (default 30%), the orchestrator selects 1-3 random "polluter" scripts from the corpus. These are prepended to the session to fill Bloom filters, fragment memory, and stress the JIT's global watchers before the test even begins.
2. **The Warmup:** The original **Parent** script is added to the bundle. Running it first ensures the JIT has "warmed up" traces relevant to the lineage.
3. **The Attack:** The mutated **Child** script is added last. It attacks the JIT state established by the previous scripts.

The orchestrator then executes this bundle using the `lafleur.driver` module. The driver runs all scripts sequentially in a **single shared process**. This ensures that JIT traces, type feedback, and memory layouts persist from the polluters/parent to the child.

* **JIT Introspection (The EKG):** During execution, the driver uses `ctypes` to inspect the internal `_PyExecutorObject` structs of the JIT. It records vital signs like **Exit Density** (bailouts per instruction) and **Zombie Traces** (`pending_deletion` flags).

### Step 4: Analysis, Scoring, and Feedback

The result of the session is passed to the `analyze_run` method. This process has been enhanced with **Differential Vital Scoring** to reward JIT instability.

1. **Error Checking & Crash Bundles:**
* If a crash occurs, the orchestrator saves the **entire session bundle** (polluters, parent, child) into a directory (e.g., `crashes/session_crash_123/`).
* It also generates a `reproduce.sh` script, ensuring the crash can be deterministically reproduced with the exact same JIT state.

2. **Coverage & Vitals Parsing:**
* The log file is parsed to extract the coverage profile (edges, rare events).
* The JIT Vitals are parsed: `max_exit_density`, `zombie_traces`, `chain_depth`.

3. **Interestingness Scoring:**
The `InterestingnessScorer` evaluates the child using a multi-factor system:
* **New Coverage:** Heavy weight for new global edges or rare events.
* **Zombie Bonus:** Massive reward (+50) if any `zombie_traces` were detected (potential Use-After-Free).
* **Differential Tachycardia:** The scorer compares the child's `max_exit_density` to its parent's. It only awards a bonus if the child is **significantly more unstable** (e.g., > 25% higher density) than the parent. This prevents lineages from coasting on inherited instability.

4. **Dynamic Density Clamping:**
If a child produces an extremely high density (e.g., 9,000,000), the value saved to the corpus metadata is **clamped** using a trailing limit (e.g., `min(parent * 5, child)`). This ensures future generations have a reachable target to beat, preventing "fitness cliffs" where a lineage dies out because it became too successful too quickly.

5. **Corpus Commit:**
If the child is interesting and unique, it is saved to the corpus. Its metadata includes the new JIT vitals, which will be used as the baseline for the next generation of mutations.
