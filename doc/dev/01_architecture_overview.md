# Lafleur Developer Documentation: 01. Architecture Overview

### Introduction

**Lafleur** is a sophisticated, feedback-driven, evolutionary fuzzer designed specifically to find complex, state-dependent bugs and crashes in CPython's JIT compiler. It began as an advanced feature set within the `fusil` project and was spun off into a standalone tool to better focus on its specialized purpose.

Unlike purely generative fuzzers that create test cases from scratch in a "fire-and-forget" manner, `lafleur` uses a learning-based approach. It executes test cases, observes their effect on the JIT's behavior via detailed coverage analysis, and uses that information to guide its future mutations, becoming progressively smarter over the course of a fuzzing campaign.

### Core Philosophy: The Evolutionary Loop

The core of `lafleur` is an evolutionary, hill-climbing search algorithm that continuously performs a four-stage feedback loop.

1.  **Selection:** Intelligently select a promising "parent" test case from the existing corpus based on heuristics like performance, code complexity, and the rarity of the coverage it generates.
2.  **Mutation:** Apply a pipeline of advanced, Abstract Syntax Tree (AST)-based mutations to the parent, creating a new "child" variant. These mutations are often specifically designed to stress JIT compiler assumptions.
3.  **Execution:** Run the child test case in a monitored process with JIT logging enabled to capture its behavior.
4.  **Analysis:** Parse the logs to extract a coverage profile. If the child produced new and interesting JIT behavior (i.e., new coverage), it is added to the corpus to serve as a parent for future generations.

This cycle allows the fuzzer to iteratively build upon its successes, exploring deeper and more complex areas of the JIT's state space over time.

### Session Fuzzing Architecture

To find deep, state-dependent bugs that only appear after prolonged execution or specific memory patterns, `lafleur` supports a **Session Fuzzing** mode (`--session-fuzz`).

In this mode, the fuzzer moves beyond executing isolated scripts. Instead, it constructs a **Session Bundle**—a sequence of scripts executed in a single, shared process. This preserves the JIT's internal state (traces, global watchers, memory layout) across script boundaries.

A typical session follows this "Mixer" strategy:
1.  **Polluters (The Mixer):** The session optionally begins by executing 1-3 random scripts from the corpus. These serve to "pollute" the JIT's cache, fill Bloom filters, and fragment the memory allocator, creating a hostile environment for the test case.
2.  **Warmup (The Parent):** The original parent script is executed to establish a known, "warm" JIT state.
3.  **Attack (The Child):** Finally, the mutated child script is executed. Because the JIT is already warm (and potentially unstable from the polluters), the child can trigger edge cases like "Zombie Traces" (Use-After-Free) or optimization invalidation bugs that isolated execution would miss.

If a crash occurs, `lafleur` saves the entire bundle (polluters, parent, and child) into a directory, ensuring exact reproducibility of the JIT state.

### High-Level System Diagram

The diagram below illustrates the main components of the `lafleur` fuzzer and the flow of data through the system.

```mermaid
flowchart TD
    subgraph LafleurOrchestrator
        A[1.Select Parent] --> B(2.Mutate);
        B --> C{3.Execute Session};
        C --> D[4.Analyze Log];
        D --> E{Interesting?};
    end

    subgraph CorpusManager
        F[Corpus & State File]
    end

    subgraph ASTMutator
        G[Mutation Engine]
    end

    subgraph CoverageParser
        H[Log Parser]
    end

    subgraph LearningEngine
        J[Mutator Scores]
    end

    F -- Parent File --> A;
    B -- AST --> G;
    G -- Mutated AST --> B;
    C -- Bundle --> I(Subprocess / Driver);
    I -- JIT Log & Vitals --> H;
    H -- Coverage Profile --> D;
    
    E -- Yes --> F;
    E -- No --> A;

    D -- Success Info --> J;
    J -- Dynamic Weights --> G;

    style F fill:#f9f,stroke:#333,stroke-width:2px
    style I fill:#bbf,stroke:#333,stroke-width:2px
    style J fill:#d4edda,stroke:#333,stroke-width:2px
```

### Module Breakdown

The `lafleur` project is organized into several distinct Python modules, each with a clear responsibility.

* `lafleur/orchestrator.py`: The "brain" of the fuzzer. Contains the `LafleurOrchestrator` class, which manages the main evolutionary loop. It now supports **Session Fuzzing**, coordinating the assembly of script bundles and implementing the **Differential Scoring** logic that rewards JIT instability (like high exit density).
* `lafleur/corpus_manager.py`: Handles all interactions with the on-disk corpus and the persistent state file (`coverage_state.pkl`). It is responsible for selecting parents, adding new files, and generating initial seeds.
* `lafleur/driver.py`: The execution engine. This standalone script runs the fuzzing sessions. It includes the **JIT Introspection (EKG)** system, which uses `ctypes` to inspect internal C structs (`_PyExecutorObject`) in real-time, extracting vital metrics like exit density and zombie trace counts.
* `lafleur/coverage.py`: The "eyes" of the fuzzer. Contains the logic for parsing verbose JIT trace logs to extract the coverage feedback signal (uop edges and rare events).
* `lafleur/mutators/`: The "hands" of the fuzzer. This package contains the `ASTMutator` engine (in `engine.py`) and a rich library of `NodeTransformer` subclasses. It includes advanced **Tier 2 Aware** mutators (e.g., `ZombieTraceMutator`, `GlobalOptimizationInvalidator`) designed to attack specific JIT optimizations.
* `lafleur/learning.py`: Houses the `MutatorScoreTracker`, the adaptive learning engine that scores mutation strategies based on their historical success, allowing the fuzzer to dynamically focus on the most effective techniques.
* `lafleur/utils.py`: A collection of generic, reusable helper components, such as the `TeeLogger` for simultaneous console and file logging, and functions for managing run statistics.
* `lafleur/state_tool.py`: A standalone command-line utility for managing the binary state file.
