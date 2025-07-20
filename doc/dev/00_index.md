# Lafleur Developer Documentation: Index

### Introduction

Welcome to the developer documentation for `lafleur`. This collection of documents is intended for contributors and advanced users who wish to understand the internal architecture, data formats, and development process of the fuzzer.

The documents are designed to be read in order for a comprehensive overview, but feel free to jump to the section most relevant to your needs.

### Document Index

| Document | Description | Target Audience |
| :--- | :--- | :--- |
| **[01\_architecture\_overview.md](https://www.google.com/search?q=./01_architecture_overview.md)** | A high-level introduction to `lafleur`'s purpose, philosophy, and core components. | **All new developers.** This is the essential starting point. |
| **[02\_the\_evolutionary\_loop.md](https://www.google.com/search?q=./02_the_evolutionary_loop.md)** | A detailed, step-by-step walkthrough of a single fuzzing session from parent selection to corpus update. | Developers wanting to understand the core execution flow of the orchestrator. |
| **[03\_coverage\_and\_feedback.md](https://www.google.com/search?q=./03_coverage_and_feedback.md)** | An explanation of how JIT logs are parsed and the different coverage signals (`uop edges`, `rare events`) that `lafleur` uses to guide its search. | Developers working on the coverage engine or analyzing the fuzzer's effectiveness. |
| **[04\_mutation\_engine.md](https://www.google.com/search?q=./04_mutation_engine.md)** | A comprehensive guide to the AST-based mutation engine and the library of generic and JIT-specific mutators. | Developers wanting to create new mutation strategies or understand how test cases are generated. |
| **[05\_state\_and\_data\_formats.md](https://www.google.com/search?q=./05_state_and_data_formats.md)** | A reference for the structure of all state files (`coverage_state.pkl`, `fuzz_run_stats.json`) and output directories. | Developers debugging the fuzzer's state or building external analysis tools. |
| **[06\_developer\_getting\_started.md](https://www.google.com/search?q=./06_developer_getting_started.md)** | A practical, hands-on guide to setting up the CPython build environment, installing dependencies, and running the fuzzer. | **All new developers.** The practical guide to getting the fuzzer running for the first time. |
| **[07\_extending\_lafleur.md](https://www.google.com/search?q=./07_extending_lafleur.md)** | A tutorial on how to contribute new features to `lafleur`, such as adding a new mutator or a new rare event. | Developers looking to contribute code to the project. |
