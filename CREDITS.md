# Credits

## Core Development

* **Daniel Diniz ([@devdanzin](https://github.com/devdanzin)):** Creator and main developer of the `lafleur` evolutionary fuzzing engine — architecture, orchestrator, mutation engine, coverage parser, JIT introspection, scoring, and the analysis/triage toolchain.

## Contributors

* **[@ShrayJP](https://github.com/ShrayJP):** Added the `--timeout` CLI option for configurable script execution timeouts.
* **[@smiyashaji](https://github.com/smiyashaji):** Added the `bump_version.py` script for automated version management.

## Acknowledgements

This project builds upon the foundational work of others and has benefited greatly from expert guidance and feedback.

* **Victor Stinner ([@vstinner](https://github.com/vstinner)):** Original developer of the [fusil](https://github.com/devdanzin/fusil) framework, from which `lafleur` originated. Fusil continues to provide the initial seed generation capabilities for `lafleur`.
* **Brandt Bucher ([@brandtbucher](https://github.com/brandtbucher)):** CPython JIT expert. Provided guidance, feedback, and encouragement throughout the project's development.
* **Ken Jin ([@Fidget-Spinner](https://github.com/Fidget-Spinner)):** CPython JIT expert. Provided guidance, feedback, and encouragement throughout the project's development. Triages, diagnoses, and fixes most JIT issues reported by `lafleur`.

## AI-Assisted Development

Development depends heavily on AI for planning and coding, in a collaborative process. The AI's input and ability to quickly and robustly implement, discuss, and iterate on proposed approaches was crucial for the viability of this project.

* **Claude Opus:** Constant AI partner for planning, architectural discussions, and prompt crafting. General feature development, systematic code review, and documentation enhancement.
* **Claude Code:** Main agentic collaborator, working across the entire codebase with emphasis on architecture design, mutator implementation, and code refactoring.
* **Gemini Pro:** Collaborative AI partner for planning, implementation, architectural refinement, and prompt writing for agents.
* **Gemini CLI:** Agentic collaborator for JIT introspection, scoring logic, and refactoring.

[Anthropic](https://www.anthropic.com/) provided financial support that enabled access to advanced AI capabilities for `lafleur`'s development.
