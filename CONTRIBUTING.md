# Contributing to lafleur

We welcome all sorts of contributions to `lafleur`! Thank you for your interest in helping improve the fuzzer.

We hope to make this a good project to contribute to by welcoming new contributors and giving you voice, space, tools, and guidance to improve while you help us.

## How You Can Contribute

There are many ways to contribute to `lafleur`, and many of them do not require writing any code.

### Reporting Bugs and Suggesting Features

If you've found a bug in `lafleur` itself or have an idea for a new feature, please check our **[Issues Page](https://github.com/devdanzin/lafleur/issues)** to see if it has already been reported.

When filing a bug report, please include:

1.  The full log file (`.log`) from the `logs/` directory that shows the error, if it's available.
2.  The `pyproject.toml` file to help us understand your configuration.
3.  The commit hash of the CPython version you are fuzzing (you can get this by running `python -VV`).

### Working on Existing Issues

A great way to contribute is by helping with issues that have already been filed.

  * **Triaging:** Simply reading existing issues and commenting, asking for clarifications, or confirming that you can also reproduce the bug is a huge help.
  * **Good First Issues:** If you are a beginner, we try to have issues tagged with [`good-first-issue`](https://github.com/devdanzin/lafleur/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22). We are happy to help you pick an issue, understand it, and guide you through creating your first pull request.

### Improving Documentation

Our documentation is an essential part of the project. We welcome any improvements, including:

  * Fixing typos or grammatical errors.
  * Clarifying sections that are confusing.
  * Adding new examples or tutorials.
  * Translating documents into other languages.

### Submitting Code Changes

If you are ready to contribute code, please see the **"Submitting a Contribution"** section below for details on our workflow.

## Submitting a Contribution (The Workflow)

We welcome code contributions, from small bug fixes to new mutation strategies. To ensure a smooth process, please follow this general workflow.

### Pull Request Process

1.  **Fork the repository** to your own GitHub account.
2.  **Create a new branch** for your changes (e.g., `git checkout -b feature/my-new-mutator`).
3.  **Make your changes.** Try to keep your changes focused on a single feature or bug fix.
4.  **Format your code.** Before committing, please run the project's code formatter from the root directory: `ruff format .`
5.  **Commit your changes** with a clear and descriptive commit message.
6.  **Push your branch** to your fork.
7.  **Open a Pull Request** from your branch to the `lafleur` `main` branch.

### Writing Good Commit Messages

Clear commit messages are important for project history. We recommend following the [Conventional Commits](https://www.conventionalcommits.org/) specification. This is not a strict requirement, but it is highly encouraged.

A good commit message summary line looks like this:
* `feat: Add new SideEffectInjector mutator`
* `fix: Prevent crash when unparsing deeply nested ASTs`
* `docs: Add getting started guide for developers`

### Pull Request Quality

Before you submit a pull request, please review your changes to ensure:
* The change is focused on a single issue or feature.
* There are no unnecessary whitespace or style changes.
* New code includes docstrings and type hints.
* The project's developer documentation is updated if you've added or changed a major feature.

## Updating Project Records

To ensure everyone's contributions are recognized, we encourage you to update the project's records as part of your first pull request.

### Adding to `CHANGELOG.md`

Please add a single line describing your change to the `## [Unreleased]` section of the `CHANGELOG.md` file. Add your entry under the appropriate category (`Added`, `Changed`, `Fixed`, etc.).

**Example:**

```markdown
### Fixed
- Avoid crash when unparsing deeply nested ASTs, by @YourGitHubUser.
```

### Adding Yourself to `CREDITS.md`

We encourage all contributors to add themselves to the `CREDITS.md` file.

Please add your **name, your GitHub username, or both** (whichever you prefer) to the `Contributors` section. Please try to keep the list in alphabetical order.

## Working with AI-Assisted Code

The development of `lafleur` has been a collaborative partnership between human developers and AI assistants. We encourage contributors to use AI as a tool to help plan, implement, and refactor code.

However, AI-generated code requires careful human review. The contributor is always the final author and is responsible for the quality and correctness of their submission. When reviewing your own or others' AI-assisted contributions, please pay close attention to the following:

* **Focus:** Does the change stay focused on its intended purpose? AI can sometimes modify unrelated code or mistakenly delete existing comments and docstrings.
* **Correctness:** Is the logic correct and robust? Always validate that the implementation perfectly matches the agreed-upon plan, as AI can sometimes misunderstand subtle requirements.
* **Simplicity:** Is the proposed solution unnecessarily complex? Look for opportunities to simplify the code, as AI can sometimes produce verbose solutions where a more direct one exists.
* **Redundancy:** Does the change add unnecessary comments that just restate what the code is doing? Please remove any unneeded boilerplate or comments.

## Communication and Support

We want to help you contribute! If you have a question, get stuck, or want to discuss an idea, please feel free to reach out.

### Primary Channel: GitHub Discussions

For most questions, ideas, and discussions, the **[GitHub Discussions Page](https://github.com/devdanzin/lafleur/discussions)** is the preferred channel. This allows the entire community to participate in and benefit from the conversation.

### Other Channels

We understand that sometimes you may want to ask a question privately, especially if you are a new contributor. You can reach out through any of the following channels:

  * **Email:** `lafleurfuzzer@gmail.com`
  * **Python Discourse:** https://discuss.python.org/u/devdanzin/summary
  * **Discord:** https://discord.com/users/1127958517849014362

## Reporting Bugs Found *in CPython*

Finding a bug in CPython is the ultimate goal of `lafleur`. If your fuzzing run produces a valuable crash (like a segmentation fault), a hang, or a correctness divergence, the correct path is to report it to the CPython project.

Creating a high-quality bug report is essential for getting bugs fixed. Before submitting an issue, please follow these steps.

#### 1. Triage the Finding

First, confirm that the bug is reproducible and not a false positive. Run the test case that `lafleur` saved in the `crashes/`, `timeouts/`, or `divergences/` directory several times to ensure the behavior is consistent.

Feel free to ask for help triaging your suspected bug in the `lafleur` **[GitHub Discussions](https://github.com/devdanzin/lafleur/discussions)** or on **[Python's Discourse](https://discuss.python.org/)**.

#### 2. Minimize the Test Case

This is the most important step. Fuzzer-generated code is often large and contains a lot of irrelevant logic. Please try to manually reduce the test case to the **smallest possible snippet of code** that still reproduces the bug. A minimal, 5-line reproducer is much more likely to be fixed than a 500-line fuzzer output.

#### 3. Create a Reproducible Report

When you are ready to file the issue, please gather the following information:

  * The final, minimized, and reproducible test case.
  * The exact command needed to trigger the bug (e.g., `python crash.py`).
  * The full traceback or crash output from the CPython interpreter.
  * The exact CPython version and commit hash (the output of `python -VV`).
  * Your operating system and architecture (e.g., Ubuntu 22.04 on x86-64).

#### 4. File the Issue

Once you have all the information, please file the issue on the official **[CPython GitHub Issues](https://github.com/python/cpython/issues)** page. Please carefully read their contribution guidelines and fill out their issue template completely.

**Optional:** Mentioning that the bug was found using the `lafleur` fuzzer can be helpful context for the CPython developers.

Thank you for reading this far! :)
