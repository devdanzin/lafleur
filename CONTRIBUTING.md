# Contributing to lafleur

We welcome all sorts of contributions to `lafleur`! Thank you for your interest in helping improve the fuzzer.

We hope to make this a good project to contribute to by welcoming new contributors and giving you voice, space, tools and guidance to improve while you help us.

## Getting Started

Before you begin, please review our developer documentation, which provides a complete guide to the project's architecture and setup process:

- **[Developer Documentation](./doc/dev/00_index.md)**

## Addressing lafleur Open Issues and Feature Requests

A great way to contribute to `lafleur` is triaging and/or tackling already reported bugs or feature requests. Simply reading the existing issues and commenting or asking for clarifications can be a lot of help.

Trying to reproduce bugs (that is, making sure the bug happens when you follow the instructions in the issue) is a great help, be sure to report your success or failure in the corresponding issue.

If you are a beginner at either contributing to GitHub or to Python projects, we try to have issues tagged `good-first-issue` and will help you pick an issue, understand it, create a PR, improve it and land your contribution.

## Filing lafleur Issues

If you've found a bug or have an idea for a new feature in `lafleur`, please check our **[Issues Page](https://github.com/devdanzin/lafleur/issues)** to see if it has already been reported.

When filing a bug report, please include:
1. The crashing, diverging or latest test case (`.py` file), if any.
2. The full, latest log file (`.log`) from the `logs/` directory.
3. The commit hash of the CPython version you are fuzzing (you can paste the output of `python -VV`).

## Filing CPython Issues

If your fuzzing runs resulted in valuable crashes (like segmentation faults, aborts, or actual divergences), the correct path is to file an issue in the CPython tracker instead: you've found a bug **in** CPython **using** `lafleur`.

Before you submit a CPython issue, you should make sure it's a real bug and not a false positive (as most recorded crashes are). Feel free to ask for help triaging your suspected bug in [Python's Discourse](https://discuss.python.org/).

Please carefully read the CPython's project contributions guidelines and fill the issue template with all necessary information when creating a new issue. 

## Code Style

This project tries to follow the **PEP 8** style guide as enforced by `ruff format` with our configurations. Please ensure your code is formatted accordingly when submitting a pull request.

We strive to have readable, logically organized code. We welcome contributions that improve the code in that regard, either by changing code or improving tooling.

## Submitting Changes (Pull Requests)

Once you have a change that you'd like to contribute, please follow this process:

1.  Fork the `lafleur` repository to your own GitHub account.
2.  Create a new branch for your changes (e.g., `git checkout -b feature/my-new-mutator`).
3.  Make your changes and commit them with a clear commit message.
4.  Before submitting, please run the code formatter: `ruff format .`
5.  Push your branch to your fork.
6.  Open a Pull Request from your branch to the `lafleur` `main` branch.

Thank you for reading this far! :)
