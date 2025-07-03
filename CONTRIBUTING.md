# Contributing

You are encouraged to contribute to the repository by **forking and submitting a pull request**.

For significant changes, please open an issue first to discuss the proposed changes to avoid re-work.

(If you are new to GitHub, you might start with a [basic tutorial](https://help.github.com/articles/set-up-git) and check out a more detailed guide to [pull requests](https://help.github.com/articles/using-pull-requests/).)

Pull requests will be evaluated by the repository guardians on a schedule and if deemed beneficial will be committed to the `main` branch. Pull requests should have a descriptive name, include a summary of all changes made in the pull request description, and include unit tests that provide good coverage of the feature or fix. A Continuous Integration (CI) pipeline is executed on all PRs before review and contributors are expected to address all CI issues identified ([except as noted below](#notes-on-actions)). Where appropriate, PRs that impact the end-user and developer demos in the repo should include updates or extensions to those demos to cover the new capabilities.

If you would like to propose a significant change, please open an issue first to discuss the work with the community.

Contributions are made pursuant to the Developer's Certificate of Origin, available at [https://developercertificate.org](https://developercertificate.org), and licensed under the Apache License, version 2.0 (Apache-2.0).

## Development Tools

### Pre-commit

A configuration for [pre-commit](https://pre-commit.com/) is included in this repository. This is an optional tool to help contributors commit code that follows the formatting requirements enforced by the CI pipeline. Additionally, it can be used to help contributors write descriptive commit messages that can be parsed by changelog generators.

On each commit, pre-commit hooks will run that verify the committed code complies and formats with ruff. To install the ruff checks:

```bash
pre-commit install
```

To install the commit message linter:

```bash
pre-commit install --hook-type commit-msg
```

## Notes on Actions

### Type checking: Ty and Pyright

Type checking is performed automatically on pull requests using both [Ty][ty] and [Pyright][pyright].

[ty]: https://github.com/astral-sh/ty
[pyright]: https://github.com/microsoft/pyright

Ty is a new type checker developed by Astral. It is currently in alpha. We check the codebase with ty and expect there to be complaints for now. PRs with a failing check from ty do not necessarily require attention if type checking with Pyright passes.

Our strategy for type checking is "gradual;" failing type checks or using casts, Any, `type: ignore`, etc. are not deal breakers. But we should strive for keeping a reasonable level of type information to keep the quality of the code high without getting too in the weeds on types.
