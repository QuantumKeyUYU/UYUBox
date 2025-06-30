# Contributing

We welcome patches and bug reports. Before opening a pull request please
read the guidelines below.

## Linting
Run `pre-commit run --all-files` which executes `black`, `ruff`, `isort`
and `mypy`.

## Testing
Use `pytest` to run the test suite. Tests must pass before your change
is reviewed.

## Commits
Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
style for commit messages.

## Pull Requests
Open a PR against the `main` branch. At least one reviewer must approve
before merge.
