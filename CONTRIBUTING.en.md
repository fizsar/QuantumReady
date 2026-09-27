# Development conventions

[Español](CONTRIBUTING.md) · **English** · [← Back to the README](README.en.md)

The project's conventions and the lessons they came from.

## A failure in a command chain must block the commit

When chaining commands that must prevent a commit if something fails (for
example, running the tests before `git commit`), always use
`set -o pipefail` in bash:

```bash
set -o pipefail
python -m pytest -q 2>&1 | tail -1 && git commit -m "..."
```

Without `set -o pipefail`, a pipeline returns the exit code of its **last**
command. In `pytest ... | tail -1 && git commit`, that command is `tail`,
which almost always exits with 0, so the commit goes through even when the
tests have failed.

**How it was found:** a `pytest -q | tail -1 && git commit` chain let through
a commit with a broken test (`1 failed, 392 passed`), because the exit code
reaching the `&&` was `tail`'s, not `pytest`'s. With the fix
(`set -o pipefail; pytest -q | tail -1 && git commit`), a test commit under the
same conditions, with a deliberately broken test, was blocked: the chain exited
with code 1 and no commit was created.
