# Install, Update, and Uninstall

Repository operations are non-destructive and manifest driven.

- `audit` and `dry-run` do not mutate the repository.
- `install` adds managed files only and preserves conflicts as side-by-side candidates.
- `update` changes only files that still match the prior managed hash.
- `uninstall` removes only unchanged files recorded by the installation manifest.
- user-modified files are preserved.

Installing the Codex plugin is separate from bootstrapping a repository. Plugin installation alone does not enable merge or deployment automation.
