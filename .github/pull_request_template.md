<!--
PR title must follow Conventional Commits, e.g. `feat: add --exclude-namespace flag` or
`fix(scanner): skip namespaces the user may not list`. It becomes the squash commit and
the changelog entry.
-->

## Summary

<!-- What does this change and why? -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change (`!` in the title or a `BREAKING CHANGE:` footer)
- [ ] Docs / chore / CI

## How was it tested?

<!-- Commands you ran, new tests, cluster you tried it on (redacted). -->

## Checklist

- [ ] Tests added or updated, and `pytest` passes locally
- [ ] `ruff check` and `ruff format --check` pass
- [ ] Docs updated where behavior changed
- [ ] Cluster access stays read-only, and credentials are never written to SQLite or logs
- [ ] No secrets, kubeconfigs, internal hostnames or real cluster data in code, fixtures or screenshots
