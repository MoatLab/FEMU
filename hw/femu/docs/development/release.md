# Releases

A FEMU release is an annotated, signed git tag on `master`, plus a GitHub
release whose notes come from [the changelog](../CHANGELOG.md). Tags are
named `femu-v<QEMU base>` with a FEMU patch number, for example
`femu-v9.0.1`.

```
 master green --> checklist --> CHANGELOG section --> signed tag --> GitHub release
                                                          |
                                        manual PDF, website, README badge follow
```

## Checklist

Do the steps in this order. Stop at the first step that fails.

1. Confirm that the CI workflow passed on the `master` commit you tag.
2. Confirm that the guest boot test passed on that commit in CI.
3. Run `make -C hw/femu/tests check` and the qtests on that commit.
4. Rename `## Unreleased` in `hw/femu/docs/CHANGELOG.md` to the tag name and date.
5. Update the commit count and the date range under that heading.
6. Add a new empty `## Unreleased (since <tag>)` section above it.
7. Commit the changelog and push it; wait for CI to pass again.
8. Create the tag: `git tag -s <tag> -m "FEMU <tag>"` on that commit.
9. Push the tag: `git push origin <tag>`.
10. Create the GitHub release from the tag; paste the changelog section as the notes.
11. Attach `hw/femu/docs/femu-manual.pdf` to the release.
12. Check that the README version badge shows the new tag.

## What a release promises

- Every property in [the property reference](../reference/properties.md)
  keeps its name and meaning until a release notes its removal.
- A removed or renamed property is listed in
  [configuration changes](../CONFIGURATION-CHANGES.md) first.
- Test-only properties (`x-` prefix under qtest) carry no promise.

## Related pages

- [Changelog](../CHANGELOG.md)
- [Testing](../guides/testing.md)
- [Keeping the documentation correct](docs-maintenance.md)
