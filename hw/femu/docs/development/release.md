# Releases

A FEMU release is a signed, annotated git tag on `master`, plus a GitHub
release whose notes come from [the changelog](../CHANGELOG.md). Tags are
named `femu-v<QEMU base>` with a FEMU patch number, for example
`femu-v9.0.1`.

```
 master green --> changelog section --> records named --> git tag -s --> push tag
                                                                           |
   release-check.yml (reads only): tag, master, CI, signature, notes <-----+
                                                                           |
   maintainer: gh release create --notes-file notes.md <-------------------+
   then the manual PDF, the website and the README badge follow
```

The release itself is a manual step of a maintainer. A tag can point at
a commit that changes a workflow, and that workflow can then ask for
more permissions. So the release check is a report for the maintainer,
and the guard is who can push tags (see below).

## Checklist

Do the steps in this order. Stop at the first step that fails.

1. Confirm that CI passed on the `master` commit you tag, guest boot included.
2. Run `make -C hw/femu/tests check` and the qtests on that commit.
3. Rename `## Unreleased` in `hw/femu/docs/CHANGELOG.md` to `## <tag> (<date>)`.
4. Update the commit count and the date range under that heading.
5. Add an empty `## Unreleased (since <tag>)` section above it.
6. In `reference/interface-changes.list`, replace each `unreleased` with the tag.
7. Commit, push, and wait for CI to pass on that commit.
8. Create the tag on that commit: `git tag -s <tag> -m "FEMU <tag>"`.
9. Check the tag: `git tag -v <tag>`.
10. Push the tag: `git push origin <tag>`.
11. Wait for the Release check workflow; download its `release-notes` artifact.
12. Read `notes.md` and `compat.txt` in the artifact.
13. Create the release: `gh release create <tag> --verify-tag --notes-file notes.md`.
14. Attach the manual: `gh release upload <tag> hw/femu/docs/femu-manual.pdf`.
15. Check that the README release badge shows the new release.

## What the release check does

| Check | Fails when |
| --- | --- |
| Name | the tag is not `femu-vX.Y.Z` |
| Tag object | the tag is lightweight, or its object names another tag |
| Commit | the tag moved, the commit is not on `master`, or the newest CI run of its push to `master` is not green |
| Signature | no key in `allowed-signers` (SSH) or `release-keys.asc` (GPG) on `master` verifies it |
| Notes | the changelog layout is wrong, or the tag has no section |
| Compatibility | a property change since the newest published release before the tag has no record that names the tag |

The key files hold public keys only. A maintainer adds their key there
before their first release.

The checks rely on one repository setting. A tag ruleset must limit who
can create, move and delete `femu-v*` tags to the maintainers who make
releases. Without it, a writer can push a tag whose workflow skips
these checks.

## What a release promises

A `-device` property keeps its name, type, default and kind until a
release notes the change. This covers [the property reference](../reference/properties.md)
and [the runtime reference](../reference/runtime-properties.md).

- `reference/properties.snapshot` is the snapshot of these facts, generated
  from the binary. CI checks that it is current.
- Each change of a property needs one line in
  `reference/interface-changes.list`. A change is a removal, or a new
  type, default or kind. Two changes of one value (20 to 413, then 413
  to 500) need two lines; the check follows the chain.
- `check-property-compat.py` checks each push and each pull request.
- A change no snapshot shows gets a `behavior` line by hand. Examples:
  a computed default, a value range, a removed `mode` name, or a runtime
  property that became read-only.
- Properties named `x-...` and environment variables carry no promise.

```
 commit changes a property --> no record --> CI red
                           --> record    --> CI green --> notes name it
```

## Deprecation

FEMU keeps a deprecated property for the same time as QEMU:

1. A `deprecate` record names the release R that deprecates the property.
2. The property still works in R and in the next minor release (X.Y).
3. Its use prints one warning that names the replacement; a qtest checks it.
4. A `remove` record needs the `deprecate` record of the same property.
5. The removal comes two or more minor releases after R.
6. Patch releases (a new Z in X.Y.Z) do not count.

The release check enforces steps 4 and 5.

## Related pages

- [Changelog](../CHANGELOG.md)
- [Scripts](../reference/scripts.md)
- [Testing](../guides/testing.md)
- [Keeping the documentation correct](docs-maintenance.md)
