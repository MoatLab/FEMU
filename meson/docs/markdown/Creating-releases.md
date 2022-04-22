---
short-description: Creating releases
...

# Creating releases

In addition to development, almost all projects provide periodical
source releases. These are standalone packages (usually either in
tar or zip format) of the source code. They do not contain any
revision control metadata, only the source code.  Meson provides
a simple way of generating these, with the `meson dist` command.

Meson provides a simple way of generating these. It consists of a
single command *(available since 0.52.0)*:

```sh
meson dist
```

or alternatively (on older Meson versions with `ninja` backend):

```sh
ninja dist
```

This creates a file called `projectname-version.tar.xz` in the build
tree subdirectory `meson-dist`. This archive contains the full
contents of the latest commit in revision control including all the
submodules (recursively). All revision control metadata is removed.
Meson then takes this archive and tests that it works by doing a full
`compile` + `test` + `install` cycle. If all these pass, Meson will
then create a `SHA-256` checksum file next to the archive.


## Autotools dist VS Meson dist

Meson behaviour is different from Autotools. The Autotools "dist"
target packages up the current source tree. Meson packages the latest
revision control commit. The reason for this is that it prevents
developers from doing accidental releases where the distributed
archive does not match any commit in revision control (especially the
one tagged for the release).


## Include subprojects in your release

The `meson dist` command has `--include-subprojects` command line
option. When enabled, the source tree of all subprojects used by the
current build will also be included in the final tarball. This is
useful to distribute self contained tarball that can be built offline
(i.e. `--wrap-mode=nodownload`).


## Skip build and test with `--no-tests`

The `meson dist` command has a `--no-tests` option to skip build and
tests steps of generated packages. It can be used to not waste time
for example when done in CI that already does its own testing.

So with `--no-tests` you can tell Meson "Do not build and test generated
packages.".

## Release a subproject separately

*Since 0.57.0* the `meson dist` command can now create a distribution tarball
for a subproject in the same git repository as the main project. This can be
useful if parts of the project (e.g. libraries) can be built and distributed
separately. In that case they can be moved into `subprojects/mysub` and running
`meson dist` in that directory will now create a tarball containing only the
source code from that subdir and not the rest of the main project or other
subprojects.

For example:
```sh
git clone https://github.com/myproject
cd myproject/subprojects/mysubproject
meson builddir
meson dist -C builddir
```
This produces `builddir/meson-dist/mysubproject-1.0.tar.xz` tarball.
