# Configuration & Build instructions for mdb

Requirements:

- Python
- CMake
- Clang or GCC

MDB uses a custom build tool: `mdbuild` which can be called from the root directory of mdb.

## Optional configure step

By running `mdbuild autocomplete` you can get autocompletion in bash, by running the command and then `source autocomplete.sh`.

To build mdb, first dependencies must be downloaded.

### Downloading Dependencies

```bash
mdbuild dev-setup
```

This will download the 3rd party dependencies needed to build mdb.

- zydis - disassembler library
- quickjs - javascript engine that mdb uses for scripting features
- googletest - testing library

These will be downloaded to `/dependencies` folder.

### Configure build root

When dependencies are met, configure what you want the build root to be, for debug / release builds. This is an example:

```bash
mdbuild configure-buildroot build-root
```

Will create a directory `build-root` inside the root directory where `debug/` and `release/` builds will be. There are 4 handpicked build versions, `debug`, `release`, `fulldebug`, `fullrelease`.

Configure a debug build:

```bash
mdbuild configure debug
```

Configure a release build:

```bash
mdbuild configure release
```

These map to `CMAKE_BUILD_TYPE=<Debug | Release>`.

Then build the configurations via the command

```bash
mdbuild build debug
mdbuild build release
```

There's a quick hand `mdbuild build` that will build the "selected" configuration. You can specify the selected configuration with the command

```bash
mdbuild select debug
```

Current build system state can be found in the file `build_meta.json` in the root directory.
