# MDB - Linux debugger

## Overview

MDB is a Linux-specific multi-process debugger designed for modern debugging workflows. It supports debugging multiple processes simultaneously and can debug [RR](https://rr-project.org/) traces in multi-process mode, making it ideal for complex debugging scenarios involving process trees and replaying recorded executions.

### Key Features

- **Multi-process debugging**: Debug multiple processes at once with full control over each process
- **RR trace support**: Debug RR traces in multi-process mode for deterministic replay debugging
- **DAP protocol**: Aims for Debug Adapter Protocol (DAP) compliance for editor integration
- **VSCode integration**: Currently requires VSCode/VSCodium with the [Midas extension](https://github.com/theIDinside/midas) for the best debugging experience
- **JavaScript scripting**: Extend and customize debugging behavior with JavaScript (powered by embedded QuickJS)

> **Note**: While MDB strives for DAP compliance, it is not yet fully compliant. Active development is ongoing to improve standards compliance.

## Index

- [Build mdb](#build)
- [Tests](#test-suite)
- [Develop & contribute](#development--contribute)

## Build

#### Required system tools

- A c++ compiler that can compile c++23.
- cmake
- ninja
- wget (to download dependencies with)

Configuring & building mdb is performed using `mdbuild`. It comes with a `help` command.

```bash
$ ./mdbuild help
Type |mdbuild help <command>| for help on individual command.
------------
mdbuild
  help                      -- Display help
  build                     -- Builds a preset
  clean                     -- Clean a build preset directory
  setup                     -- Setup project and download dependencies.
  configure-buildroot       -- Configure root build directory for presets to be placed in.
  configure                 -- Run cmake configure for a preset
  list-presets              -- List the cmake presets of this project.
  select                    -- Set selected build preset.
  autocomplete              -- Generate autocompletion for bash or zsh
```

To configure the dependencies of the project (required) run the command

```bash
./mdbuild setup
```

The dependencies will be downloaded using wget so wget must be installed on your system. Generally comes with most linux distributions by default.

Next, configure the build root, where binary & generated files will be written to.

```bash
./mdbuild configure-buildroot obj
```

This will create the a directory name `obj` in the source directory. You can specify an absolute path as well, outside of the source directory.

To configure one of the presets, like `debug` do:

```bash
./mdbuild configure debug
```

Now you can build using

```bash
./mdbuild build debug
# or
./mdbuild build
```

You can select the "current build" by doing `mdbuild select <type>` and in that way build using the short hand.

### Test suite

TODO

### Development & Contribute

TODO
