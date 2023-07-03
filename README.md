# Midas Debugger
A simpler, easier debugger - for x86-64 Linux only.

In no way shape or form does this project claim to be better or attempt to be better than any other debuggers. See it more like a project attempting to be like SerenityOS - a learning experience, building a reasonably complex tool/system. I welcome ALL to work on Midas Debugger.

# Contribute & Develop Midas
Set up dev environment using configure-dev.sh. It sets up the required tools and pulls in the dependencies required to build this project, sets up commit pre-hooks and verifies that the required tools can be found on $PATH.

The script can be executed from wherever, but it's recommended to be executed from inside the repo root dir.

```bash
$ ./configure-dev.sh
```

Current dependencies
- libfmt version 10.0.0