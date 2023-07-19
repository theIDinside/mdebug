# Midas Debugger
A simpler, easier debugger - for x86-64 Linux only.

In no way shape or form does this project claim to be better or attempt to be better than any other debuggers. See it more like a project attempting to be like SerenityOS - a learning experience, building a reasonably complex tool/system. I welcome ALL to work on Midas Debugger.

TWo "simple" stated goals, at least at this point in time.

- Only support the DWARF debug information (and of that subset, only support version >= 4)
- Only use >= C++20 features.

## Testing & Tests
Midas Debugger uses multiple kinds of tests. Google test for unit testing individual parts of the system and CMake's built in `ctest` functionality, for the "driver tests". These tests mimicks the real behavior of a DA-extension in VSCode. They are found in the [test/driver](./test/driver/) folder; and they are set in the CMake file as `DRIVER_TESTS`. What's neat about ctest is that it takes an executable and if it exits with a 0 code it's passed, otherwise it failed. This is extremely flexible and makes it possible for Midas to use whatever is suitable, Python, NodeJs (in this case, but we could just use Python) or anything else for that matter. We could use Tcl+expect too, but I am not a sadist.

# Contribute & Develop Midas
Set up dev environment using configure-dev.sh. It sets up the required tools and pulls in the dependencies required to build this project, sets up commit pre-hooks and verifies that the required tools can be found on $PATH.

The script can be executed from wherever, but it's recommended to be executed from inside the repo root dir.

```bash
$ ./configure-dev.sh
```

Current dependencies
- libfmt version 10.0.0
- nlohmann_json version 3.11.2
- gtest 

Justification for these three libraries are as follows;
- libfmt is the best thing that ever happened to C++. Finally C++ can join the 21st century. An added bonus is also that it's a fast library and easy to use. With the right tweaks, it compiles down to what looks like C printf's. Fantastic.
- nlohmann_json because we don't want to parse json ourselves. It's not fun. The particular choice for parsing JSON may change, as nlohmann_json might not fulfill MDB's requirements, because it *seems* as though it only operates on JSON Lines. We parse JSON that come with a header (defining the length of the json object) - if there's a library that can take this into account, we will use that instead.
- gtest - for unit testing. Which is absolutely needed when we, for instance, want to parse JSON objects from a raw stream of bytes.

# Current blog posts that describes MDB 
These blog posts are not done, but I write some in them during the dev cycles to build a cohesive explanation of what's going on and where.

- [Command System](./blog/commands_system.md)
- [Concurrency](./blog/concurrency.md)