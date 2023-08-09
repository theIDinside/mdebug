# Midas Debugger

### Contents

- [Testing & Tests](#testing--tests)
  - [How to use & write driver tests](#how-to-use--write-driver-tests)
    - [Adding a new sub-suite](#adding-a-new-sub-suite)
    - [Adding a test to existing sub-suite](#adding-a-test-to-existing-sub-suite)
- [Contribute & Develop Midas](#contribute--develop-midas)
  - [Dependencies](#dependencies)
  - [Dev-dependencies](#dev-dependencies)
- [WIP (possible) blog posts](#current-blog-posts-that-describes-mdb)

A simple, easy debugger - for x86-64 Linux only. Do you want to learn how to write a debugger in Linux? Come along for the journey!

In no way shape or form does this project claim to be better or attempt to be better than any other debuggers. See it more like a project attempting to be like SerenityOS - a learning experience, building a reasonably complex tool/system.

Some mission goals with this debugger, at least at this point in time.

- Only support the DWARF debug information (and of that a subset only, namely versions >= 4)
- Use >= C++20 features.
- Massive fine-wine hackery. Experiment with everything. Produce bad code, to understand how to produce good code. And even if we never do, we've learned something at the end of the day. Break C++ rules. Write undefined behaviors, cross all boundaries. Experiment with platform specific functionality (SIMD? AVX/2? Yes! All of it! Unfortunately I'm not on a platform that supports AVX-512 though).

# Testing & Tests

Midas Debugger uses multiple kinds of tests. Google test for unit testing individual parts of the system and CMake's built in `ctest` functionality, for the "driver tests". These tests mimicks the real behavior of a DA-extension in VSCode. They are found in the [test/driver](./test/driver/) folder; and they are set in the CMake file as `DRIVER_TESTS`. What's neat about ctest is that it takes an executable and if it exits with a 0 code it's passed, otherwise it failed. This is extremely flexible and makes it possible for Midas to use whatever is suitable, Python, NodeJs (in this case, but we could just use Python) or anything else for that matter. We could use Tcl+expect too, but I am not a sadist.

## How to use & write driver tests

The driver tests contains sub-suites meant to test some functionality in the debugger. Each sub-suite might contain several tests, meant to test different kind of states the tracee might be in. Look to [stackframes.js](./test/driver/stackframes.js) for examples.

### Adding a new sub-suite

- Add a `test.js` (named suitably) to [`/test/drivers`](./test/driver/)
- Write the test logic. Each sub test should be a separate function and a name. These function<->name pairs must be exported as a JS object, like what is done in [stackframes.js](./test/driver/stackframes.js#L194) and passed to `runTestSuite` a function defined in [client.js](./test/driver/client.js#L450).
- In [`CMakeLists.txt`](./CMakeLists.txt) inside the `if(NODEJS)` add the sub-suite name (which must be named the same as the file name, but without the file extension) to the `DRIVER_TEST_SUITES` list and then also define a new variable with the same name as the name added to `DRIVER_TEST_SUITES`. This variable is supposed to hold all names of the sub-tests.

Now the test should be executed when `ctest` is executed from the build folder. But it's subtests should also be executable, stand alone, by saying `ctest -R <subSuiteName>.<subTestName>` (if the sub test name is unique, all you have to do is type `ctest -R <subTestName>` - without the <> of course)

### Adding a test to existing sub-suite

- Write the test logic in the file where the test logically fits
- Add it to the name-to-function pair inside the `tests` object, see [stackframes.js](./test/driver/stackframes.js#L194) for example
- In [`CMakeLists.txt`](./CMakeLists.txt) find the variable named the same as the test you've added it to, and add the test name to the list of tests of that sub-suite (see the stackframes variable, for example on how to do it)

Now the test will be executed with the `ctest` command (for individual test-execution see [Adding a new sub-suite](#adding-a-new-sub-suite))

# Contribute & Develop Midas

Set up dev environment using configure-dev.sh. It sets up the required tools and pulls in the dependencies required to build this project, sets up commit pre-hooks and verifies that the required tools can be found on $PATH.

The script can be executed from wherever, but it's recommended to be executed from inside the repo root dir.

```bash
$ ./configure-dev.sh
```

It does the following

- libfmt (c++ formatting library, which std::format et all is being modelled after)
- nlohmann_json (json library)
- zydis (disassembler library)
- installs commit pre-hook, to verify that all code is formatted before pushing
- verifies that `clang-format` is installed on `$PATH` (but does not install it, you have to do that)

## Dependencies

Current dependencies

- libfmt version 10.0.0
- nlohmann_json version 3.11.2
- zydis

Justification for these three libraries are as follows;

- `libfmt` is the best thing that ever happened to C++. Finally C++ can join the 21st century. An added bonus is also that it's a fast library and easy to use. With the right tweaks, it compiles down to what looks like C printf's (according to their documentation). That's pretty awesome.
- `nlohmann_json` because we don't want to parse json ourselves. It's not fun. The particular choice for parsing JSON may change, as nlohmann*json might not fulfill MDB's requirements, because it \_seems* as though it only operates on JSON Lines. We parse JSON that come with a header (defining the length of the json object) - if there's a library that can take this into account, we will use that instead.
- `zydis` - because I don't know how to disassemble yet and being able to perform this task is crucial for a debugger. We'll cross that bridge when we have solved everything else, though. It's the only "debug related" dependency we will be using though, so we can pat ourselves on our back for that.

### Dev-dependencies

- gtest - for unit testing.
- clang-format (required)

#### Coding guidelines

Few of these for now.

1. clang-format it all. Write it however you want it and let clang-format do the rest.

2. Keep implementations of interface methods linearly placed in source files. If A is an abstract class with 3 virtual methods, and B and C implement those, group the method _definitions_ together in the `.cpp` file. This might seem strange to some, but I prefer it. My general sense is, an interface often have only slightly different behaviors - and even if they do, their overriden methods are used in the same contexts. Some times they might even resembled one another. Therefore having them close, a sort of spatial locality in the source code is benefitial - it's quick and easy to compare multiple different implementations. Below is an example:

```cpp
struct A { virtual void foo() = 0; virtual void bar() = 0; };
struct B : A ...
struct C : A ...
// in cpp file

// group all `foo`s together
void B::foo() { }
void C::foo() {}
// group all `bar`s together
void B::bar() {}
void C::bar() {}
```

# Current blog posts that describes MDB

These blog posts are not done, but I write some in them during the dev cycles to build a cohesive explanation of what's going on and where.

- [Why a debugger?](./blog/why_debugger.md)
- ["Architecture" of the debugger](./blog/architecture.md)
- [Command System](./blog/commands_system.md)
- [Driver tests](./blog/driver_tests.md)
- [Elves and dwarves](./blog/elves_and_dwarves.md)
