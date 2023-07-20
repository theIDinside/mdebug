# Why a debugger?

- [TLDR - repo setup](#tldr)

Why do anything in this world? A simple answer I could give you is - it's fun. But beyond being fun, a debugger involves a bit of different concepts and ideas. It's systems programming, because you will be resorting to doing fancy shmancy syscalls and inspecting the "low level" state of your program - but it's also perfect for hackery to the finest degree. There's a plethora of architectures out there, the amount of edge case handling required is infintely large - but wait, doesn't that mean that the scope is infinite too and therefore completely impossible for one woman or man? This is where our first constraint comes into play.

I'm setting an arbitrary constraint of x86_64 and Linux. It leaves enough complexity on the table to deal with - and also, loosening that constraint later on is perfectly doable.

What other constraints should the project have? I'd like to keep it as loose as possible and write most of it ourselves. So what does that say for 3rd party libraries?

For this to be fun, it has to be kept to a minimum. Besides, I've seen some projects for chat applications, where the amount of dependencies are staggering, for applications that more or less are a solved problem. If they can do funny things, so can we, we just do it in the other direction.

I'm allowing the project to begin with at most 2 dependencies - one, because it's just _so_ amazing from a C++ perspective. If you have a bit of experience using C++, I think you should probably be able to guess which one it is and that's [`libfmt`](https://fmt.dev/latest/index.html) - C++, welcome to the 21st century. The second dependency is an arbitrary JSON library, for now it'll be [`nlohmann_json`](https://json.nlohmann.me/). Why? We'll get to that later.

So where would someone who knows next to nothing about debuggers start? What features are needed? What exactly does a debugger do? We know they set some breakpoints, step through some code. If we only had some guiding spec, that we could emulate or fulfill. Aha!

# Debug Specifications

The [Debug Adapter Protocol (DAP)](https://microsoft.github.io/debug-adapter-protocol/overview) follows recent years developement, mimicking
the idea of the LSP. It describes a certain set of generic operations and events and aims to make it easier to re-use debuggers in different environment and IDE's.

With this spec - and I'm leaving out any criticism about it, I've heard both positive and negative - we more or less get a "to do" list to work with. Beautiful. Too much planning can kill the fun.

Secondly, we will have to parse the program somehow, understand what functions exist in it, types, so on and so forth. Here's a 2nd constraint - I will only support [DWARF](https://dwarfstd.org/), which is a specification for debug info. This will be a bit more difficult to handle - and I don't know the full ins and outs of it, I don't think anybody really does. But we won't be pulling in 3rd party libraries to deal with it, because again, that would go against the idea of this project - that we can write software, even if it turns out less good than what some expert somewhere else wrote, in a reasonable amount of time.

## TLDR Repo Setup

We need to start with some project setup. We want niceties like `clang-format`, `cmake`, `ctest`. We want repo-cloners to be able to get the ball rolling as fast as possible. Since we don't have many dependencies (2 in total, 1 additional "dev dependency"), let's write some bash!

We need the bash script to do a few things;

- Download a specific release of the dependencies from their github pages
- Unzip that download to a directory in the source tree
- Clean up things we don't want

Also, we don't want to download stuff we've already setup. That would be annoying. As such, we write [this bash script](../configure-dev.sh). It should be fairly simple to understand; we check if the dependencies exist, if they don't, we download using `wget`, `unzip` and remove the zip files. Done!

Finally we check if `clang-format` exists on the system and tell the user to go install that (like, why have you NOT already installed it!? You're crazy!). We'll also copy something call [`pre-commit`](../setup/pre-commit) into `path/to/reporoot/.git/hooks` - this is a bash script that executes every time we try to commit something, even just locally - and run `clang-format` on it, to see if it follows the clang-format config we've set up. This way, we will never again commit poorly formatted code. It all just looks uniform and nice.

Now, a user can be inside the repo root directory and say

```bash
$ ./configure-dev.sh
```

And it will perform the setup of the dependencies we need. No package managers here! And since we've decided to use as little 3rd party deps as possible, this becomes trivial to manage.
