## Concurrency

Currently MDB utilizes concurrency in various ways. The main "execution loop" involves 3 threads. I'm defining "the main execution loop" as what is meant to run for the entire time of the program.

These three threads, are as follows:
- `Tracer Thread`
- `IO Thread`
- `Awaiter Thread`

### `Tracer thread`
The `Tracer thread` performs all the debug info logic. It represents the user experience, as it were. It performs the commands that the user requests, it manages the state/meta data of the tracee, it makes all the choices on what to do at any given point in time. It also is responsible for spawning batch job threads - these are threads that parse debug information into a format that MDB wants it in. These are "short lived" tasks and as such are not described here.

### `IO Thread`
The next long-running thread does the obvious thing, it's in the name! It waits for input (and output). It waits for input from the user, in the form of commands and requests, which it processes before sending it to the `Tracer Thread` which then executes the commands. It also waits on output, from the tracee, the program being debugged, so that it can pre-process that and display it properly - this really only is worth thinking about if we're running the DAP UI (which is the only supported UI for now). If we ever created a CLI, then the output would flow from the tracee directly to `MDB`'s stdout. If we wrote a GUI, we would have to also have some pre-processing/routing logic, where the output from the tracee could be moved from it's stdout to the screen in some fashion.

### `Awaiter Thread`
This is the tiniest thread of them all, but it's also in the name what it does. It sits in a loop where it blocks on `waitid` - looking for any changes in any child and once it comes across a change; it notifies the Tracer thread and then blocks, waiting for the Tracer thread to handle those events and then wake the `Awaiter thread` up again. This is because the `Tracer Thread` might perform tasks that actually change the state of the children that's a`waitid` on - we don't want the `Awaiter Thread` to yell at us that there exists events, when we know because we're the reason for those events.