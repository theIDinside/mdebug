# "Architecture" of the debugger

First thing we need to think about is, what should our design be? This, potentially can be an impossible question to answer when you're in the dark. How could you possibly know, what you don't know?

Debugging has a few concepts; a "tracer" is the actual debugger application and the "tracee" is the application we're debugging.

In debuggers on Linux there are 2 system calls that are crucial concepts:

- `ptrace` - A Linux system call that is the "debugger API". It is with this function we make "tracer requests", like continue, single step, read registers, write to registers and a host of other things.
- `wait/waitpid/waitid` - A system call that "waits" for an event in the tracee. This system call is "blocking", which means if we call (pseudocode) `waitpid(processid)`; we will block until something happens. This is important to remember and is also why we need to think of a way to be [concurrent](#concurrency). We can't just sit around and wait for it to return - what if we want to process some other stuff? Process some data from the `tracer` like it's output? Or input? Or what if we want to process some commands from the user, while we're waiting on a new event?

This means we need the following;
A way to `wait` on events from the `tracee`, a way to process input and output, both from the `tracer user` but also the `tracee`. Both of these need to run in "infinite" loops, which means we also need a way to actually perform "commands" like, interrupt the tracee, read registers.

We need 3 threads. One thread that waits, using the `wait` system calls, one IO thread and one "main" thread.

## Concurrency

The main "execution loop" involves 3 threads. I'm defining "the main execution loop" as what is meant to run for the entire time of the program.

These three threads, are as follows:

- `Tracer Thread`
- `IO Thread`
- `Awaiter Thread`

### `Tracer thread`

The `Tracer thread` performs all the debug info logic. It represents the actions a user can take. It performs the commands that the user requests, it manages the state/meta data of the tracee, it makes all the choices on what to do at any given point in time. It also is responsible for spawning batch job threads - these are threads that parse debug information into a format that MDB wants it in. These are "short lived" tasks and as such are not described here.

### `IO Thread`

The next long-running thread does the obvious thing, it's in the name! It waits for input (and output). It waits for input from the user, in the form of commands and requests, which it processes before sending it to the `Tracer Thread` which then executes the commands. It also waits on output, from the tracee, the program being debugged, so that it can pre-process that and display it properly - this really only is worth thinking about if we're running the DAP UI (which is the only supported UI for now). If we ever created a CLI, then the output would flow from the tracee directly to `MDB`'s stdout. If we wrote a GUI, we would have to also have some pre-processing/routing logic, where the output from the tracee could be moved from it's stdout to the screen in some fashion.

### `Awaiter Thread`

This is the tiniest thread of them all, but it's also in the name what it does. It sits in a loop where it blocks on `waitid` - looking for any changes in any child and once it comes across a change; it notifies the Tracer thread and then blocks, waiting for the Tracer thread to handle those events and then wake the `Awaiter thread` up again. This is because the `Tracer Thread` might perform tasks that actually change the state of the children that's a`waitid` on - we don't want the `Awaiter Thread` to yell at us that there exists events, when we know because we're the reason for those events.

## Inter-thread communication

Finally we need a way to stich these three threads together, so they can communicate to each other in an asynchronous fashion.

For this, we'll use a "polling" API, where we open Linux pipes that we can poll in the main thread and be informed when we need to take an action. That way, the `awaiter thread` can write to the write-end of the pipe, and the IO can write to it's write end of the pipe while the main thread polls it's "read ends" to know when to do things.

The `Tracer Thread`'s main loop becomes something like this:

```c++
  // pseudo-code
  auto timeout = 1000; // 1 second
  while(true) {
    if(poller.do_polling(timeout)) {
      for(auto evt : poller.awaiter_events())
        handle_awaiter_event(evt);

      for(auto evt : poller.io_events())
        handle_io_event(evt);
    }
  }
```

The main thread runs in a continous loop and when the other threads have written, say a byte `+` to the pipe, we are informed of it and process it accordingly. We will need additional synchronization things. We can use `select`, `poll` or `epoll` for polling a file descriptor if it has any data we can read from it. For now, the debugger uses `poll` for simplicity's sake, though `epoll` is probably preferable.

Some more pseudo code:

```c++
// this is in the main thread

auto io_thread = std::thread{[&]() {
  while(true) {
    auto io_events = poll_inputs_and_outputs();
    for(auto evt : io_events) {
      if(evt.is_command()) {
        post_command_to_tracer(evt);
      } else if(evt.is_tracee_output()) {
        write_tracee_output(evt);
      }
    }
  }
}};

auto awaiter_thread = std::thread{[&]() {
  while(true) {
    int stat;
    // blocks
    waitpid(child_process_id, &stat, 0);
    auto processed = process_event(stat);
    post_event_to_tracer(processed);
    // go to sleep, wait until
    // main thread tells us it's ok to block on wait again
    wait_for_tracer_to_notify_us();
  }
}};
```

That's basically the design of the 3 application-lifetime threads.
