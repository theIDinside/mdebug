## Terminology

### Tracee controller

### Stops

There are many kinds of stops that happen during a debug-session. From a low-versus-high level perspective, we have what ptrace refers to signal-delivery-stops and ptrace-stops, but when thinking about the domain of the debugger in it's entirety, we have user-stops and tracer-stops.

### Low Level stops

`ptrace` defines a few different kind of stops, of which it names `ptrace-stops` - `signal-delivery-stops`, `group-stops`, `PTRACE_EVENT-stops` and `syscall-stops`.

Let's begin by reading what the manpages say of `signal-delivery-stops`:

```
  Signal-delivery-stop
       When  a  (possibly  multithreaded) process receives any signal except SIGKILL,
       the kernel selects an arbitrary thread which handles the signal.  (If the sig‐
       nal  is generated with tgkill(2), the target thread can be explicitly selected
       by the caller.)  If the selected thread is traced, it enters  signal-delivery-
       stop.   At this point, the signal is not yet delivered to the process, and can
       be suppressed by the tracer.  If the tracer doesn't suppress  the  signal,  it
       passes the signal to the tracee in the next ptrace restart request.  This sec‐
       ond step of signal delivery is called signal injection in  this  manual  page.
       Note  that if the signal is blocked, signal-delivery-stop doesn't happen until
       the signal is unblocked, with  the  usual  exception  that  SIGSTOP  can't  be
       blocked.

       Signal-delivery-stop  is  observed  by the tracer as waitpid(2) returning with
       WIFSTOPPED(status) true, with the signal returned by WSTOPSIG(status).  If the
       signal  is  SIGTRAP,  this  may  be  a  different kind of ptrace-stop; see the
       "Syscall-stops" and "execve" sections below for details.  If  WSTOPSIG(status)
       returns a stopping signal, this may be a group-stop; see below.
```

### Debugger stops

There are 2 different kind of "debugger stops";

#### User stops

User stops occur when we hit a breakpoint, for instance. It's a kind of stop that is reported to the user at which point she or he can do something. It means that a thread or the entire tracee process has stopped.

#### Tracer stops

These are the kinds of stops that are _invisble_ to the user. An example of such a stop probably is best, to describe what that entails:

Let's say the user issues a `next line` requests/command. We might at some point during the execution of that command, set a breakpoint at a resume address, so that we can optimize our stepping (not having to single step all the way, but instead let the tracee continue at full speed). When this temporary breakpoint is hit, we have no will to let the user know that this breakpoint has been hit; this is a tracer-stop. Because from the perspective of the debugger, the _tracee_ has stopped, but we're not informing the user of that. In this example, we would only inform the user once we've actually _stopped at the next line_ - at which point _that_ would be a user stop.
