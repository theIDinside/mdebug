## Commands System

Midas uses an "Event Queue" as a pattern for how commands (and the output/user interface results they produce) work.

At the top of the food chain, exists two types
- `ui::UICommand`
- `ui::UIResult`

Any UI interface that wants to work with Midas will have to implement a set of `ui::UICommand` and `ui::UIResult` in order to work.
Why all this abstraction and virtual functions and inheritance?

I wanted a system that, in the future can not only have a DAP-interface, but perhaps a command line interface, or possibly even a native-adhoc GUI solution.
For that kind of flexibility, I figured we kind of *have* to go for this kind of design.

Here's a diagram, for what the intention is: ![event queue](./commands%20&%20event%20queue.png)

If we so ever choose to roll a GUI that is native to Midas, we can start poking around in the [`Tracer`](../src/tracer.h) and [`Target`](../src/target.h) code to do that, so we can avoid much of the "in between stuff" as it were. Well, that's what we will do if we implement a "immediate mode" GUI, that every N time units poll Midas for results for what it's displaying. That's for another day though.

Midas has at the time of writing this, 2 long running threads. The `Tracer` thread and the `IOThread` (where the user interface lives, which currently being developed is only the "Debug Adapter Protocol User Interface"). Having two threads like this, requires some form of inter-thread communication. We do this by posting "messages" back and forth. Did the `Tracer` thread see an event, like "we hit a breakpoint" - it posts an event to the IOThread, which pulls it off it's internal message queue and `serialize`s it, so that it can be written to a socket, file or whatever really.


