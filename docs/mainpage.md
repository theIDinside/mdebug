# MDB

### Javascript API

#### Breakpoint conditions

Breakpoint conditions can be thought of as a javascript function body. You are handed N number of implicit parameters that you can use directly:

- supervisor
- taskId
- breakpoint

So from your conditional you can say `supervisor.getTask(taskId)`, or `breakpoint.disable()` for instance.
Your breakpoint condition should return one of the enum values in `EventResult`, that's defined on the global `mdb` object

- `mdb.None` - let the debugger take the default action
- `mdb.Resume` - Explicitly resume from this breakpoint and don't stop (which won't inform the UI)
- `mdb.Stop` - Stop.
- `mdb.StopAll` - Stop all tasks in the process. This will configure the supervisor to stop all tasks and once they've all been stopped and collected, then MDB will inform the UI, via a `StoppedEvent`
