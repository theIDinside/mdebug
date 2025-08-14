# Embedding Javascript

MDB embeds a javascript interpreter, so that a user can script custom behavior, tailored to their needs. As such, this part of the debugger will be ever growing
to expose as many features directly as possible, without breaking the core concepts of what the debugger needs to function as a user would expect.

## Contents

- [Previous javascript engine embedding](#previous-javascript-engine-embedding)
- [Introcuce: QuickJS](#introcuce-quickjs)

### Previous javascript engine embedding

My initial embedded engine was Spidermonkey, and it worked. What eventually led me to choosing QuickJs was for many reasons:

- Spidermonkey is not easily built
- It requires over 500mb of space
- In the context of this debugger, introduces a lot of bloat
- Does not work well with newer C++ versions

But beyond the problems, I found myself asking the question;
"Will I really need JIT'ed javascript?" - and the answer I keep coming back to is "No".

If a user of the debugger needs to script a certain kind of behavior, it's probably better to just have an easily embedded and managed interpreter/engine and allow for QuickJs to call into shared objects that the user can write in C/C++ for their truly high performance needs. If the bottlenext becomes javascript, we're doing something wrong, I believe.

### Introcuce: QuickJS

QuickJS is a small engine, and just a couple of C files. It's the kind of design I could only dream of (at this point in my life. It's a journey!). It's small, extremely trivial to build, but it does lack somewhat in documentation.

So what would be one use case for a debugger? Let's say we want to "evaluate some condition" (or rephrased: we want to run some javascript code at some point in time), during breakpoint hits. Let's state some requirements:

- Have some way to "compile" some javascript source code, provided by a user, into a "handle" of some sort
- Execute this "handle" and also passing in some arguments to the function, in this case an argument called `breakpointStatus`, which the user can manipulate to signal what should be the behavior/result of this "condition evalutator"
