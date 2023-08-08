## Todos

- [ ] Optimize call stack caching and building
- [ ] Optimize (backwards) disassembly. For simplicity we do a _bunch_ of copying and throwing away. This might be ok in the long run, it might not. How often do we disassemble backwards? Not much. If we're talking about sub-second responses for a few thousand instructions (backwards, forwards is _always_ extremely fast), it's fine.
- [ ] Write unwind tests and a host of other tests, that involve performing some functionality, when the pc is inside a shared object
