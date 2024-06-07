## Why a new remote protocol?

Because the remote "protocol" that GDB defines, can hardly be called a protocol. It's also exclusively designed for _remote stubs_ (obviously - competition for the front end wouldn't be... good, right?)

## Design goals

- An fully asynchronous and stateless protocol
- Customizable commands and events, beyond the standard core
