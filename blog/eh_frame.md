# .eh_frame, .eh_frame_hdr, .debug_frame

This was a doosey. After having google many a hours, a realisation crept into my mind - the documentation either is meant to be as obtuse as possible, so only "smart people" can understand it, or perhaps the documentation was meant as a cruel joke.

It's fairly easy to find blog posts and what not, that describes the stack machine and byte code - as if anybody who knows a bit of programming is going to have a hard time implementing (?) stack based abstract machine. That kind of stuff is literally what we do daily - if this, then do this, if that then do that, if neither, do whatever.

No, the difficult part of these sections is not that. It's the format of said sections. Most of the fields probably make sense to you, but the most important ones - the ones describing addresses in the actual binary - somehow is left out of every blog post, every documentation everywhere.

## .eh_frame

This section contains "Common Information Entries" (CIE) and "Frame Description Entries" (FDE). As usual with DWARF, it performs some custom "compression" - CIE are "common" because they contain data that is _shared_ with multiple FDE. We can also think of CIE as "containing" FDE's, where we prepend the contents of the CIE to each FDE it contains.

Each CIE has the fields:

- length: 4 bytes for 32-bit, 12 bytes for 64-bit (as usual with dwarf, 64-bit contains 4 bytes of padding=`0xff'ff'ff'ff`)
- id: 4 bytes/8 bytes (32/64 bit) represented as an offset into the section
- version - 1 byte
- augmentation string - UTF-8 string containing ABI-vendor-specific meta data
- code alignment factor - unsigned LEB128
- data alignment factor - signed LEB128
- return address register - unsigned LEB128
- array of instructions (bytes, "byte code")
