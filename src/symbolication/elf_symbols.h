#pragma once
#include "../common.h"
#include <string_view>
/**
 * Parsing & Decoding minimalistic symbols found in the elf symtable (.symtab)
 * These are generally not particularly useful, unless of course you're doing some hacking stuff,
 * where it can be very useful. But normal, everyday fixing the stupid mistakes you introduce into your code?
 * Not so much.
 */

struct MinSymbol
{
  std::string_view name;
  TPtr<void> address;
  u64 maybe_size;
};