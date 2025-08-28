#include "deserialization.h"

namespace mdb {
u8
fromhex(char a) noexcept
{
  if (a >= '0' && a <= '9') {
    return a - '0';
  } else if (a >= 'a' && a <= 'f') {
    return a - 'a' + 10;
  } else if (a == 'x') {
    return 0;
  } else {
    MDB_ASSERT(false, "unexpected character");
    return 0;
  }
}
} // namespace mdb