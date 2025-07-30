/** LICENSE TEMPLATE */

// mdb
#include <common/macros.h>

// stdlib
#include <cstdint>

// system
#include <sys/user.h>
namespace mdb {

enum class ThreadEventType
{
};

class ThreadUserRegisters
{
  static constexpr auto REGISTER_BLOCK_SIZE = PAGE_SIZE;
  // How many bytes of `mRegisterBlock` we will be using for this thread.
  std::uint32_t mRegisterBlockSize;
  std::array<std::byte, REGISTER_BLOCK_SIZE> mRegisterBlock;

public:
  NO_COPY_DEFAULTED_MOVE(ThreadUserRegisters);
  explicit ThreadUserRegisters(std::uint32_t registerBlockSize);
  ~ThreadUserRegisters() = default;
};

class ThreadEvent
{
  // Some targets may provide
  ThreadUserRegisters *mUserRegisters{nullptr};

public:
};
} // namespace mdb