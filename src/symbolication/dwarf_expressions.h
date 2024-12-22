#pragma once
#include "../common.h"
#include "dwarf_binary_reader.h"
#include "dwarf_defs.h"
#include "tracee_pointer.h"
#include "utils/immutable.h"

class TraceeController;
struct TaskInfo;

namespace sym {

namespace dw {
class FrameBaseExpression
{
  Immutable<std::span<const u8>> bytecode;

public:
  constexpr explicit FrameBaseExpression(std::span<const u8> byteCode) noexcept : bytecode(byteCode) {}

  static constexpr FrameBaseExpression
  Empty() noexcept
  {
    return FrameBaseExpression{{}};
  }

  static constexpr FrameBaseExpression
  Take(std::optional<std::span<const u8>> byteCode) noexcept
  {
    return FrameBaseExpression{byteCode.value_or(std::span<const u8>{})};
  }

  std::span<const u8>
  GetExpression() const noexcept
  {
    return bytecode;
  }

  constexpr bool
  HasExpression() const noexcept
  {
    return !bytecode->empty();
  }
};
} // namespace dw

struct UnwindInfo;

struct StackValue
{
  bool is_signed;
  union
  {
    u64 u;
    i64 i;
  };
};

struct DwarfStack
{
  DwarfStack() = default;
  ~DwarfStack() = default;

  template <std::integral T>
  void
  Push(T t) noexcept
  {
    ASSERT(mStackSize < mStack.size(), "Attempting to push value to stack when it's full");
    mStack[mStackSize] = static_cast<u64>(t);
    ++mStackSize;
  }
  u64 Pop() noexcept;
  void Dup() noexcept;
  void Rotate() noexcept;
  void Copy(u8 index) noexcept;
  void Swap() noexcept;

  u16 mStackSize;
  std::array<u64, 1028> mStack;
};

// The byte code interpreter needs all state set up, so that any possibly data it reference during execution, is
// already "there".
struct ExprByteCodeInterpreter
{
  explicit ExprByteCodeInterpreter(int frameLevel, TraceeController &tc, TaskInfo &t,
                                   std::span<const u8> byteStream) noexcept;
  explicit ExprByteCodeInterpreter(int frameLevel, TraceeController &tc, TaskInfo &t,
                                   std::span<const u8> byteStream, std::span<const u8> frameBaseCode) noexcept;
  AddrPtr ComputeFrameBase() noexcept;
  // Read contents of register, at frame level `mFrameLevel` - if registers hasn't been unwound, or if that register
  // for some reason could not be determined, returns nullopt.
  std::optional<u64> GetRegister(u64 number);

  u64 Run() noexcept;

  int mFrameLevel;
  DwarfStack mStack;
  DwarfOp mLatestDecoded;
  TraceeController &mTraceeController;
  TaskInfo &mTask;
  std::span<const u8> mByteStream;
  std::span<const u8> mFrameBaseProgram;
  DwarfBinaryReader mReader;
};

using Op = void (*)(ExprByteCodeInterpreter &);

} // namespace sym
