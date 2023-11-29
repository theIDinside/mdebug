#pragma once
#include "../common.h"
#include "dwarf_defs.h"
#include <concepts>
#include <stack>

struct TraceeController;
struct TaskInfo;

namespace sym {

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
  push(T t) noexcept
  {
    ASSERT(size < stack.size(), "Attempting to push value to stack when it's full");
    stack[size] = static_cast<u64>(t);
    ++size;
  }
  u64 pop() noexcept;
  void dup() noexcept;
  void rotate() noexcept;
  void copy(u8 index) noexcept;
  void swap() noexcept;

  u16 size;
  std::array<u64, 1028> stack;
};

// The byte code interpreter needs all state set up, so that any possibly data it reference during execution, is
// already "there".
struct ExprByteCodeInterpreter
{
  explicit ExprByteCodeInterpreter(TraceeController *tc, TaskInfo *t, std::span<const u8> byte_stream) noexcept;
  AddrPtr request_frame_base() noexcept;
  u64 run() noexcept;

  DwarfStack stack;
  DwarfOp latest_decoded;
  TraceeController *tc;
  TaskInfo *task;
  std::span<const u8> byte_stream;
  DwarfBinaryReader reader;
};

using Op = void (*)(ExprByteCodeInterpreter &);

} // namespace sym