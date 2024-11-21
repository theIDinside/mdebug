#pragma once
#include "../common.h"
#include "dwarf_binary_reader.h"
#include "dwarf_defs.h"
#include "utils/immutable.h"

class TraceeController;
struct TaskInfo;

namespace sym {

namespace dw {
class FrameBaseExpression
{
  Immutable<std::span<const u8>> bytecode;

public:
  constexpr explicit FrameBaseExpression(std::span<const u8> expr_bytecode) noexcept : bytecode(expr_bytecode) {}

  static constexpr FrameBaseExpression
  Empty() noexcept
  {
    return FrameBaseExpression{{}};
  }

  static constexpr FrameBaseExpression
  Take(std::optional<std::span<const u8>> maybe_expr_bytecode) noexcept
  {
    return FrameBaseExpression{maybe_expr_bytecode.value_or(std::span<const u8>{})};
  }

  std::span<const u8>
  get_expression() const noexcept
  {
    return bytecode;
  }

  constexpr bool
  has_expression() const noexcept
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
  explicit ExprByteCodeInterpreter(int frame_level, TraceeController &tc, TaskInfo &t,
                                   std::span<const u8> byte_stream) noexcept;
  explicit ExprByteCodeInterpreter(int frame_level, TraceeController &tc, TaskInfo &t,
                                   std::span<const u8> byte_stream, std::span<const u8> frameBaseCode) noexcept;
  AddrPtr request_frame_base() noexcept;
  u64 run() noexcept;

  int frame_level;
  DwarfStack stack;
  DwarfOp latest_decoded;
  TraceeController &tc;
  TaskInfo &task;
  std::span<const u8> byte_stream;
  std::span<const u8> mFrameBaseProgram;
  DwarfBinaryReader reader;
};

using Op = void (*)(ExprByteCodeInterpreter &);

} // namespace sym
