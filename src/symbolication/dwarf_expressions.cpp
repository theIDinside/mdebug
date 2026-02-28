/** LICENSE TEMPLATE */
#include "dwarf_expressions.h"

// mdb
#include <common.h>
#include <interface/tracee_command/supervisor_state.h>
#include <symbolication/dwarf_frameunwinder.h>
#include <symbolication/objfile.h>
#include <task.h>
#include <utils/todo.h>

// std
#include <utility>

#define DW_OP_TODO(msg, ...)                                                                                      \
  TODO_FMT("objectfile={}, " msg, i.mObjectFile->GetPathString() __VA_OPT__(, ) __VA_ARGS__);

namespace mdb::sym {

u64
DwarfStack::Pop() noexcept
{
  MDB_ASSERT(mStackSize > 0, "Attempting to pop stack with no elements");
  return mStack[--mStackSize];
}

void
DwarfStack::Dup() noexcept
{
  mStack[mStackSize] = mStack[mStackSize - 1];
  ++mStackSize;
}

void
DwarfStack::Rotate() noexcept
{
  std::swap(mStack[mStackSize - 1], mStack[mStackSize - 2]);
  std::swap(mStack[mStackSize - 2], mStack[mStackSize - 3]);
}

void
DwarfStack::Copy(u8 index) noexcept
{
  mStack[mStackSize] = mStack[index];
  ++mStackSize;
}

void
DwarfStack::Swap() noexcept
{
  const auto tmp = mStack[mStackSize - 1];
  mStack[mStackSize - 1] = mStack[mStackSize - 2];
  mStack[mStackSize - 2] = tmp;
}

ExprByteCodeInterpreter::ExprByteCodeInterpreter(int frameLevel,
  tc::SupervisorState &tc,
  TaskInfo &t,
  std::span<const u8> byteStream,
  ObjectFile *objectFile) noexcept
    : mFrameLevel(frameLevel), mStack(), mSupervisor(tc), mTask(t), mByteStream(byteStream),
      mReader(nullptr, byteStream.data(), byteStream.size()), mObjectFile(objectFile)
{
}

ExprByteCodeInterpreter::ExprByteCodeInterpreter(int frameLevel,
  tc::SupervisorState &tc,
  TaskInfo &t,
  std::span<const u8> byteStream,
  std::span<const u8> frameBaseCode,
  ObjectFile *objectFile) noexcept
    : mFrameLevel(frameLevel), mStack(), mSupervisor(tc), mTask(t), mByteStream(byteStream),
      mFrameBaseProgram(frameBaseCode), mReader(this->mByteStream), mObjectFile(objectFile)
{
}

void
ub(ExprByteCodeInterpreter &i) noexcept
{
  PANIC(std::format("UNDEFINED OPCODE 0x{:x}", std::to_underlying(i.mLatestDecoded)));
}

void
op_addr(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadValue<u64>());
}

void
op_literal(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(std::to_underlying(i.mLatestDecoded) - std::to_underlying(DwarfOp::DW_OP_lit0));
}

void
op_reg(ExprByteCodeInterpreter &i) noexcept
{
  const auto bytecode = std::to_underlying(i.mLatestDecoded);
  MDB_ASSERT(
    bytecode >= std::to_underlying(DwarfOp::DW_OP_reg0) && bytecode <= std::to_underlying(DwarfOp::DW_OP_reg31),
    "Byte code for DW_OP_reg<n> out of range");
  const auto reg_no = std::to_underlying(i.mLatestDecoded) - std::to_underlying(DwarfOp::DW_OP_reg0);
  const auto reg_contents = i.GetRegister(reg_no);
  MUST_HOLD(reg_contents.has_value(), "Could not get register value");
  i.mStack.Push<u64>(reg_contents.value());
}

void
op_breg(ExprByteCodeInterpreter &i) noexcept
{
  const auto offset = i.mReader.ReadLeb128<i64>();
  const auto reg_num = std::to_underlying(i.mLatestDecoded) - std::to_underlying(DwarfOp::DW_OP_breg0);
  const auto result = i.GetRegister(reg_num).transform([&](auto v) { return v + offset; });
  MUST_HOLD(result.has_value(), "Could not get register contents");
  i.mStack.Push<u64>(result.value());
}

void
op_deref(ExprByteCodeInterpreter &i) noexcept
{
  const auto v = i.mStack.Pop();
  const TPtr<std::uintptr_t> addr{ v };
  const auto deref = i.mSupervisor.ReadType(addr);
  i.mStack.Push(deref);
}

void
op_deref_size(ExprByteCodeInterpreter &i) noexcept
{
  const auto v = i.mStack.Pop();

  const auto bytes = i.mReader.ReadValue<u8>();
  switch (bytes) {
  case 1: {
    const TPtr<u8> addr{ v };
    const auto deref = i.mSupervisor.ReadType(addr);
    i.mStack.Push<u64>(deref);
  } break;
  case 2: {
    const TPtr<u16> addr{ v };
    const auto deref = i.mSupervisor.ReadType(addr);
    i.mStack.Push<u64>(deref);
  } break;
  case 4: {
    const TPtr<u32> addr{ v };
    const auto deref = i.mSupervisor.ReadType(addr);
    i.mStack.Push<u64>(deref);
  } break;
  case 8: {
    const TPtr<u64> addr{ v };
    const auto deref = i.mSupervisor.ReadType(addr);
    i.mStack.Push<u64>(deref);
  } break;
  }
}
void
op_xderef_size(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_xderef_size not supported yet!");
}

void
op_xderef(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_xderef not supported yet!");
}

void
op_push_object_address(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_push_object_address not yet supported!");
}

void
op_form_tls_address(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_form_tls_address not supported yet!");
}

void
op_const1u(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadValue<u8>());
}
void
op_const1s(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadValue<i8>());
}
void
op_const2u(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadValue<u16>());
}
void
op_const2s(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadValue<i16>());
}
void
op_const4u(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadValue<u32>());
}
void
op_const4s(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadValue<i32>());
}
void
op_const8u(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadValue<u64>());
}
void
op_const8s(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadValue<i64>());
}
void
op_constu(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadUleb128<u64>());
}
void
op_consts(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Push(i.mReader.ReadLeb128<i64>());
}

void
op_dup(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Dup();
}

void
op_drop(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Pop();
}

void
op_over(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Copy(1);
}
void
op_pick(ExprByteCodeInterpreter &i) noexcept
{
  const auto idx = i.mReader.ReadValue<u8>();
  i.mStack.Copy(idx);
}

void
op_swap(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Swap();
}

void
op_rot(ExprByteCodeInterpreter &i) noexcept
{
  i.mStack.Rotate();
}

void
op_abs(ExprByteCodeInterpreter &i) noexcept
{
  const auto v = i.mStack.Pop();
  const auto iv = static_cast<i64>(v);
  const auto abs = std::abs(iv);
  i.mStack.Push(abs);
}
void
op_and(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto result = a & b;
  i.mStack.Push(result);
}
void
op_div(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto ia = static_cast<i64>(a);
  const auto ib = static_cast<i64>(b);
  const auto res = ib / ia;
  i.mStack.Push(res);
}

void
op_minus(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b - a;
  i.mStack.Push(res);
}
void
op_mod(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b % a;
  i.mStack.Push(res);
}
void
op_mul(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b * a;
  i.mStack.Push(res);
}
void
op_neg(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto sa = -static_cast<i64>(a);
  i.mStack.Push(sa);
}
void
op_not(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto res = ~a;
  i.mStack.Push(res);
}
void
op_or(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b | a;
  i.mStack.Push(res);
}
void
op_plus(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b + a;
  i.mStack.Push(res);
}

void
op_plus_uconst(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mReader.ReadUleb128<u64>();
  const auto res = b + a;
  i.mStack.Push(res);
}

void
op_shl(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b << a;
  i.mStack.Push(res);
}
void
op_shr(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = a >> b;
  i.mStack.Push(res);
}
void
op_shra(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_shra???");
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = static_cast<int>(a) >> static_cast<int>(b);
  i.mStack.Push(res);
}
void
op_xor(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = a xor b;
  i.mStack.Push(res);
}
void
op_skip(ExprByteCodeInterpreter &i) noexcept
{
  const auto skip = i.mReader.ReadValue<i16>();
  i.mReader.Skip(skip);
}
void
op_bra(ExprByteCodeInterpreter &i) noexcept
{
  const auto skip = i.mReader.ReadValue<i16>();
  auto value = i.mStack.Pop();
  if (value != 0) {
    i.mReader.Skip(skip);
  }
}
void
op_eq(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = a == b;
  i.mStack.Push(res ? 1 : 0);
}
void
op_ge(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b >= a;
  i.mStack.Push(res ? 1 : 0);
}
void
op_gt(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b > a;
  i.mStack.Push(res ? 1 : 0);
}
void
op_le(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b <= a;
  i.mStack.Push(res ? 1 : 0);
}
void
op_lt(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b < a;
  i.mStack.Push(res ? 1 : 0);
}
void
op_ne(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.mStack.Pop();
  const auto b = i.mStack.Pop();
  const auto res = b != a;
  i.mStack.Push(res ? 1 : 0);
}

void
op_regx(ExprByteCodeInterpreter &i) noexcept
{
  const auto reg_no = i.mReader.ReadUleb128<u64>();
  i.mStack.Push(reg_no);
}

void
op_fbreg(ExprByteCodeInterpreter &i) noexcept
{
  const i64 offset = i.mReader.ReadLeb128<i64>();
  const auto frameBase = i.ComputeFrameBase();
  i.mStack.Push<u64>(frameBase + offset);
}
void
op_bregx(ExprByteCodeInterpreter &i) noexcept
{
  const auto reg_num = i.mReader.ReadUleb128<u64>();
  const auto offset = i.mReader.ReadLeb128<i64>();
  const auto result = i.GetRegister(reg_num).transform([&](auto v) { return v + offset; });
  MUST_HOLD(result.has_value(), "could not get register contents");
  i.mStack.Push<u64>(result.value());
  DW_OP_TODO("op_bregx")
}
void
op_piece(ExprByteCodeInterpreter &i) noexcept
{
  const auto size_bytes = i.mReader.ReadUleb128<u32>();

  i.mIsComposite = true;

  // The previous computation left a location description on the stack (or in a register)
  if (i.mStack.mStackSize > 0) {
    const auto location_value = i.mStack.Pop();

    // For now, we'll treat this as a memory address
    // TODO: Need to track whether this was a register location (DW_OP_reg*) or memory
    i.mPieces.push_back(LocationPiece::Memory(location_value, size_bytes));
  } else {
    // No location on stack - this piece is unavailable/optimized out
    i.mPieces.push_back(LocationPiece::Unavailable(size_bytes));
  }
}

void
op_nop(ExprByteCodeInterpreter &i) noexcept
{
}

void
op_call2(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_call2");
}
void
op_call4(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_call4 {}", i.mStack.mStackSize);
}
void
op_call_ref(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_call_ref {}", i.mStack.mStackSize);
}

void
op_call_frame_cfa(ExprByteCodeInterpreter &i) noexcept
{
  MDB_ASSERT(i.mFrameLevel != -1,
    "**Requires** frame level to be known for this DWARF expression computation but was -1 (undefined/unknown)");
  auto *unwindState = i.mTask.GetUnwindState(i.mFrameLevel);
  MDB_ASSERT(unwindState, "The interpreter can not know the CFA value.");
  i.mStack.Push(unwindState->CanonicalFrameAddress());
}

void
op_bit_piece(ExprByteCodeInterpreter &i) noexcept
{
  const auto size_bits = i.mReader.ReadUleb128<u32>();
  const auto bit_offset = i.mReader.ReadUleb128<u32>();

  i.mIsComposite = true;

  // The previous computation left a location description on the stack
  if (i.mStack.mStackSize > 0) {
    const auto location_value = i.mStack.Pop();

    // Create a bit piece
    LocationPiece piece = LocationPiece::Memory(location_value, (size_bits + 7) / 8);
    piece.mSizeBits = size_bits;
    piece.mBitOffset = bit_offset;
    i.mPieces.push_back(piece);
  } else {
    // No location on stack - this piece is unavailable/optimized out
    LocationPiece piece = LocationPiece::Unavailable((size_bits + 7) / 8);
    piece.mSizeBits = size_bits;
    piece.mBitOffset = bit_offset;
    i.mPieces.push_back(piece);
  }
}
void
op_implicit_value(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_implicit_value");
}

void
op_stack_value(ExprByteCodeInterpreter &i) noexcept
{
  // DW_OP_stack_value indicates that the value at the top of the stack is the actual value,
  // not a memory address. This is a semantic marker - no stack manipulation needed.
}

void
op_implicit_pointer(ExprByteCodeInterpreter &i)
{
  DW_OP_TODO("op_implicit_pointer");
}

void
op_addrx(ExprByteCodeInterpreter &i)
{
  DW_OP_TODO("op_addrx");
}

void
op_constx(ExprByteCodeInterpreter &i)
{
  DW_OP_TODO("op_constx")
}

void
op_entry_value(ExprByteCodeInterpreter &i)
{
  const auto len = i.mReader.ReadUleb128<u64>();
  DataBlock block = i.mReader.ReadBlock(len);

  if (!block.IsRegisterLocationDescription()) {
    ExprByteCodeInterpreter interpreter{ i.mFrameLevel, i.mSupervisor, i.mTask, block.AsSpan(), i.mObjectFile };
    const auto location = interpreter.Run();
    // For entry values, we expect a simple location that can be pushed to the stack
    // TODO: Handle composite locations properly
    MDB_ASSERT(location.IsSimple(), "Only simple location is supported here for now");
    i.mStack.Push(location.uAddress);
  } else {
    u64 registerNumber = [&]() {
      DwarfBinaryReader reader(block.AsSpan());
      auto op = reader.ReadByte<DwarfOp>();
      if (op >= DwarfOp::DW_OP_reg0 && op <= DwarfOp::DW_OP_reg31) {
        return static_cast<u64>(op) - static_cast<u64>(DwarfOp::DW_OP_reg0);
      }
      return reader.ReadUleb128<u64>();
    }();

    auto *unwindState = i.mTask.GetUnwindState(i.mFrameLevel - 1);
    MDB_ASSERT(unwindState, "Expected FrameUnwindState but got null");
    auto registerContentsAtEntry = unwindState->GetRegister(registerNumber);
    if (registerContentsAtEntry) {
      i.mStack.Push(registerContentsAtEntry.GetRaw());
    }
  }
}

void
op_const_type(ExprByteCodeInterpreter &i)
{
  DW_OP_TODO("op_const_type")
}

void
op_regval_type(ExprByteCodeInterpreter &i)
{
  DW_OP_TODO("op_regval_type")
}

void
op_deref_type(ExprByteCodeInterpreter &i)
{
  DW_OP_TODO("op_deref_type")
}

void
op_xderef_type(ExprByteCodeInterpreter &i)
{
  DW_OP_TODO("op_xderef_type")
}

void
op_convert(ExprByteCodeInterpreter &i)
{
  DW_OP_TODO("op_convert")
}

void
op_reinterpret(ExprByteCodeInterpreter &i)
{
  DW_OP_TODO("op_reinterpret")
}

// GNU extensions
void
op_gnu_push_tls_address(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_gnu_push_tls_address");
}

void
op_gnu_uninit(ExprByteCodeInterpreter &i) noexcept
{
  // Marks the preceding value as uninitialized. This is a semantic marker.
}

void
op_gnu_encoded_addr(ExprByteCodeInterpreter &i) noexcept
{
  DW_OP_TODO("op_gnu_encoded_addr");
}

void
op_gnu_implicit_pointer(ExprByteCodeInterpreter &i) noexcept
{
  // Skip the DIE offset and the offset into the pointed-to value
  i.mReader.ReadValue<u64>();  // DIE offset
  i.mReader.ReadLeb128<i64>(); // offset
  DW_OP_TODO("op_gnu_implicit_pointer");
}

void
op_gnu_entry_value(ExprByteCodeInterpreter &i) noexcept
{
  // op_gnu_entry_value is an old opcode for DWARF 5 (4?) op_entry_value
  op_entry_value(i);
}

void
op_gnu_const_type(ExprByteCodeInterpreter &i) noexcept
{
  i.mReader.ReadUleb128<u64>(); // DIE offset for type
  const auto size = i.mReader.ReadValue<u8>();
  i.mReader.Skip(size); // constant value bytes
  DW_OP_TODO("op_gnu_const_type");
}

void
op_gnu_regval_type(ExprByteCodeInterpreter &i) noexcept
{
  i.mReader.ReadUleb128<u64>(); // register number
  i.mReader.ReadUleb128<u64>(); // DIE offset for type
  DW_OP_TODO("op_gnu_regval_type");
}

void
op_gnu_deref_type(ExprByteCodeInterpreter &i) noexcept
{
  const auto size = i.mReader.ReadValue<u8>();
  i.mReader.ReadUleb128<u64>(); // DIE offset for type
  const auto addr = i.mStack.Pop();
  // For now, just do a basic deref of the specified size
  switch (size) {
  case 1: {
    const TPtr<u8> ptr{ addr };
    i.mStack.Push<u64>(i.mSupervisor.ReadType(ptr));
  } break;
  case 2: {
    const TPtr<u16> ptr{ addr };
    i.mStack.Push<u64>(i.mSupervisor.ReadType(ptr));
  } break;
  case 4: {
    const TPtr<u32> ptr{ addr };
    i.mStack.Push<u64>(i.mSupervisor.ReadType(ptr));
  } break;
  case 8: {
    const TPtr<u64> ptr{ addr };
    i.mStack.Push<u64>(i.mSupervisor.ReadType(ptr));
  } break;
  }
}

void
op_gnu_convert(ExprByteCodeInterpreter &i) noexcept
{
  i.mReader.ReadUleb128<u64>(); // DIE offset for type
  DW_OP_TODO("op_gnu_convert: type conversion not implemented");
}

void
op_gnu_reinterpret(ExprByteCodeInterpreter &i) noexcept
{
  i.mReader.ReadUleb128<u64>(); // DIE offset for type
  DW_OP_TODO("op_gnu_reinterpret: type reinterpretation not implemented");
}

void
op_gnu_parameter_ref(ExprByteCodeInterpreter &i) noexcept
{
  i.mReader.ReadValue<u32>(); // DIE offset for parameter
  DW_OP_TODO("op_gnu_parameter_ref");
}

static Op ops[0xff] = {
  &ub,                     // 0x0
  &ub,                     // 0x1
  &ub,                     // 0x2
  &op_addr,                // 0x3
  &ub,                     // 0x4
  &ub,                     // 0x5
  &op_deref,               // 0x6
  &ub,                     // 0x7
  &op_const1u,             // 0x08
  &op_const1s,             // 0x09
  &op_const2u,             // 0x0a
  &op_const2s,             // 0x0b
  &op_const4u,             // 0x0c
  &op_const4s,             // 0x0d
  &op_const8u,             // 0x0e
  &op_const8s,             // 0x0f
  &op_constu,              // 0x10
  &op_consts,              // 0x11
  &op_dup,                 // 0x12
  &op_drop,                // 0x13
  &op_over,                // 0x14
  &op_pick,                // 0x15
  &op_swap,                // 0x16
  &op_rot,                 // 0x17
  &op_xderef,              // 0x18
  &op_abs,                 // 0x19
  &op_and,                 // 0x1a
  &op_div,                 // 0x1b
  &op_minus,               // 0x1c
  &op_mod,                 // 0x1d
  &op_mul,                 // 0x1e
  &op_neg,                 // 0x1f
  &op_not,                 // 0x20
  &op_or,                  // 0x21
  &op_plus,                // 0x22
  &op_plus_uconst,         // 0x23
  &op_shl,                 // 0x24
  &op_shr,                 // 0x25
  &op_shra,                // 0x26
  &op_xor,                 // 0x27
  &op_bra,                 // 0x28
  &op_eq,                  // 0x29
  &op_ge,                  // 0x2a
  &op_gt,                  // 0x2b
  &op_le,                  // 0x2c
  &op_lt,                  // 0x2d
  &op_ne,                  // 0x2e
  &op_skip,                // 0x2f
  &op_literal,             // 0x30
  &op_literal,             // 0x31
  &op_literal,             // 0x32
  &op_literal,             // 0x33
  &op_literal,             // 0x34
  &op_literal,             // 0x35
  &op_literal,             // 0x36
  &op_literal,             // 0x37
  &op_literal,             // 0x38
  &op_literal,             // 0x39
  &op_literal,             // 0x3a
  &op_literal,             // 0x3b
  &op_literal,             // 0x3c
  &op_literal,             // 0x3d
  &op_literal,             // 0x3e
  &op_literal,             // 0x3f
  &op_literal,             // 0x40value
  &op_literal,             // 0x41
  &op_literal,             // 0x42
  &op_literal,             // 0x43
  &op_literal,             // 0x44
  &op_literal,             // 0x45
  &op_literal,             // 0x46
  &op_literal,             // 0x47
  &op_literal,             // 0x48
  &op_literal,             // 0x49
  &op_literal,             // 0x4a
  &op_literal,             // 0x4b
  &op_literal,             // 0x4c
  &op_literal,             // 0x4d
  &op_literal,             // 0x4e
  &op_literal,             // 0x4f
  &op_reg,                 // 0x50
  &op_reg,                 // 0x51
  &op_reg,                 // 0x52
  &op_reg,                 // 0x53
  &op_reg,                 // 0x54
  &op_reg,                 // 0x55
  &op_reg,                 // 0x56
  &op_reg,                 // 0x57
  &op_reg,                 // 0x58
  &op_reg,                 // 0x59
  &op_reg,                 // 0x5a
  &op_reg,                 // 0x5b
  &op_reg,                 // 0x5c
  &op_reg,                 // 0x5d
  &op_reg,                 // 0x5e
  &op_reg,                 // 0x5f
  &op_reg,                 // 0x60
  &op_reg,                 // 0x61
  &op_reg,                 // 0x62
  &op_reg,                 // 0x63
  &op_reg,                 // 0x64
  &op_reg,                 // 0x65
  &op_reg,                 // 0x66
  &op_reg,                 // 0x67
  &op_reg,                 // 0x68
  &op_reg,                 // 0x69
  &op_reg,                 // 0x6a
  &op_reg,                 // 0x6b
  &op_reg,                 // 0x6c
  &op_reg,                 // 0x6d
  &op_reg,                 // 0x6e
  &op_reg,                 // 0x6f
  &op_breg,                // 0x70
  &op_breg,                // 0x71
  &op_breg,                // 0x72
  &op_breg,                // 0x73
  &op_breg,                // 0x74
  &op_breg,                // 0x75
  &op_breg,                // 0x76
  &op_breg,                // 0x77
  &op_breg,                // 0x78
  &op_breg,                // 0x79
  &op_breg,                // 0x7a
  &op_breg,                // 0x7b
  &op_breg,                // 0x7c
  &op_breg,                // 0x7d
  &op_breg,                // 0x7e
  &op_breg,                // 0x7f
  &op_breg,                // 0x80
  &op_breg,                // 0x81
  &op_breg,                // 0x82
  &op_breg,                // 0x83
  &op_breg,                // 0x84
  &op_breg,                // 0x85
  &op_breg,                // 0x86
  &op_breg,                // 0x87
  &op_breg,                // 0x88
  &op_breg,                // 0x89
  &op_breg,                // 0x8a
  &op_breg,                // 0x8b
  &op_breg,                // 0x8c
  &op_breg,                // 0x8d
  &op_breg,                // 0x8e
  &op_breg,                // 0x8f
  &op_regx,                // 0x90
  &op_fbreg,               // 0x91
  &op_bregx,               // 0x92
  &op_piece,               // 0x93
  &op_deref_size,          // 0x94
  &op_xderef_size,         // 0x95
  &op_nop,                 // 0x96
  &op_push_object_address, // 0x97
  &op_call2,               // 0x98
  &op_call4,               // 0x99
  &op_call_ref,            // 0x9a
  &op_form_tls_address,    // 0x9b
  &op_call_frame_cfa,      // 0x9c
  &op_bit_piece,           // 0x9d
  &op_implicit_value,      // 0x9e
  &op_stack_value,         // 0x9f
  &op_implicit_pointer,    // 0xa0
  &op_addrx,               // 0xa1
  &op_constx,              // 0xa2
  &op_entry_value,         // 0xa3
  &op_const_type,          // 0xa4
  &op_regval_type,         // 0xa5
  &op_deref_type,          // 0xa6
  &op_xderef_type,         // 0xa7
  &op_convert,             // 0xa8
  &op_reinterpret,         // 0xa9
                           // clang-format off
  // 0xaa-0xdf: undefined opcodes
  &ub,&ub,&ub,&ub,&ub,&ub, // 0xaa-0xaf
  &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub, // 0xb0-0xbf
  &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub, // 0xc0-0xcf
  &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub, // 0xd0-0xdf
  // GNU extensions
  &op_gnu_push_tls_address,  // 0xe0
  &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub, // 0xe1-0xef
  &op_gnu_uninit,            // 0xf0
  &op_gnu_encoded_addr,      // 0xf1
  &op_gnu_implicit_pointer,  // 0xf2
  &op_gnu_entry_value,       // 0xf3
  &op_gnu_const_type,        // 0xf4
  &op_gnu_regval_type,       // 0xf5
  &op_gnu_deref_type,        // 0xf6
  &op_gnu_convert,           // 0xf7
  &ub,                       // 0xf8
  &op_gnu_reinterpret,       // 0xf9
  &op_gnu_parameter_ref,     // 0xfa
  &ub,&ub,&ub,&ub            // 0xfb-0xfe
  // clang-format-on
};

AddrPtr
ExprByteCodeInterpreter::ComputeFrameBase() noexcept
{
  MDB_ASSERT(mFrameLevel != -1,
    "**Requires** frame level to be known for this DWARF expression computation but was -1 (undefined/unknown)");
  ExprByteCodeInterpreter frameBaseReader{ mFrameLevel, mSupervisor, mTask, mFrameBaseProgram, mObjectFile };
  const auto location = frameBaseReader.Run();
  // Frame base should be a simple memory address
  MDB_ASSERT(location.IsSimple() && location.mKind == LocationKind::Memory,
    "Frame base expression must evaluate to a simple memory address");
  return AddrPtr{ location.uAddress };
}

std::optional<u64> ExprByteCodeInterpreter::GetRegister(u64 number)
{
  auto unwindState = mTask.GetUnwindState(mFrameLevel);
  if(!unwindState) {
    return {};
  }
  return unwindState->GetRegister(number);
}

LocationDescription
ExprByteCodeInterpreter::Run() noexcept
{
  PROFILE_SCOPE("ExprByteCodeInterpreter::Run", "bytecode-interpreter");
  while (mReader.HasMore()) {
    const auto op = mReader.ReadByte<DwarfOp>();
    this->mLatestDecoded = op;
    const auto idx = std::to_underlying(op);
    ops[idx](*this);
  }

  // If we built up a composite location, return it
  if (mIsComposite) {
    return LocationDescription::Composite(std::move(mPieces));
  }

  // Otherwise, return a simple memory location (legacy behavior)
  return LocationDescription::Memory(mStack.mStack[0]);
}
} // namespace sym