#include "dwarf_expressions.h"
#include "../task.h"
#include "../tracee_controller.h"
#include "dwarf_defs.h"
#include "dwarf_frameunwinder.h"
#include <utility>

namespace sym {

u64
DwarfStack::pop() noexcept
{
  ASSERT(size > 0, "Attempting to pop stack with no elements");
  return stack[--size];
}

void
DwarfStack::dup() noexcept
{
  stack[size] = stack[size - 1];
  ++size;
}

void
DwarfStack::rotate() noexcept
{
  std::swap(stack[size - 1], stack[size - 2]);
  std::swap(stack[size - 2], stack[size - 3]);
}

void
DwarfStack::copy(u8 index) noexcept
{
  stack[size] = stack[index];
  ++size;
}

void
DwarfStack::swap() noexcept
{
  const auto tmp = stack[size - 1];
  stack[size - 1] = stack[size - 2];
  stack[size - 2] = tmp;
}

ExprByteCodeInterpreter::ExprByteCodeInterpreter(std::span<const u8> bytecode) noexcept
    : stack(), reader{bytecode.data(), bytecode.size()}, bytecode(bytecode)
{
}

void
ub(ExprByteCodeInterpreter &i) noexcept
{
  PANIC(fmt::format("UNDEFINED OPCODE 0x{:x}", std::to_underlying(i.latest_decoded)));
}

void
op_addr(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_value<u64>());
}

void
op_literal(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(std::to_underlying(i.latest_decoded) - std::to_underlying(DwarfOp::DW_OP_lit0));
}

void
op_reg(ExprByteCodeInterpreter &) noexcept
{
  TODO("op_reg(ExprByteCodeInterpreter&)");
}

void
op_breg(ExprByteCodeInterpreter &i) noexcept
{
  const auto offset = i.reader.read_leb128<i64>();
  const auto reg_num = std::to_underlying(i.latest_decoded) - std::to_underlying(DwarfOp::DW_OP_breg0);
  const auto reg_contents = i.task->get_register(reg_num);
  const auto result = reg_contents + offset;
  i.stack.push<u64>(result);
}

void
op_deref(ExprByteCodeInterpreter &i) noexcept
{
  const auto v = i.stack.pop();
  const TPtr<std::uintptr_t> addr{v};
  const auto deref = i.tc->read_type(addr);
  i.stack.push(deref);
}

void
op_deref_size(ExprByteCodeInterpreter &i) noexcept
{
  const auto v = i.stack.pop();

  const auto bytes = i.reader.read_value<u8>();
  switch (bytes) {
  case 1: {
    const TPtr<u8> addr{v};
    const auto deref = i.tc->read_type(addr);
    i.stack.push<u64>(deref);
  } break;
  case 2: {
    const TPtr<u16> addr{v};
    const auto deref = i.tc->read_type(addr);
    i.stack.push<u64>(deref);
  } break;
  case 4: {
    const TPtr<u32> addr{v};
    const auto deref = i.tc->read_type(addr);
    i.stack.push<u64>(deref);
  } break;
  case 8: {
    const TPtr<u64> addr{v};
    const auto deref = i.tc->read_type(addr);
    i.stack.push<u64>(deref);
  } break;
  }
}
void
op_xderef_size(ExprByteCodeInterpreter &) noexcept
{
  TODO("op_xderef_size not supported yet!");
}

void
op_xderef(ExprByteCodeInterpreter &) noexcept
{
  TODO("op_xderef not supported yet!");
}

void
op_push_object_address(ExprByteCodeInterpreter &) noexcept
{
  TODO("op_push_object_address not yet supported!");
}

void
op_form_tls_address(ExprByteCodeInterpreter &) noexcept
{
  TODO("op_form_tls_address not supported yet!");
}

void
op_const1u(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_value<u8>());
}
void
op_const1s(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_value<i8>());
}
void
op_const2u(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_value<u16>());
}
void
op_const2s(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_value<i16>());
}
void
op_const4u(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_value<u32>());
}
void
op_const4s(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_value<i32>());
}
void
op_const8u(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_value<u64>());
}
void
op_const8s(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_value<i64>());
}
void
op_constu(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_uleb128<u64>());
}
void
op_consts(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.push(i.reader.read_leb128<i64>());
}

void
op_dup(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.dup();
}

void
op_drop(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.pop();
}

void
op_over(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.copy(1);
}
void
op_pick(ExprByteCodeInterpreter &i) noexcept
{
  const auto idx = i.reader.read_value<u8>();
  i.stack.copy(idx);
}

void
op_swap(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.swap();
}

void
op_rot(ExprByteCodeInterpreter &i) noexcept
{
  i.stack.rotate();
}

void
op_abs(ExprByteCodeInterpreter &i) noexcept
{
  const auto v = i.stack.pop();
  const auto iv = static_cast<i64>(v);
  const auto abs = std::abs(iv);
  i.stack.push(abs);
}
void
op_and(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto result = a & b;
  i.stack.push(result);
}
void
op_div(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto ia = static_cast<i64>(a);
  const auto ib = static_cast<i64>(b);
  const auto res = ib / ia;
  i.stack.push(res);
}

void
op_minus(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b - a;
  i.stack.push(res);
}
void
op_mod(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b % a;
  i.stack.push(res);
}
void
op_mul(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b * a;
  i.stack.push(res);
}
void
op_neg(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto sa = -static_cast<i64>(a);
  i.stack.push(sa);
}
void
op_not(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto res = ~a;
  i.stack.push(res);
}
void
op_or(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b | a;
  i.stack.push(res);
}
void
op_plus(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b + a;
  i.stack.push(res);
}

void
op_plus_uconst(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.reader.read_uleb128<u64>();
  const auto res = b + a;
  i.stack.push(res);
}

void
op_shl(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b << a;
  i.stack.push(res);
}
void
op_shr(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = a >> b;
  i.stack.push(res);
}
void
op_shra(ExprByteCodeInterpreter &i) noexcept
{
  TODO("op_shra???");
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = static_cast<int>(a) >> static_cast<int>(b);
  i.stack.push(res);
}
void
op_xor(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = a xor b;
  i.stack.push(res);
}
void
op_skip(ExprByteCodeInterpreter &i) noexcept
{
  const auto skip = i.reader.read_value<i16>();
  i.reader.skip(skip);
}
void
op_bra(ExprByteCodeInterpreter &i) noexcept
{
  const auto skip = i.reader.read_value<i16>();
  auto value = i.stack.pop();
  if (value != 0)
    i.reader.skip(skip);
}
void
op_eq(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = a == b;
  i.stack.push(res ? 1 : 0);
}
void
op_ge(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b >= a;
  i.stack.push(res ? 1 : 0);
}
void
op_gt(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b > a;
  i.stack.push(res ? 1 : 0);
}
void
op_le(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b <= a;
  i.stack.push(res ? 1 : 0);
}
void
op_lt(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b < a;
  i.stack.push(res ? 1 : 0);
}
void
op_ne(ExprByteCodeInterpreter &i) noexcept
{
  const auto a = i.stack.pop();
  const auto b = i.stack.pop();
  const auto res = b != a;
  i.stack.push(res ? 1 : 0);
}

void
op_regx(ExprByteCodeInterpreter &) noexcept
{
  TODO("op_regx")
}
void
op_fbreg(ExprByteCodeInterpreter &i) noexcept
{
  const auto offset = i.reader.read_leb128<i64>();
  const auto frame_base_addr = i.request_frame_base();
  const auto result = frame_base_addr + offset;
  i.stack.push<u64>(result.get());
  TODO("op_fbreg")
}
void
op_bregx(ExprByteCodeInterpreter &i) noexcept
{
  const auto reg_num = i.reader.read_uleb128<u64>();
  const auto offset = i.reader.read_leb128<i64>();
  const auto reg_contents = i.task->get_register(reg_num);
  const auto result = reg_contents + offset;
  i.stack.push<u64>(result);
  TODO("op_bregx")
}
void
op_piece(ExprByteCodeInterpreter &i) noexcept
{
  TODO(fmt::format("op_piece {}", i.stack.size));
  TODO("op_piece")
}

void
op_nop(ExprByteCodeInterpreter &) noexcept
{
}

void
op_call2(ExprByteCodeInterpreter &i) noexcept
{
  TODO(fmt::format("op_call2 {}", i.stack.size));
}
void
op_call4(ExprByteCodeInterpreter &i) noexcept
{
  TODO(fmt::format("op_call4 {}", i.stack.size));
}
void
op_call_ref(ExprByteCodeInterpreter &i) noexcept
{
  TODO(fmt::format("op_call_ref {}", i.stack.size));
}

void
op_call_frame_cfa(ExprByteCodeInterpreter &i) noexcept
{
  // ??
  DLOG("dwarf", "I have no idea if this is correct");
  i.stack.push(i.unwind_info->start.get());
}

void
op_bit_piece(ExprByteCodeInterpreter &) noexcept
{
  TODO("op_bit_piece");
}
void
op_implicit_value(ExprByteCodeInterpreter &) noexcept
{
  TODO("op_implicit_value");
}
void
op_stack_value(ExprByteCodeInterpreter &) noexcept
{
  TODO("op_stack_value");
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
    &op_skip,                // 0x2f
    &op_bra,                 // 0x28
    &op_eq,                  // 0x29
    &op_ge,                  // 0x2a
    &op_gt,                  // 0x2b
    &op_le,                  // 0x2c
    &op_lt,                  // 0x2d
    &op_ne,                  // 0x2e
    &ub,                     // 0x2f
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
    &op_literal,             // 0x40
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
                             // clang-format off
    &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,
    &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,
    &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,
    &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,
    &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,
    &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,
    &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,
    &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,
    &ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,&ub,
    &ub,&ub,&ub,&ub
    // clang-format-on
};

AddrPtr ExprByteCodeInterpreter::request_frame_base() noexcept {
  TODO("ExprByteCodeInterpreter::request_frame_base");
}

void
ExprByteCodeInterpreter::run() noexcept
{
  DwarfBinaryReader r{bytecode.data(), bytecode.size()};
  while (r.has_more()) {
    const auto op = r.read_byte<DwarfOp>();
    this->latest_decoded = op;
    ops[std::to_underlying(op)](*this);
  }
}
} // namespace sym