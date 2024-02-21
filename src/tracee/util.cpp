#include "util.h"
#include "common.h"
#include <cstddef>
#include <string_view>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

static constexpr std::string_view reg_names[17] = {"rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8",
                                                   "r9",  "r10", "r11", "r12", "r13", "r14", "r15", "rip"};
static constexpr u16 offsets[17] = {
    offsetof(user_regs_struct, rax), offsetof(user_regs_struct, rdx), offsetof(user_regs_struct, rcx),
    offsetof(user_regs_struct, rbx), offsetof(user_regs_struct, rsi), offsetof(user_regs_struct, rdi),
    offsetof(user_regs_struct, rbp), offsetof(user_regs_struct, rsp), offsetof(user_regs_struct, r8),
    offsetof(user_regs_struct, r9),  offsetof(user_regs_struct, r10), offsetof(user_regs_struct, r11),
    offsetof(user_regs_struct, r12), offsetof(user_regs_struct, r13), offsetof(user_regs_struct, r14),
    offsetof(user_regs_struct, r15), offsetof(user_regs_struct, rip)};

u64
get_register(user_regs_struct *regs, int reg_number) noexcept
{
  ASSERT(reg_number <= 16, "Register number {} not supported", reg_number);
  return *(u64 *)(((std::uintptr_t)regs) + offsets[reg_number]);
}