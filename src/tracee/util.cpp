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
static constexpr u16 RegNumToX86_64Offsets[24] = {
  offsetof(user_regs_struct, rax), offsetof(user_regs_struct, rbx), offsetof(user_regs_struct, rcx),
  offsetof(user_regs_struct, rdx), offsetof(user_regs_struct, rsi), offsetof(user_regs_struct, rdi),
  offsetof(user_regs_struct, rbp), offsetof(user_regs_struct, rsp), offsetof(user_regs_struct, r8),
  offsetof(user_regs_struct, r9),  offsetof(user_regs_struct, r10), offsetof(user_regs_struct, r11),
  offsetof(user_regs_struct, r12), offsetof(user_regs_struct, r13), offsetof(user_regs_struct, r14),
  offsetof(user_regs_struct, r15), offsetof(user_regs_struct, rip), offsetof(user_regs_struct, eflags),
  offsetof(user_regs_struct, cs),  offsetof(user_regs_struct, ss),  offsetof(user_regs_struct, ds),
  offsetof(user_regs_struct, es),  offsetof(user_regs_struct, fs),  offsetof(user_regs_struct, gs),
};

static constexpr std::array<std::pair<u8, u16>, 24> UserRegsMapping = {
  {{8, offsetof(user_regs_struct, rax)}, {8, offsetof(user_regs_struct, rbx)},
   {8, offsetof(user_regs_struct, rcx)}, {8, offsetof(user_regs_struct, rdx)},
   {8, offsetof(user_regs_struct, rsi)}, {8, offsetof(user_regs_struct, rdi)},
   {8, offsetof(user_regs_struct, rbp)}, {8, offsetof(user_regs_struct, rsp)},
   {8, offsetof(user_regs_struct, r8)},  {8, offsetof(user_regs_struct, r9)},
   {8, offsetof(user_regs_struct, r10)}, {8, offsetof(user_regs_struct, r11)},
   {8, offsetof(user_regs_struct, r12)}, {8, offsetof(user_regs_struct, r13)},
   {8, offsetof(user_regs_struct, r14)}, {8, offsetof(user_regs_struct, r15)},
   {8, offsetof(user_regs_struct, rip)}, {4, offsetof(user_regs_struct, eflags)},
   {4, offsetof(user_regs_struct, cs)},  {4, offsetof(user_regs_struct, ss)},
   {4, offsetof(user_regs_struct, ds)},  {4, offsetof(user_regs_struct, es)},
   {4, offsetof(user_regs_struct, fs)},  {4, offsetof(user_regs_struct, gs)}}};

u64
get_register(user_regs_struct *regs, int reg_number) noexcept
{
  ASSERT(reg_number <= 16, "Register number {} not supported", reg_number);
  return *(u64 *)(((std::uintptr_t)regs) + RegNumToX86_64Offsets[reg_number]);
}

std::string
process_exe_path(Pid pid) noexcept
{
  char buf[128];
  char resolved[PATH_MAX];
  auto end = fmt::format_to(buf, "/proc/{}/exe", pid);
  *end = 0;
  auto res = realpath(buf, resolved);
  if (res == nullptr) {
    PANIC("Failed to resolve exe of exec'd process");
  }

  return std::string{resolved};
}