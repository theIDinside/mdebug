/** LICENSE TEMPLATE */

// mdb
#include <common.h>
#include <common/panic.h>
#include <tracee/util.h>

// stdlib
#include <charconv>
#include <cstddef>
#include <string_view>

// system
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

namespace mdb {
u32
QueryAvxSupport() noexcept
{
#if defined(__GNUC__) || defined(__clang__)
  if (__builtin_cpu_supports("avx512f")) {
    return 64; // AVX-512: 512 bits = 64 bytes
  }
  if (__builtin_cpu_supports("avx2")) {
    return 32; // AVX2: 256 bits = 32 bytes
  }
  if (__builtin_cpu_supports("avx")) {
    return 16; // AVX/SSE: 128 bits = 16 bytes
  }
#elif defined(_MSC_VER)
  int cpuInfo[4] = {};
  __cpuid(cpuInfo, 1);            // Get processor info
  if (cpuInfo[1] & (1 << 16)) {   // Check AVX
    if (cpuInfo[1] & (1 << 28)) { // Check AVX2
      return 64;                  // Assume AVX-512 support
    }
    return 32; // AVX2 supported
  }
  return 16; // Default to AVX/SSE/MMX
#endif
  return 16; // Fallback: Assume 128 bits = 16 bytes
}

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

#ifdef DEBUG
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
#endif
u64
get_register(user_regs_struct *regs, int reg_number) noexcept
{
  ASSERT(reg_number <= 16, "Register number {} not supported", reg_number);
  return *(u64 *)(((std::uintptr_t)regs) + RegNumToX86_64Offsets[reg_number]);
}

std::string
ProcessExecPath(Pid pid) noexcept
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

// N.B. Currently does nothing. In the future will be used to be able to assert in debug mode that specific
// functionality is sure to be executed only by the main thread.
pid_t
GetProcessId() noexcept
{
  static pid_t gProcessId = 0;
  if (gProcessId == 0) {
    gProcessId = getpid();
  }

  return gProcessId;
}

std::optional<pid_t>
ParseProcessId(std::string_view input, bool hex) noexcept
{
  if (input.empty()) {
    return {};
  }
  pid_t tid;
  const auto format = hex ? 16 : 10;
  const auto pid_result = std::from_chars(input.begin(), input.end(), tid, format);
  if (pid_result.ec != std::errc()) {
    return {};
  }
  return tid;
}

PidTid
ParsePidTid(std::string_view input, bool formatIsHex) noexcept
{
  auto sep = input.find('.');
  if (sep == input.npos) {
    return PidTid{.mPid = ParseProcessId(input, formatIsHex), .mTid = {}};
  }
  auto first = input.substr(0, sep);
  input.remove_prefix(sep + 1);

  auto pid = ParseProcessId(first, formatIsHex);
  if (pid) {
    auto tid = ParseProcessId(input, formatIsHex);
    if (tid) {
      return PidTid{pid, tid};
    }
  }

  return PidTid{};
}
} // namespace mdb