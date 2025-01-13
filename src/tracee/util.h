#pragma once
#include <string>
#include <thread>
#include <typedefs.h>

struct user_regs_struct;

struct PidTid
{
  std::optional<Pid> mPid;
  std::optional<Tid> mTid;

  constexpr operator bool() const noexcept {
    return mPid.has_value();
  }
};

u64 *register_by_number(user_regs_struct *regs, int reg_number) noexcept;
u64 get_register(user_regs_struct *regs, int reg_number) noexcept;

/// Returns the path that process with `pid` used to `exec`
std::string ProcessExecPath(Pid pid) noexcept;

/// Returns the largest vector register size on your system
u32 SystemVectorExtensionSize() noexcept;

/// Return the main thread ID, used to identify if some debugger-core
/// code should/can be executed.
std::thread::id GetMainThreadId() noexcept;

/// Parse `input` and return a process id as a result if successful.
std::optional<pid_t> ParseProcessId(std::string_view input, bool hex) noexcept;

/// Reads `input` and parses a pid and tid from it. If input is not a number
/// or doesn't have the format number.number the PidTid result will hold 2 empty
/// optionals. If the PID can be parsed, and a dot-syntax is used, but the TID can't be parsed
/// this will return two nullopts to signal invalid format.
/// `formatIsHex` specifies if the format is in hex or decimal.
PidTid ParsePidTid(std::string_view input, bool formatIsHex) noexcept;