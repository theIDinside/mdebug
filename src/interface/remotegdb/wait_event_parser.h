#pragma once
#include "./shared.h"
#include "common.h"
#include <event_queue_event_param.h>
#include <optional>
#include <string_view>
#include <typedefs.h>

struct CoreEvent;
struct TraceeController;

namespace gdb {

class RemoteConnection;

using RegisterData = std::vector<std::pair<u32, std::vector<u8>>>;

constexpr u32
valueOf(std::string_view v)
{
  u64 val = 0;
  for (const auto ch : v) {
    val += (ch - 'a' + 1);
  }
  return val;
}

enum class TraceeStopReason : u32
{
  Watch = valueOf("watch"),
  RWatch = valueOf("rwatch"),
  AWatch = valueOf("awatch"),
  SyscallEntry = valueOf("syscall_entry"),
  SyscallReturn = valueOf("syscall_return"),
  Library = valueOf("library"),
  ReplayLog = valueOf("replaylog"),
  SWBreak = valueOf("swbreak"),
  HWBreak = valueOf("hwbreak"),
  Fork = valueOf("fork"),
  VFork = valueOf("vfork"),
  VForkDone = valueOf("vforkdone"),
  Exec = valueOf("exec"),
  Clone = valueOf("clone"),
  Create = valueOf("create"),
};

static constexpr std::string_view StopReasons[]{
    "watch",   "rwatch", "awatch", "syscall_entry", "syscall_return", "library", "replaylog", "swbreak",
    "hwbreak", "fork",   "vfork",  "vforkdone",     "exec",           "clone",   "create"};

consteval std::array<u32, 15>
StopReasonTokenFactory()
{
  static constexpr std::array<u32, 15> StopReasonTokens{
      valueOf("watch"),          valueOf("rwatch"),  valueOf("awatch"),    valueOf("syscall_entry"),
      valueOf("syscall_return"), valueOf("library"), valueOf("replaylog"), valueOf("swbreak"),
      valueOf("hwbreak"),        valueOf("fork"),    valueOf("vfork"),     valueOf("vforkdone"),
      valueOf("exec"),           valueOf("clone"),   valueOf("create"),
  };
  auto tmp = StopReasonTokens;
  std::sort(tmp.begin(), tmp.end());
  return tmp;
}

constexpr static auto StopReasonTokens = StopReasonTokenFactory();

static_assert(
    []() {
      for (const auto token : StopReasonTokens) {
        if (std::count(StopReasonTokens.begin(), StopReasonTokens.end(), token) != 1) {
          return false;
        }
      }

      return true;
    }(),
    "All generated TraceeStopReason convert to unique integer values (relative to itself)");

struct WaitEventParser
{
  std::optional<TraceeStopReason> stop_reason;
  bool control_kind_is_attached;
  int signal{0};
  Pid pid{0};
  Tid tid{0};
  Pid new_pid{0};
  Tid new_tid{0};
  u32 core{0};
  int syscall_no{0};
  AddrPtr wp_address{nullptr};
  std::string exec_path{};
  RegisterData registers;
  ArchInfo arch{};
  RemoteConnection &connection;

  WaitEventParser(RemoteConnection &conn) noexcept;

  EventDataParam param() const noexcept;
  void parse_stop_reason(TraceeStopReason reason, std::string_view val) noexcept;
  bool is_stop_reason(u32 maybeStopReason) noexcept;
  void parse_pid_tid(std::string_view arg) noexcept;
  void parse_core(std::string_view arg) noexcept;

  // Determines PC value, from the payload sent by the remote. Returns nullopt if no PC was provided (or we
  // couldn't parse it)
  std::optional<std::uintptr_t> determine_pc() const noexcept;

  CoreEvent *new_debugger_event(bool init) noexcept;

  void parse_fork(std::string_view data);

  void parse_vfork(std::string_view data);

  void set_vfork(Pid newpid, Tid newtid) noexcept;

  void set_wp_address(AddrPtr addr) noexcept;

  void set_stop_reason(TraceeStopReason stop) noexcept;

  void set_pid(Pid process) noexcept;
  void set_tid(Tid thread) noexcept;

  void set_execed(std::string_view exec) noexcept;

  void parse_clone(std::string_view data) noexcept;

  void set_syscall_exit(int number) noexcept;

  void set_syscall_entry(int number) noexcept;
};
} // namespace gdb