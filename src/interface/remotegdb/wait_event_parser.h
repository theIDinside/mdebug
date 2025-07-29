/** LICENSE TEMPLATE */
#pragma once
#include "./shared.h"
#include "tracee_pointer.h"
#include <algorithm>
#include <event_queue_event_param.h>
#include <optional>
#include <string_view>
#include <typedefs.h>
namespace mdb {
struct TraceEvent;
class TraceeController;

namespace gdb {

struct GdbThread;
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
  std::optional<TraceeStopReason> mStopReason;
  bool mControlKindIsAttached;
  int mSignal{0};
  Pid mPid{0};
  Tid mTid{0};
  Pid mNewPid{0};
  Tid mNewTid{0};
  u32 mCore{0};
  int mSyscallNumber{0};
  int mEventTime{};
  AddrPtr mWatchpointAddress{nullptr};
  std::string mExecPath{};
  RegisterData mRegisters;
  ArchInfo mArch{};
  RemoteConnection &mConnection;

  WaitEventParser(RemoteConnection &conn) noexcept;

  EventDataParam Params() const noexcept;
  void ParseStopReason(TraceeStopReason reason, std::string_view val) noexcept;
  bool IsStopReason(u32 maybeStopReason) noexcept;
  void ParsePidTid(std::string_view arg) noexcept;
  void ParseCore(std::string_view arg) noexcept;

  // Determines PC value, from the payload sent by the remote. Returns nullopt if no PC was provided (or we
  // couldn't parse it)
  std::optional<std::uintptr_t> DeterminePc() const noexcept;

  TraceEvent *NewDebuggerEvent(bool init) noexcept;

  void ParseFork(std::string_view data);

  void ParseVFork(std::string_view data);

  void SetVFork(Pid newpid, Tid newtid) noexcept;

  void SetWatchpointAddress(AddrPtr addr) noexcept;

  void SetStopReason(TraceeStopReason stop) noexcept;

  void SetPid(Pid process) noexcept;
  void SetTid(Tid thread) noexcept;

  void SetExeced(std::string_view exec) noexcept;

  void ParseClone(std::string_view data) noexcept;
  void ParseEventTime(std::string_view data) noexcept;

  void SetSyscallExit(int number) noexcept;

  void SetSyscallEntry(int number) noexcept;

  std::vector<GdbThread> ParseThreadsParameter(std::string_view input) noexcept;
};
} // namespace gdb
} // namespace mdb